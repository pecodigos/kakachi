use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use kakachi_coordination::{
    AuthenticatedUser, ControlPlaneState, CoordinationError, EndpointCandidate, NetworkSummary,
    PeerEndpointBundle, PeerIdentity, SessionNatType, SessionNegotiationSummary,
    SessionProgressInput,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let state = build_app_state()?;
    let bind_addr = load_bind_addr()?;

    let router = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/auth/register", post(register_user))
        .route("/v1/auth/login", post(login_user))
        .route("/v1/networks", post(create_network))
        .route("/v1/networks/{network_id}", get(get_network))
        .route("/v1/networks/{network_id}/join", post(join_network))
        .route("/v1/networks/{network_id}/peers", get(list_peers))
        .route(
            "/v1/networks/{network_id}/endpoint-candidates",
            post(update_endpoint_candidates).get(list_endpoint_candidates),
        )
        .route(
            "/v1/networks/{network_id}/sessions",
            post(open_session_negotiation),
        )
        .route(
            "/v1/networks/{network_id}/sessions/{session_id}",
            get(get_session_negotiation),
        )
        .route(
            "/v1/networks/{network_id}/sessions/{session_id}/report",
            post(report_session_progress),
        )
        .route("/v1/ws", get(ws_entry))
        .with_state(state)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind control plane on {bind_addr}"))?;

    info!(%bind_addr, "kakachi control plane started");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("control plane server failed")?;

    Ok(())
}

#[derive(Clone)]
struct AppState {
    control: Arc<ControlPlaneState>,
    auth: Arc<AuthService>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    username: String,
    public_key: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct CreateNetworkRequest {
    name: String,
}

#[derive(Debug, Deserialize)]
struct UpdateEndpointCandidatesRequest {
    candidates: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct OpenSessionRequest {
    peer_username: String,
}

#[derive(Debug, Deserialize)]
struct SessionProgressRequest {
    nat_type: SessionNatType,
    attempt: u8,
    candidate_count: u8,
    direct_ready: bool,
}

#[derive(Debug, Serialize)]
struct PeerIdentityResponse {
    username: String,
    public_key: String,
}

impl From<PeerIdentity> for PeerIdentityResponse {
    fn from(value: PeerIdentity) -> Self {
        Self {
            username: value.username,
            public_key: value.public_key.as_str().to_owned(),
        }
    }
}

#[derive(Debug, Serialize)]
struct NetworkSummaryResponse {
    network_id: Uuid,
    name: String,
    owner: String,
    members: Vec<PeerIdentityResponse>,
    created_at: DateTime<Utc>,
}

impl From<NetworkSummary> for NetworkSummaryResponse {
    fn from(value: NetworkSummary) -> Self {
        let members = value
            .members
            .into_iter()
            .map(PeerIdentityResponse::from)
            .collect::<Vec<_>>();

        Self {
            network_id: value.network_id,
            name: value.name,
            owner: value.owner,
            members,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
struct WsQuery {
    token: String,
    network_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerEvent {
    Welcome {
        username: String,
        public_key: String,
        server_time: DateTime<Utc>,
    },
    PeerSnapshot {
        network_id: Uuid,
        peers: Vec<PeerIdentityResponse>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

fn map_coordination_error(err: CoordinationError) -> ApiError {
    match err {
        CoordinationError::InvalidUsername
        | CoordinationError::WeakPassword
        | CoordinationError::InvalidPublicKey
        | CoordinationError::InvalidNetworkName
        | CoordinationError::InvalidEndpointCandidate
        | CoordinationError::TooManyEndpointCandidates
        | CoordinationError::InvalidSessionParticipants
        | CoordinationError::InvalidSessionReport(_) => ApiError::bad_request(err.to_string()),
        CoordinationError::UserAlreadyExists => ApiError::conflict(err.to_string()),
        CoordinationError::InvalidCredentials => ApiError::unauthorized(err.to_string()),
        CoordinationError::AccessDenied => ApiError::forbidden(err.to_string()),
        CoordinationError::UserNotFound
        | CoordinationError::NetworkNotFound
        | CoordinationError::SessionNotFound => ApiError::not_found(err.to_string()),
        CoordinationError::InconsistentState
        | CoordinationError::PasswordHashFailure
        | CoordinationError::StorageFailure(_) => ApiError::internal("internal coordination error"),
    }
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        timestamp: Utc::now(),
    })
}

async fn register_user(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    let password = SecretString::new(request.password);
    let registered = state
        .control
        .register_user(&request.username, &password, &request.public_key)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(RegisterResponse {
        username: registered.username,
        public_key: registered.public_key.as_str().to_owned(),
        created_at: registered.created_at,
    }))
}

async fn login_user(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, ApiError> {
    let password = SecretString::new(request.password);
    let user = state
        .control
        .authenticate_user(&request.username, &password)
        .await
        .map_err(map_coordination_error)?;

    let response = state.auth.issue_token(&user)?;
    Ok(Json(response))
}

async fn create_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateNetworkRequest>,
) -> Result<Json<NetworkSummaryResponse>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let network = state
        .control
        .create_network(&identity.username, &request.name)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(NetworkSummaryResponse::from(network)))
}

async fn get_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<NetworkSummaryResponse>, ApiError> {
    let identity = authorize(&headers, &state)?;

    state
        .control
        .list_peers(network_id, &identity.username)
        .await
        .map_err(map_coordination_error)?;

    let summary = state
        .control
        .get_network_summary(network_id)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(NetworkSummaryResponse::from(summary)))
}

async fn join_network(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<NetworkSummaryResponse>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let summary = state
        .control
        .join_network(network_id, &identity.username)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(NetworkSummaryResponse::from(summary)))
}

async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<Vec<PeerIdentityResponse>>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let peers = state
        .control
        .list_peers(network_id, &identity.username)
        .await
        .map_err(map_coordination_error)?;

    let serialized = peers
        .into_iter()
        .map(PeerIdentityResponse::from)
        .collect::<Vec<_>>();

    Ok(Json(serialized))
}

async fn update_endpoint_candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Json(request): Json<UpdateEndpointCandidatesRequest>,
) -> Result<Json<Vec<EndpointCandidate>>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let candidates = state
        .control
        .upsert_endpoint_candidates(network_id, &identity.username, &request.candidates)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(candidates))
}

async fn list_endpoint_candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
) -> Result<Json<Vec<PeerEndpointBundle>>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let bundles = state
        .control
        .list_network_endpoint_candidates(network_id, &identity.username)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(bundles))
}

async fn open_session_negotiation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(network_id): Path<Uuid>,
    Json(request): Json<OpenSessionRequest>,
) -> Result<Json<SessionNegotiationSummary>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let session = state
        .control
        .open_session_negotiation(network_id, &identity.username, &request.peer_username)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(session))
}

async fn report_session_progress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((network_id, session_id)): Path<(Uuid, Uuid)>,
    Json(request): Json<SessionProgressRequest>,
) -> Result<Json<SessionNegotiationSummary>, ApiError> {
    let identity = authorize(&headers, &state)?;

    let progress = SessionProgressInput {
        nat_type: request.nat_type,
        attempt: request.attempt,
        candidate_count: request.candidate_count,
        direct_ready: request.direct_ready,
    };

    let session = state
        .control
        .report_session_progress(network_id, session_id, &identity.username, progress)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(session))
}

async fn get_session_negotiation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((network_id, session_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<SessionNegotiationSummary>, ApiError> {
    let identity = authorize(&headers, &state)?;
    let session = state
        .control
        .get_session_negotiation(network_id, session_id, &identity.username)
        .await
        .map_err(map_coordination_error)?;

    Ok(Json(session))
}

async fn ws_entry(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> Result<Response, ApiError> {
    let identity = state.auth.verify_token(&query.token)?;
    let control = state.control.clone();
    let network_id = query.network_id;

    Ok(ws.on_upgrade(move |socket| async move {
        handle_ws(socket, control, identity, network_id).await;
    }))
}

async fn handle_ws(
    mut socket: WebSocket,
    control: Arc<ControlPlaneState>,
    identity: AuthContext,
    network_id: Option<Uuid>,
) {
    let welcome = ServerEvent::Welcome {
        username: identity.username.clone(),
        public_key: identity.public_key.clone(),
        server_time: Utc::now(),
    };

    if send_ws_event(&mut socket, &welcome).await.is_err() {
        return;
    }

    if let Some(network_id) = network_id {
        match control.list_peers(network_id, &identity.username).await {
            Ok(peers) => {
                let payload = peers
                    .into_iter()
                    .map(PeerIdentityResponse::from)
                    .collect::<Vec<_>>();

                let snapshot = ServerEvent::PeerSnapshot {
                    network_id,
                    peers: payload,
                };

                if send_ws_event(&mut socket, &snapshot).await.is_err() {
                    return;
                }
            }
            Err(err) => {
                let event = ServerEvent::Error {
                    message: format!("failed to access network: {err}"),
                };
                let _ = send_ws_event(&mut socket, &event).await;
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
        }
    }

    while let Some(next) = socket.recv().await {
        let message = match next {
            Ok(message) => message,
            Err(err) => {
                error!(error = %err, "websocket receive failed");
                break;
            }
        };

        match message {
            Message::Text(text) => {
                if text.as_str() == "ping" {
                    let _ = socket.send(Message::Text("pong".into())).await;
                }
            }
            Message::Ping(payload) => {
                let _ = socket.send(Message::Pong(payload)).await;
            }
            Message::Close(_) => break,
            Message::Binary(_) | Message::Pong(_) => {}
        }
    }
}

async fn send_ws_event(socket: &mut WebSocket, event: &ServerEvent) -> Result<(), ()> {
    let payload = serde_json::to_string(event).map_err(|_| ())?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .map_err(|_| ())
}

fn authorize(headers: &HeaderMap, state: &AppState) -> Result<AuthContext, ApiError> {
    let header_value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("missing authorization header"))?;

    let header_value = header_value
        .to_str()
        .map_err(|_| ApiError::unauthorized("authorization header is not valid utf-8"))?;

    let token = header_value
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::unauthorized("authorization header must use Bearer token"))?;

    state.auth.verify_token(token)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    sub: String,
    public_key: String,
    exp: usize,
    iat: usize,
}

#[derive(Debug, Clone)]
struct AuthContext {
    username: String,
    public_key: String,
}

struct AuthService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    token_ttl: Duration,
}

impl AuthService {
    fn new(secret: &str) -> Result<Self, ApiError> {
        if secret.len() < 32 {
            return Err(ApiError::internal(
                "KAKACHI_JWT_SECRET must be at least 32 chars",
            ));
        }

        Ok(Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            token_ttl: Duration::hours(12),
        })
    }

    fn issue_token(&self, user: &AuthenticatedUser) -> Result<LoginResponse, ApiError> {
        let issued_at = Utc::now();
        let expires_at = issued_at + self.token_ttl;
        let claims = Claims {
            sub: user.username.clone(),
            public_key: user.public_key.as_str().to_owned(),
            exp: expires_at.timestamp() as usize,
            iat: issued_at.timestamp() as usize,
        };

        let access_token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|_| ApiError::internal("failed to issue auth token"))?;

        Ok(LoginResponse {
            access_token,
            expires_at,
        })
    }

    fn verify_token(&self, token: &str) -> Result<AuthContext, ApiError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let decoded = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| ApiError::unauthorized("invalid or expired token"))?;

        Ok(AuthContext {
            username: decoded.claims.sub,
            public_key: decoded.claims.public_key,
        })
    }
}

fn build_app_state() -> anyhow::Result<AppState> {
    let jwt_secret = std::env::var("KAKACHI_JWT_SECRET")
        .context("KAKACHI_JWT_SECRET must be set for API startup")?;

    let coordination_db = std::env::var("KAKACHI_COORDINATION_DB")
        .unwrap_or_else(|_| "./.kakachi/control-plane.db".to_owned());

    let auth = AuthService::new(&jwt_secret).map_err(|err| anyhow::anyhow!(err.message))?;
    let control = ControlPlaneState::new_with_sqlite(&coordination_db)
        .with_context(|| format!("failed to initialize coordination DB at {coordination_db}"))?;

    info!(
        database_path = %coordination_db,
        backend = %control.persistence_backend(),
        "coordination state initialized"
    );

    Ok(AppState {
        control: Arc::new(control),
        auth: Arc::new(auth),
    })
}

fn load_bind_addr() -> anyhow::Result<SocketAddr> {
    let bind = std::env::var("KAKACHI_API_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_owned());
    bind.parse::<SocketAddr>()
        .with_context(|| format!("KAKACHI_API_BIND is not a valid socket address: {bind}"))
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG")
        .unwrap_or_else(|_| "kakachi_api=info,tower_http=info,axum=info".to_owned());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut stream) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            let _ = stream.recv().await;
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
