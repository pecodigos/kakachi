use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use kakachi_agent::{
    AgentConfig, AgentService, ControlPlaneClient, NegotiationRunSummary, SessionNegotiationSummary,
};
use kakachi_net::TraversalPolicy;
use kakachi_wg::WireGuardKeyPair;
use reqwest::{Client, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

const MAX_CONTROL_PLANE_ERROR_BODY_LEN: usize = 512;

#[derive(Debug, Error)]
enum DesktopError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("agent error: {0}")]
    Agent(#[from] kakachi_agent::AgentError),
    #[error("control-plane request failed with status {status}: {message}")]
    ControlPlaneStatus { status: u16, message: String },
}

#[derive(Clone)]
struct RuntimeState {
    http: Client,
    agent_data_dir: PathBuf,
}

impl RuntimeState {
    fn from_env() -> Result<Self, DesktopError> {
        let agent_data_dir = std::env::var("KAKACHI_DESKTOP_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("./.kakachi/desktop"));

        fs::create_dir_all(&agent_data_dir)?;

        let http = Client::builder().timeout(Duration::from_secs(15)).build()?;

        Ok(Self {
            http,
            agent_data_dir,
        })
    }
}

#[derive(Clone)]
struct ApiClient {
    http: Client,
    base_url: String,
}

impl ApiClient {
    fn new(http: Client, control_plane_url: &str) -> Result<Self, DesktopError> {
        Ok(Self {
            http,
            base_url: normalize_control_plane_base_url(control_plane_url)?,
        })
    }

    async fn get_json<T>(&self, path: &str, token: Option<&str>) -> Result<T, DesktopError>
    where
        T: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let request = self.http.get(url);
        let response = self.with_auth(request, token).send().await?;
        let response = ensure_success(response).await?;
        response.json::<T>().await.map_err(DesktopError::from)
    }

    async fn post_json<Req, Res>(
        &self,
        path: &str,
        token: Option<&str>,
        payload: &Req,
    ) -> Result<Res, DesktopError>
    where
        Req: Serialize,
        Res: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let request = self.http.post(url).json(payload);
        let response = self.with_auth(request, token).send().await?;
        let response = ensure_success(response).await?;
        response.json::<Res>().await.map_err(DesktopError::from)
    }

    async fn post_empty<Res>(&self, path: &str, token: Option<&str>) -> Result<Res, DesktopError>
    where
        Res: DeserializeOwned,
    {
        let url = format!("{}{}", self.base_url, path);
        let request = self.http.post(url);
        let response = self.with_auth(request, token).send().await?;
        let response = ensure_success(response).await?;
        response.json::<Res>().await.map_err(DesktopError::from)
    }

    fn with_auth(
        &self,
        request: reqwest::RequestBuilder,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        if let Some(value) = token {
            request.bearer_auth(value)
        } else {
            request
        }
    }
}

async fn ensure_success(response: Response) -> Result<Response, DesktopError> {
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status().as_u16();
    let mut message = match response.text().await {
        Ok(body) => body.trim().to_owned(),
        Err(_) => String::new(),
    };

    if message.len() > MAX_CONTROL_PLANE_ERROR_BODY_LEN {
        message.truncate(MAX_CONTROL_PLANE_ERROR_BODY_LEN);
    }

    if message.is_empty() {
        message = "empty response body".to_owned();
    }

    Err(DesktopError::ControlPlaneStatus { status, message })
}

fn normalize_control_plane_base_url(raw_url: &str) -> Result<String, DesktopError> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(DesktopError::InvalidInput(
            "control_plane_url cannot be empty".to_owned(),
        ));
    }

    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return Ok(trimmed.to_owned());
    }

    if let Some(rest) = trimmed.strip_prefix("ws://") {
        return Ok(format!("http://{rest}"));
    }

    if let Some(rest) = trimmed.strip_prefix("wss://") {
        return Ok(format!("https://{rest}"));
    }

    Err(DesktopError::InvalidInput(
        "control_plane_url must use http/https/ws/wss".to_owned(),
    ))
}

fn parse_uuid_field(raw: &str, field_name: &str) -> Result<Uuid, DesktopError> {
    Uuid::parse_str(raw.trim()).map_err(|_| {
        DesktopError::InvalidInput(format!("{field_name} must be a valid UUID string"))
    })
}

fn sanitize_component(raw: &str) -> String {
    let mut item = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    if item.is_empty() {
        item = "peer".to_owned();
    }

    item
}

#[derive(Debug, Clone, Deserialize)]
struct ControlPlaneInput {
    control_plane_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
struct RegisterUserInput {
    control_plane_url: String,
    username: String,
    password: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RegisterResponse {
    username: String,
    public_key: String,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
struct LoginUserInput {
    control_plane_url: String,
    username: String,
    password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LoginResponse {
    access_token: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
struct CreateNetworkInput {
    control_plane_url: String,
    access_token: String,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct JoinNetworkInput {
    control_plane_url: String,
    access_token: String,
    network_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ListPeersInput {
    control_plane_url: String,
    access_token: String,
    network_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct OpenSessionInput {
    control_plane_url: String,
    access_token: String,
    network_id: String,
    peer_username: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GetSessionInput {
    control_plane_url: String,
    access_token: String,
    network_id: String,
    session_id: String,
}

#[derive(Debug, Clone, Deserialize)]
struct RunNegotiationInput {
    control_plane_url: String,
    access_token: String,
    network_id: String,
    peer_username: String,
    stun_servers: Vec<String>,
    local_bind_addr: String,
    session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerIdentityResponse {
    username: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkSummaryResponse {
    network_id: Uuid,
    name: String,
    owner: String,
    members: Vec<PeerIdentityResponse>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
struct GeneratedKeyPair {
    public_key: String,
    private_key: String,
}

#[derive(Debug, Clone, Serialize)]
struct CreateNetworkRequest {
    name: String,
}

#[derive(Debug, Clone, Serialize)]
struct RegisterRequest {
    username: String,
    password: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[tauri::command]
async fn health_check(
    state: tauri::State<'_, RuntimeState>,
    input: ControlPlaneInput,
) -> Result<HealthResponse, String> {
    let api = ApiClient::new(state.http.clone(), &input.control_plane_url)
        .map_err(|error| error.to_string())?;

    api.get_json("/healthz", None)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn generate_wireguard_identity() -> Result<GeneratedKeyPair, String> {
    let pair = WireGuardKeyPair::generate();
    Ok(GeneratedKeyPair {
        public_key: pair.public_key.as_str().to_owned(),
        private_key: pair.private_key.as_str().to_owned(),
    })
}

#[tauri::command]
async fn register_user(
    state: tauri::State<'_, RuntimeState>,
    input: RegisterUserInput,
) -> Result<RegisterResponse, String> {
    let api = ApiClient::new(state.http.clone(), &input.control_plane_url)
        .map_err(|error| error.to_string())?;

    let payload = RegisterRequest {
        username: input.username,
        password: input.password,
        public_key: input.public_key,
    };

    api.post_json("/v1/auth/register", None, &payload)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn login_user(
    state: tauri::State<'_, RuntimeState>,
    input: LoginUserInput,
) -> Result<LoginResponse, String> {
    let api = ApiClient::new(state.http.clone(), &input.control_plane_url)
        .map_err(|error| error.to_string())?;

    let payload = LoginRequest {
        username: input.username,
        password: input.password,
    };

    api.post_json("/v1/auth/login", None, &payload)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn create_network(
    state: tauri::State<'_, RuntimeState>,
    input: CreateNetworkInput,
) -> Result<NetworkSummaryResponse, String> {
    let api = ApiClient::new(state.http.clone(), &input.control_plane_url)
        .map_err(|error| error.to_string())?;

    let payload = CreateNetworkRequest { name: input.name };

    api.post_json("/v1/networks", Some(input.access_token.trim()), &payload)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn join_network(
    state: tauri::State<'_, RuntimeState>,
    input: JoinNetworkInput,
) -> Result<NetworkSummaryResponse, String> {
    let network_id =
        parse_uuid_field(&input.network_id, "network_id").map_err(|e| e.to_string())?;

    let api = ApiClient::new(state.http.clone(), &input.control_plane_url)
        .map_err(|error| error.to_string())?;

    let path = format!("/v1/networks/{network_id}/join");
    api.post_empty(&path, Some(input.access_token.trim()))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn list_peers(
    state: tauri::State<'_, RuntimeState>,
    input: ListPeersInput,
) -> Result<Vec<PeerIdentityResponse>, String> {
    let network_id =
        parse_uuid_field(&input.network_id, "network_id").map_err(|e| e.to_string())?;

    let api = ApiClient::new(state.http.clone(), &input.control_plane_url)
        .map_err(|error| error.to_string())?;

    let path = format!("/v1/networks/{network_id}/peers");
    api.get_json(&path, Some(input.access_token.trim()))
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn open_session_negotiation(
    input: OpenSessionInput,
) -> Result<SessionNegotiationSummary, String> {
    let network_id =
        parse_uuid_field(&input.network_id, "network_id").map_err(|e| e.to_string())?;
    let control = ControlPlaneClient::new(&input.control_plane_url, input.access_token)
        .map_err(|error| error.to_string())?;

    control
        .open_session_negotiation(network_id, input.peer_username.trim())
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn get_session_negotiation(
    input: GetSessionInput,
) -> Result<SessionNegotiationSummary, String> {
    let network_id =
        parse_uuid_field(&input.network_id, "network_id").map_err(|e| e.to_string())?;
    let session_id =
        parse_uuid_field(&input.session_id, "session_id").map_err(|e| e.to_string())?;

    let control = ControlPlaneClient::new(&input.control_plane_url, input.access_token)
        .map_err(|error| error.to_string())?;

    control
        .get_session_negotiation(network_id, session_id)
        .await
        .map_err(|error| error.to_string())
}

#[tauri::command]
async fn run_session_negotiation(
    state: tauri::State<'_, RuntimeState>,
    input: RunNegotiationInput,
) -> Result<NegotiationRunSummary, String> {
    let network_id =
        parse_uuid_field(&input.network_id, "network_id").map_err(|e| e.to_string())?;
    let session_id = input
        .session_id
        .as_deref()
        .map(|value| parse_uuid_field(value, "session_id"))
        .transpose()
        .map_err(|error| error.to_string())?;

    let peer_key = sanitize_component(input.peer_username.trim());
    let data_dir = state
        .agent_data_dir
        .join(peer_key)
        .join(network_id.to_string());
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;

    let database_path = data_dir.join("agent.db");
    let config = AgentConfig {
        control_plane_url: input.control_plane_url.clone(),
        local_bind_addr: input.local_bind_addr,
        data_dir,
        database_path,
    };

    let service =
        AgentService::new(config, TraversalPolicy::default()).map_err(|error| error.to_string())?;

    let control_plane = ControlPlaneClient::new(&input.control_plane_url, input.access_token)
        .map_err(|error| error.to_string())?;

    service
        .run_session_negotiation(
            &control_plane,
            network_id,
            input.peer_username.trim(),
            session_id,
            &input.stun_servers,
        )
        .await
        .map_err(|error| error.to_string())
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "kakachi_desktop=info".to_owned());

    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .try_init();
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _ = dotenvy::dotenv();
    init_tracing();

    let state = match RuntimeState::from_env() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to initialize desktop runtime state: {error}");
            std::process::exit(1);
        }
    };

    info!(agent_data_dir = %state.agent_data_dir.display(), "starting kakachi desktop");

    let app = tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            health_check,
            generate_wireguard_identity,
            register_user,
            login_user,
            create_network,
            join_network,
            list_peers,
            open_session_negotiation,
            get_session_negotiation,
            run_session_negotiation,
        ])
        .run(tauri::generate_context!());

    if let Err(error) = app {
        eprintln!("desktop runtime error: {error}");
        std::process::exit(1);
    }
}

fn main() {
    run();
}
