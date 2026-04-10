use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use kakachi_chat::{ChatEnvelope, ChatError, StoredMessage, TransportPath};
use kakachi_net::{
    ConnectivityPath, DecisionReason, NatObservation, NatType, NetError, SessionReport,
    StunProbePlan, TraversalPolicy, build_session_report, build_stun_probe_plan as build_probe,
    infer_nat_type,
};
use kakachi_wg::{
    InterfaceConfig, LinuxWgCliBackend, WgCommandPlan, WgError, WindowsWgNtBackend,
    WireGuardBackend, WireGuardKeyPair,
};
use reqwest::Client;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

const DEFAULT_STUN_RETRY_INTERVAL_MS: u64 = 500;
const MAX_CONTROL_PLANE_ERROR_BODY_LEN: usize = 512;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("invalid config: {0}")]
    InvalidConfig(&'static str),
    #[error("network config error: {0}")]
    Net(#[from] NetError),
    #[error("wireguard config error: {0}")]
    Wg(#[from] WgError),
    #[error("chat envelope error: {0}")]
    Chat(#[from] ChatError),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("mutex lock poisoned")]
    LockPoisoned,
    #[error("invalid uuid in storage")]
    InvalidUuid,
    #[error("invalid timestamp in storage")]
    InvalidTimestamp,
    #[error("invalid transport path in storage")]
    InvalidTransportPath,
    #[error("http client error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("control-plane request failed with status {status}: {message}")]
    ControlPlaneStatus { status: u16, message: String },
    #[error("control_plane_url must use http/https/ws/wss")]
    UnsupportedControlPlaneUrl,
    #[error("invalid control-plane response: {0}")]
    InvalidControlPlaneResponse(&'static str),
    #[error("stun probe failed: {0}")]
    StunProbe(String),
    #[error("stun probe produced no observations")]
    EmptyStunObservations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub control_plane_url: String,
    pub local_bind_addr: String,
    pub data_dir: PathBuf,
    pub database_path: PathBuf,
}

impl AgentConfig {
    pub fn validate(&self) -> Result<(), AgentError> {
        let endpoint = self.control_plane_url.trim();
        let is_secure = endpoint.starts_with("https://") || endpoint.starts_with("wss://");
        let is_local_dev = endpoint.starts_with("http://127.0.0.1")
            || endpoint.starts_with("http://localhost")
            || endpoint.starts_with("ws://127.0.0.1")
            || endpoint.starts_with("ws://localhost");

        if !is_secure && !is_local_dev {
            return Err(AgentError::InvalidConfig(
                "control_plane_url must use https/wss (or localhost dev endpoint)",
            ));
        }

        if SocketAddr::from_str(self.local_bind_addr.trim()).is_err() {
            return Err(AgentError::InvalidConfig(
                "local_bind_addr must be a valid socket address",
            ));
        }

        if self.database_path.as_os_str().is_empty() {
            return Err(AgentError::InvalidConfig("database_path cannot be empty"));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    NegotiatingDirect,
    DirectReady,
    RelayRequired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionNatType {
    Unknown,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

impl From<NatType> for SessionNatType {
    fn from(value: NatType) -> Self {
        match value {
            NatType::Unknown => SessionNatType::Unknown,
            NatType::FullCone => SessionNatType::FullCone,
            NatType::RestrictedCone => SessionNatType::RestrictedCone,
            NatType::PortRestrictedCone => SessionNatType::PortRestrictedCone,
            NatType::Symmetric => SessionNatType::Symmetric,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPeerReport {
    pub username: String,
    pub nat_type: SessionNatType,
    pub attempt: u8,
    pub candidate_count: u8,
    pub direct_ready: bool,
    pub reported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionNegotiationSummary {
    pub session_id: Uuid,
    pub network_id: Uuid,
    pub initiator: String,
    pub responder: String,
    pub state: SessionState,
    pub path: ConnectivityPath,
    pub reason: DecisionReason,
    #[serde(default)]
    pub reports: Vec<SessionPeerReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NegotiationRunSummary {
    pub session_id: Uuid,
    pub final_state: SessionState,
    pub final_path: ConnectivityPath,
    pub final_reason: DecisionReason,
    pub attempts_sent: u8,
    pub last_report: Option<SessionReport>,
    pub last_candidates: Vec<SocketAddr>,
}

#[derive(Debug, Clone, Serialize)]
struct UpdateEndpointCandidatesRequest {
    candidates: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct OpenSessionRequest {
    peer_username: String,
}

#[derive(Debug, Clone, Serialize)]
struct SessionProgressRequest {
    nat_type: SessionNatType,
    attempt: u8,
    candidate_count: u8,
    direct_ready: bool,
}

#[derive(Debug, Clone)]
pub struct ControlPlaneClient {
    http: Client,
    base_url: String,
    access_token: String,
}

impl ControlPlaneClient {
    pub fn new(
        control_plane_url: &str,
        access_token: impl Into<String>,
    ) -> Result<Self, AgentError> {
        let base_url = normalize_control_plane_base_url(control_plane_url)?;
        let token = access_token.into();
        if token.trim().is_empty() {
            return Err(AgentError::InvalidConfig(
                "control-plane token cannot be empty",
            ));
        }

        let http = Client::builder().timeout(Duration::from_secs(15)).build()?;

        Ok(Self {
            http,
            base_url,
            access_token: token,
        })
    }

    pub async fn update_endpoint_candidates(
        &self,
        network_id: Uuid,
        candidates: &[SocketAddr],
    ) -> Result<(), AgentError> {
        let payload = UpdateEndpointCandidatesRequest {
            candidates: candidates.iter().map(ToString::to_string).collect(),
        };

        let response = self
            .http
            .post(format!(
                "{}/v1/networks/{network_id}/endpoint-candidates",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&payload)
            .send()
            .await?;

        let _ = ensure_success(response).await?;
        Ok(())
    }

    pub async fn open_session_negotiation(
        &self,
        network_id: Uuid,
        peer_username: &str,
    ) -> Result<SessionNegotiationSummary, AgentError> {
        let payload = OpenSessionRequest {
            peer_username: peer_username.trim().to_owned(),
        };

        let response = self
            .http
            .post(format!(
                "{}/v1/networks/{network_id}/sessions",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&payload)
            .send()
            .await?;

        let response = ensure_success(response).await?;
        let session = response.json::<SessionNegotiationSummary>().await?;
        Ok(session)
    }

    pub async fn report_session_progress(
        &self,
        network_id: Uuid,
        session_id: Uuid,
        report: SessionReport,
    ) -> Result<SessionNegotiationSummary, AgentError> {
        let payload = SessionProgressRequest {
            nat_type: SessionNatType::from(report.nat_type),
            attempt: report.attempt,
            candidate_count: report.candidate_count,
            direct_ready: report.direct_ready,
        };

        let response = self
            .http
            .post(format!(
                "{}/v1/networks/{network_id}/sessions/{session_id}/report",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .json(&payload)
            .send()
            .await?;

        let response = ensure_success(response).await?;
        let session = response.json::<SessionNegotiationSummary>().await?;
        Ok(session)
    }

    pub async fn get_session_negotiation(
        &self,
        network_id: Uuid,
        session_id: Uuid,
    ) -> Result<SessionNegotiationSummary, AgentError> {
        let response = self
            .http
            .get(format!(
                "{}/v1/networks/{network_id}/sessions/{session_id}",
                self.base_url
            ))
            .bearer_auth(&self.access_token)
            .send()
            .await?;

        let response = ensure_success(response).await?;
        let session = response.json::<SessionNegotiationSummary>().await?;
        Ok(session)
    }
}

async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response, AgentError> {
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

    Err(AgentError::ControlPlaneStatus { status, message })
}

fn normalize_control_plane_base_url(raw_url: &str) -> Result<String, AgentError> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(AgentError::UnsupportedControlPlaneUrl);
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

    Err(AgentError::UnsupportedControlPlaneUrl)
}

pub struct AgentStorage {
    conn: Mutex<Connection>,
}

impl AgentStorage {
    pub fn open(database_path: &Path) -> Result<Self, AgentError> {
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let connection = Connection::open(database_path)?;
        connection.execute_batch(
            "
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS chat_messages (
                message_id TEXT PRIMARY KEY,
                network_id TEXT NOT NULL,
                sender_public_key TEXT NOT NULL,
                ciphertext BLOB NOT NULL,
                sent_at TEXT NOT NULL,
                transport_path TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_chat_messages_network_sent
                ON chat_messages (network_id, sent_at DESC);
            ",
        )?;

        Ok(Self {
            conn: Mutex::new(connection),
        })
    }

    pub fn store_chat_message(
        &self,
        envelope: &ChatEnvelope,
        transport_path: TransportPath,
    ) -> Result<(), AgentError> {
        envelope.validate()?;

        let path = match transport_path {
            TransportPath::DirectP2p => "direct",
            TransportPath::RelayWebSocket => "relay",
        };

        let lock = self.conn.lock().map_err(|_| AgentError::LockPoisoned)?;
        lock.execute(
            "
            INSERT OR REPLACE INTO chat_messages (
                message_id, network_id, sender_public_key, ciphertext, sent_at, transport_path
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ",
            params![
                envelope.message_id.to_string(),
                envelope.network_id.to_string(),
                envelope.sender_public_key,
                envelope.ciphertext,
                envelope.sent_at.to_rfc3339(),
                path,
            ],
        )?;

        Ok(())
    }

    pub fn list_recent_messages(
        &self,
        network_id: Uuid,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, AgentError> {
        let query_limit = limit.min(500);
        let lock = self.conn.lock().map_err(|_| AgentError::LockPoisoned)?;
        let mut statement = lock.prepare(
            "
            SELECT message_id, network_id, sender_public_key, ciphertext, sent_at, transport_path
            FROM chat_messages
            WHERE network_id = ?1
            ORDER BY sent_at DESC
            LIMIT ?2
            ",
        )?;

        let mut rows = statement.query(params![network_id.to_string(), query_limit as i64])?;
        let mut items = Vec::new();

        while let Some(row) = rows.next()? {
            let message_id_raw: String = row.get(0)?;
            let network_id_raw: String = row.get(1)?;
            let sender_public_key: String = row.get(2)?;
            let ciphertext: Vec<u8> = row.get(3)?;
            let sent_at_raw: String = row.get(4)?;
            let transport_path_raw: String = row.get(5)?;

            let message_id =
                Uuid::parse_str(&message_id_raw).map_err(|_| AgentError::InvalidUuid)?;
            let parsed_network_id =
                Uuid::parse_str(&network_id_raw).map_err(|_| AgentError::InvalidUuid)?;
            let sent_at = DateTime::parse_from_rfc3339(&sent_at_raw)
                .map_err(|_| AgentError::InvalidTimestamp)?
                .with_timezone(&Utc);
            let transport_path = match transport_path_raw.as_str() {
                "direct" => TransportPath::DirectP2p,
                "relay" => TransportPath::RelayWebSocket,
                _ => return Err(AgentError::InvalidTransportPath),
            };

            items.push(StoredMessage {
                message_id,
                network_id: parsed_network_id,
                sender_public_key,
                ciphertext,
                sent_at,
                transport_path,
            });
        }

        Ok(items)
    }
}

pub struct AgentService {
    config: AgentConfig,
    storage: AgentStorage,
    traversal_policy: TraversalPolicy,
}

impl AgentService {
    pub fn new(config: AgentConfig, traversal_policy: TraversalPolicy) -> Result<Self, AgentError> {
        config.validate()?;
        traversal_policy.validate()?;

        if !config.data_dir.exists() {
            fs::create_dir_all(&config.data_dir)?;
        }

        let storage = AgentStorage::open(&config.database_path)?;
        Ok(Self {
            config,
            storage,
            traversal_policy,
        })
    }

    pub fn config(&self) -> &AgentConfig {
        &self.config
    }

    pub fn traversal_policy(&self) -> &TraversalPolicy {
        &self.traversal_policy
    }

    pub fn generate_wireguard_identity(&self) -> WireGuardKeyPair {
        WireGuardKeyPair::generate()
    }

    pub fn persist_chat_message(
        &self,
        envelope: &ChatEnvelope,
        transport_path: TransportPath,
    ) -> Result<(), AgentError> {
        self.storage.store_chat_message(envelope, transport_path)
    }

    pub fn recent_chat_messages(
        &self,
        network_id: Uuid,
        limit: usize,
    ) -> Result<Vec<StoredMessage>, AgentError> {
        self.storage.list_recent_messages(network_id, limit)
    }

    pub fn stage_linux_wireguard_plan(
        &self,
        interface_config: &InterfaceConfig,
    ) -> Result<WgCommandPlan, AgentError> {
        let backend = LinuxWgCliBackend;
        backend
            .build_plan(interface_config)
            .map_err(AgentError::from)
    }

    pub fn stage_windows_wireguard_plan(
        &self,
        interface_config: &InterfaceConfig,
        tunnel_config_path: &str,
    ) -> Result<WgCommandPlan, AgentError> {
        let backend = WindowsWgNtBackend {
            tunnel_config_path: tunnel_config_path.to_owned(),
        };
        backend
            .build_plan(interface_config)
            .map_err(AgentError::from)
    }

    pub fn build_stun_probe_plan(
        &self,
        raw_servers: &[String],
    ) -> Result<StunProbePlan, AgentError> {
        build_probe(&self.traversal_policy, raw_servers).map_err(AgentError::from)
    }

    pub async fn collect_nat_observations(
        &self,
        plan: &StunProbePlan,
    ) -> Result<Vec<NatObservation>, AgentError> {
        let bind_addr = self.stun_probe_bind_addr()?;
        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        let timeout = Duration::from_secs(u64::from(plan.probe_timeout_secs));

        let mut observations = Vec::with_capacity(plan.servers.len());
        let mut last_error = None::<String>;

        for server in &plan.servers {
            let mut client = stunclient::StunClient::new(server.addr);
            client
                .set_timeout(timeout)
                .set_retry_interval(Duration::from_millis(DEFAULT_STUN_RETRY_INTERVAL_MS));

            match client.query_external_address_async(&socket).await {
                Ok(observed_addr) => {
                    debug!(server = %server.addr, observed_addr = %observed_addr, "stun probe succeeded");
                    observations.push(NatObservation {
                        observed_addr,
                        nat_type: NatType::Unknown,
                        recorded_at: Utc::now(),
                    });
                }
                Err(error) => {
                    let message = error.to_string();
                    warn!(
                        server = %server.addr,
                        error = %message,
                        "stun probe failed against candidate server"
                    );
                    last_error = Some(message);
                }
            }
        }

        if observations.is_empty() {
            if let Some(message) = last_error {
                return Err(AgentError::StunProbe(message));
            }

            return Err(AgentError::EmptyStunObservations);
        }

        Ok(observations)
    }

    pub async fn run_session_negotiation(
        &self,
        control_plane: &ControlPlaneClient,
        network_id: Uuid,
        peer_username: &str,
        session_id: Option<Uuid>,
        raw_stun_servers: &[String],
    ) -> Result<NegotiationRunSummary, AgentError> {
        let probe_plan = self.build_stun_probe_plan(raw_stun_servers)?;
        let mut session = match session_id {
            Some(existing_session_id) => {
                control_plane
                    .get_session_negotiation(network_id, existing_session_id)
                    .await?
            }
            None => {
                control_plane
                    .open_session_negotiation(network_id, peer_username)
                    .await?
            }
        };

        let mut attempts_sent = 0;
        let mut last_report = None;
        let mut last_candidates = Vec::new();
        let mut cached_observations = Vec::new();

        for attempt in 1..=self.traversal_policy.max_hole_punch_attempts {
            let observations = match self.collect_nat_observations(&probe_plan).await {
                Ok(current) => {
                    cached_observations = current.clone();
                    current
                }
                Err(error) => {
                    if cached_observations.is_empty() {
                        return Err(error);
                    }

                    warn!(
                        attempt,
                        error = %error,
                        "stun probing failed, reusing previous observations"
                    );
                    cached_observations.clone()
                }
            };

            let candidates = dedupe_endpoint_candidates(&observations);
            control_plane
                .update_endpoint_candidates(network_id, &candidates)
                .await?;
            last_candidates = candidates.clone();

            let nat_type = infer_nat_type(&observations);
            let direct_ready = !candidates.is_empty() && nat_type != NatType::Symmetric;
            let report = build_session_report(
                &self.traversal_policy,
                attempt,
                candidates.len(),
                direct_ready,
                &observations,
            )?;

            session = control_plane
                .report_session_progress(network_id, session.session_id, report)
                .await?;
            attempts_sent = attempt;
            last_report = Some(report);

            if session.state != SessionState::NegotiatingDirect {
                break;
            }

            tokio::time::sleep(Duration::from_secs(u64::from(
                self.traversal_policy.relay_backoff_secs,
            )))
            .await;
        }

        if session.state == SessionState::NegotiatingDirect {
            session = control_plane
                .get_session_negotiation(network_id, session.session_id)
                .await?;
        }

        Ok(NegotiationRunSummary {
            session_id: session.session_id,
            final_state: session.state,
            final_path: session.path,
            final_reason: session.reason,
            attempts_sent,
            last_report,
            last_candidates,
        })
    }

    fn stun_probe_bind_addr(&self) -> Result<SocketAddr, AgentError> {
        let configured =
            SocketAddr::from_str(self.config.local_bind_addr.trim()).map_err(|_| {
                AgentError::InvalidConfig("local_bind_addr must be a valid socket address")
            })?;

        let resolved = match configured.ip() {
            IpAddr::V4(ip) if ip.is_loopback() => {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), configured.port())
            }
            IpAddr::V6(ip) if ip.is_loopback() => {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), configured.port())
            }
            _ => configured,
        };

        Ok(resolved)
    }
}

fn dedupe_endpoint_candidates(observations: &[NatObservation]) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();

    for observation in observations {
        if seen.insert(observation.observed_addr) {
            candidates.push(observation.observed_addr);
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_with_db(database_path: PathBuf) -> AgentConfig {
        AgentConfig {
            control_plane_url: "https://control.kakachi.test".to_owned(),
            local_bind_addr: "127.0.0.1:7000".to_owned(),
            data_dir: database_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from(".")),
            database_path,
        }
    }

    #[test]
    fn service_persists_and_reads_chat_messages() {
        let db_path = std::env::temp_dir().join(format!("kakachi-agent-{}.db", Uuid::new_v4()));
        let config = test_config_with_db(db_path.clone());
        let service = AgentService::new(config, TraversalPolicy::default());
        assert!(service.is_ok());

        let service = if let Ok(service) = service {
            service
        } else {
            return;
        };

        let network_id = Uuid::new_v4();
        let envelope = ChatEnvelope::new(network_id, "peer-key".to_owned(), vec![10, 20, 30]);

        assert!(
            service
                .persist_chat_message(&envelope, TransportPath::DirectP2p)
                .is_ok()
        );

        let messages = service.recent_chat_messages(network_id, 20);
        assert!(messages.is_ok());
        let len = if let Ok(items) = messages {
            items.len()
        } else {
            0
        };
        assert_eq!(len, 1);

        if db_path.exists() {
            let _ = fs::remove_file(db_path);
        }
    }

    #[test]
    fn config_rejects_non_secure_non_local_control_plane() {
        let db_path = std::env::temp_dir().join(format!("kakachi-agent-{}.db", Uuid::new_v4()));
        let mut config = test_config_with_db(db_path.clone());
        config.control_plane_url = "http://example.com".to_owned();

        let service = AgentService::new(config, TraversalPolicy::default());
        assert!(service.is_err());

        if db_path.exists() {
            let _ = fs::remove_file(db_path);
        }
    }

    #[test]
    fn normalizes_ws_control_plane_url() {
        let normalized = normalize_control_plane_base_url("ws://127.0.0.1:8080/");
        assert!(normalized.is_ok());

        let normalized = if let Ok(value) = normalized {
            value
        } else {
            return;
        };

        assert_eq!(normalized, "http://127.0.0.1:8080");
    }

    #[test]
    fn dedupe_endpoint_candidates_keeps_unique_addresses() {
        let shared = match "198.51.100.20:51820".parse::<SocketAddr>() {
            Ok(value) => value,
            Err(_) => return,
        };

        let second = match "203.0.113.9:51820".parse::<SocketAddr>() {
            Ok(value) => value,
            Err(_) => return,
        };

        let observations = vec![
            NatObservation {
                observed_addr: shared,
                nat_type: NatType::Unknown,
                recorded_at: Utc::now(),
            },
            NatObservation {
                observed_addr: shared,
                nat_type: NatType::Unknown,
                recorded_at: Utc::now(),
            },
            NatObservation {
                observed_addr: second,
                nat_type: NatType::Unknown,
                recorded_at: Utc::now(),
            },
        ];

        let deduped = dedupe_endpoint_candidates(&observations);
        assert_eq!(deduped, vec![shared, second]);
    }

    #[test]
    fn stun_probe_bind_addr_rewrites_loopback_interface() {
        let db_path = std::env::temp_dir().join(format!("kakachi-agent-{}.db", Uuid::new_v4()));
        let config = test_config_with_db(db_path.clone());
        let service = AgentService::new(config, TraversalPolicy::default());
        assert!(service.is_ok());

        let service = if let Ok(value) = service {
            value
        } else {
            return;
        };

        let bind_addr = service.stun_probe_bind_addr();
        assert!(bind_addr.is_ok());

        let bind_addr = if let Ok(value) = bind_addr {
            value
        } else {
            return;
        };

        assert_eq!(
            bind_addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7000)
        );

        if db_path.exists() {
            let _ = fs::remove_file(db_path);
        }
    }
}
