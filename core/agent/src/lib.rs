use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use kakachi_chat::{ChatEnvelope, ChatError, StoredMessage, TransportPath};
use kakachi_net::{NetError, TraversalPolicy};
use kakachi_wg::{
    InterfaceConfig, LinuxWgCliBackend, WgCommandPlan, WgError, WindowsWgNtBackend,
    WireGuardBackend, WireGuardKeyPair,
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

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
}
