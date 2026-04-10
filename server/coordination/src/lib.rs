use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use regex::Regex;
use rusqlite::{Connection, params};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

const MIN_PASSWORD_LEN: usize = 12;
const MAX_NETWORK_NAME_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum CoordinationError {
    #[error("username must be 3-32 chars and only contain letters, numbers, _, -, .")]
    InvalidUsername,
    #[error("password does not meet minimum strength requirements")]
    WeakPassword,
    #[error("public key is not a valid WireGuard base64 key")]
    InvalidPublicKey,
    #[error("user already exists")]
    UserAlreadyExists,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("user does not exist")]
    UserNotFound,
    #[error("network name cannot be empty or larger than {MAX_NETWORK_NAME_LEN} chars")]
    InvalidNetworkName,
    #[error("network not found")]
    NetworkNotFound,
    #[error("requester is not a member of this network")]
    AccessDenied,
    #[error("internal state is inconsistent")]
    InconsistentState,
    #[error("internal password hashing failure")]
    PasswordHashFailure,
    #[error("storage failure: {0}")]
    StorageFailure(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PublicKey(String);

impl PublicKey {
    pub fn parse(raw: &str) -> Result<Self, CoordinationError> {
        let trimmed = raw.trim();
        let decoded = BASE64_STANDARD
            .decode(trimmed)
            .map_err(|_| CoordinationError::InvalidPublicKey)?;

        if decoded.len() != 32 {
            return Err(CoordinationError::InvalidPublicKey);
        }

        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSnapshot {
    pub username: String,
    pub public_key: PublicKey,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    pub username: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub username: String,
    pub public_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub network_id: Uuid,
    pub name: String,
    pub owner: String,
    pub members: Vec<PeerIdentity>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct UserRecord {
    username: String,
    password_hash: String,
    public_key: PublicKey,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct NetworkRecord {
    network_id: Uuid,
    name: String,
    owner_username_lookup: String,
    member_usernames_lookup: HashSet<String>,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Default)]
struct LoadedState {
    users: HashMap<String, UserRecord>,
    networks: HashMap<Uuid, NetworkRecord>,
}

#[derive(Debug, Clone)]
struct SqliteCoordinationStorage {
    database_path: PathBuf,
}

impl SqliteCoordinationStorage {
    fn open(database_path: &Path) -> Result<Self, CoordinationError> {
        if let Some(parent) = database_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| CoordinationError::StorageFailure(err.to_string()))?;
        }

        let storage = Self {
            database_path: database_path.to_path_buf(),
        };
        storage.init_schema()?;
        Ok(storage)
    }

    fn init_schema(&self) -> Result<(), CoordinationError> {
        self.with_connection(|conn| {
            conn.execute_batch(
                "
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;

                CREATE TABLE IF NOT EXISTS users (
                    username_lookup TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS networks (
                    network_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner_username_lookup TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(owner_username_lookup) REFERENCES users(username_lookup)
                );

                CREATE TABLE IF NOT EXISTS network_members (
                    network_id TEXT NOT NULL,
                    username_lookup TEXT NOT NULL,
                    PRIMARY KEY (network_id, username_lookup),
                    FOREIGN KEY(network_id) REFERENCES networks(network_id) ON DELETE CASCADE,
                    FOREIGN KEY(username_lookup) REFERENCES users(username_lookup) ON DELETE CASCADE
                );
                ",
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, CoordinationError>,
    ) -> Result<T, CoordinationError> {
        let mut connection = Connection::open(&self.database_path).map_err(sqlite_err)?;
        connection
            .execute("PRAGMA foreign_keys=ON", [])
            .map_err(sqlite_err)?;
        operation(&mut connection)
    }

    fn load_snapshot(&self) -> Result<LoadedState, CoordinationError> {
        self.with_connection(|conn| {
            let mut users = HashMap::new();
            let mut networks = HashMap::new();

            let mut user_statement = conn
                .prepare(
                    "
                    SELECT username_lookup, username, password_hash, public_key, created_at
                    FROM users
                    ",
                )
                .map_err(sqlite_err)?;

            let user_rows = user_statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })
                .map_err(sqlite_err)?;

            for row in user_rows {
                let (username_lookup, username, password_hash, public_key_raw, created_at_raw) =
                    row.map_err(sqlite_err)?;
                let public_key = PublicKey::parse(&public_key_raw)?;
                let created_at = parse_rfc3339_utc(&created_at_raw)?;

                users.insert(
                    username_lookup,
                    UserRecord {
                        username,
                        password_hash,
                        public_key,
                        created_at,
                    },
                );
            }

            let mut network_statement = conn
                .prepare(
                    "
                    SELECT network_id, name, owner_username_lookup, created_at
                    FROM networks
                    ",
                )
                .map_err(sqlite_err)?;

            let network_rows = network_statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                })
                .map_err(sqlite_err)?;

            for row in network_rows {
                let (network_id_raw, name, owner_username_lookup, created_at_raw) =
                    row.map_err(sqlite_err)?;
                let network_id = Uuid::parse_str(&network_id_raw)
                    .map_err(|_| CoordinationError::InconsistentState)?;
                let created_at = parse_rfc3339_utc(&created_at_raw)?;

                networks.insert(
                    network_id,
                    NetworkRecord {
                        network_id,
                        name,
                        owner_username_lookup,
                        member_usernames_lookup: HashSet::new(),
                        created_at,
                    },
                );
            }

            let mut member_statement = conn
                .prepare(
                    "
                    SELECT network_id, username_lookup
                    FROM network_members
                    ",
                )
                .map_err(sqlite_err)?;

            let member_rows = member_statement
                .query_map([], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(sqlite_err)?;

            for row in member_rows {
                let (network_id_raw, username_lookup) = row.map_err(sqlite_err)?;
                let network_id = Uuid::parse_str(&network_id_raw)
                    .map_err(|_| CoordinationError::InconsistentState)?;

                let network = networks
                    .get_mut(&network_id)
                    .ok_or(CoordinationError::InconsistentState)?;
                network.member_usernames_lookup.insert(username_lookup);
            }

            Ok(LoadedState { users, networks })
        })
    }

    fn insert_user(
        &self,
        username_lookup: &str,
        record: &UserRecord,
    ) -> Result<(), CoordinationError> {
        self.with_connection(|conn| {
            conn.execute(
                "
                INSERT INTO users (
                    username_lookup, username, password_hash, public_key, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5)
                ",
                params![
                    username_lookup,
                    record.username,
                    record.password_hash,
                    record.public_key.as_str(),
                    record.created_at.to_rfc3339(),
                ],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
    }

    fn insert_network(&self, record: &NetworkRecord) -> Result<(), CoordinationError> {
        self.with_connection(|conn| {
            let transaction = conn.transaction().map_err(sqlite_err)?;
            transaction
                .execute(
                    "
                    INSERT INTO networks (
                        network_id, name, owner_username_lookup, created_at
                    ) VALUES (?1, ?2, ?3, ?4)
                    ",
                    params![
                        record.network_id.to_string(),
                        record.name,
                        record.owner_username_lookup,
                        record.created_at.to_rfc3339(),
                    ],
                )
                .map_err(sqlite_err)?;

            for member_lookup in &record.member_usernames_lookup {
                transaction
                    .execute(
                        "
                        INSERT INTO network_members (
                            network_id, username_lookup
                        ) VALUES (?1, ?2)
                        ",
                        params![record.network_id.to_string(), member_lookup],
                    )
                    .map_err(sqlite_err)?;
            }

            transaction.commit().map_err(sqlite_err)?;
            Ok(())
        })
    }

    fn insert_network_member(
        &self,
        network_id: Uuid,
        username_lookup: &str,
    ) -> Result<(), CoordinationError> {
        self.with_connection(|conn| {
            conn.execute(
                "
                INSERT OR IGNORE INTO network_members (
                    network_id, username_lookup
                ) VALUES (?1, ?2)
                ",
                params![network_id.to_string(), username_lookup],
            )
            .map_err(sqlite_err)?;
            Ok(())
        })
    }
}

#[derive(Debug, Default)]
pub struct ControlPlaneState {
    users: RwLock<HashMap<String, UserRecord>>,
    networks: RwLock<HashMap<Uuid, NetworkRecord>>,
    storage: Option<SqliteCoordinationStorage>,
}

impl ControlPlaneState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_with_sqlite(database_path: impl AsRef<Path>) -> Result<Self, CoordinationError> {
        let storage = SqliteCoordinationStorage::open(database_path.as_ref())?;
        let snapshot = storage.load_snapshot()?;

        Ok(Self {
            users: RwLock::new(snapshot.users),
            networks: RwLock::new(snapshot.networks),
            storage: Some(storage),
        })
    }

    pub fn persistence_backend(&self) -> &'static str {
        if self.storage.is_some() {
            "sqlite"
        } else {
            "memory"
        }
    }

    pub async fn register_user(
        &self,
        username: &str,
        password: &SecretString,
        public_key: &str,
    ) -> Result<UserSnapshot, CoordinationError> {
        validate_username(username)?;
        validate_password_strength(password.expose_secret())?;
        let parsed_public_key = PublicKey::parse(public_key)?;
        let username_lookup = normalize_lookup(username);

        let mut users = self.users.write().await;
        if users.contains_key(&username_lookup) {
            return Err(CoordinationError::UserAlreadyExists);
        }

        let created_at = Utc::now();
        let record = UserRecord {
            username: username.to_owned(),
            password_hash: hash_password(password)?,
            public_key: parsed_public_key.clone(),
            created_at,
        };

        if let Some(storage) = &self.storage {
            storage.insert_user(&username_lookup, &record)?;
        }

        users.insert(username_lookup, record.clone());

        Ok(UserSnapshot {
            username: record.username,
            public_key: record.public_key,
            created_at: record.created_at,
        })
    }

    pub async fn authenticate_user(
        &self,
        username: &str,
        password: &SecretString,
    ) -> Result<AuthenticatedUser, CoordinationError> {
        let username_lookup = normalize_lookup(username);
        let users = self.users.read().await;
        let user = users
            .get(&username_lookup)
            .ok_or(CoordinationError::InvalidCredentials)?;

        verify_password(&user.password_hash, password)?;

        Ok(AuthenticatedUser {
            username: user.username.clone(),
            public_key: user.public_key.clone(),
        })
    }

    pub async fn create_network(
        &self,
        owner_username: &str,
        network_name: &str,
    ) -> Result<NetworkSummary, CoordinationError> {
        validate_network_name(network_name)?;

        let owner_lookup = normalize_lookup(owner_username);
        {
            let users = self.users.read().await;
            if !users.contains_key(&owner_lookup) {
                return Err(CoordinationError::UserNotFound);
            }
        }

        let network_id = Uuid::new_v4();
        let created_at = Utc::now();

        let mut record = NetworkRecord {
            network_id,
            name: network_name.trim().to_owned(),
            owner_username_lookup: owner_lookup.clone(),
            member_usernames_lookup: HashSet::new(),
            created_at,
        };
        record.member_usernames_lookup.insert(owner_lookup);

        let mut networks = self.networks.write().await;
        if let Some(storage) = &self.storage {
            storage.insert_network(&record)?;
        }
        networks.insert(network_id, record);
        drop(networks);

        self.get_network_summary(network_id).await
    }

    pub async fn join_network(
        &self,
        network_id: Uuid,
        username: &str,
    ) -> Result<NetworkSummary, CoordinationError> {
        let username_lookup = normalize_lookup(username);

        {
            let users = self.users.read().await;
            if !users.contains_key(&username_lookup) {
                return Err(CoordinationError::UserNotFound);
            }
        }

        let mut networks = self.networks.write().await;
        let network = networks
            .get_mut(&network_id)
            .ok_or(CoordinationError::NetworkNotFound)?;

        if !network.member_usernames_lookup.contains(&username_lookup) {
            if let Some(storage) = &self.storage {
                storage.insert_network_member(network_id, &username_lookup)?;
            }
            network.member_usernames_lookup.insert(username_lookup);
        }

        drop(networks);
        self.get_network_summary(network_id).await
    }

    pub async fn list_peers(
        &self,
        network_id: Uuid,
        requester_username: &str,
    ) -> Result<Vec<PeerIdentity>, CoordinationError> {
        let requester_lookup = normalize_lookup(requester_username);
        let member_usernames = {
            let networks = self.networks.read().await;
            let network = networks
                .get(&network_id)
                .ok_or(CoordinationError::NetworkNotFound)?;

            if !network.member_usernames_lookup.contains(&requester_lookup) {
                return Err(CoordinationError::AccessDenied);
            }

            network
                .member_usernames_lookup
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        };

        let users = self.users.read().await;
        let mut peers = Vec::with_capacity(member_usernames.len());

        for member_lookup in member_usernames {
            let member = users
                .get(&member_lookup)
                .ok_or(CoordinationError::InconsistentState)?;
            peers.push(PeerIdentity {
                username: member.username.clone(),
                public_key: member.public_key.clone(),
            });
        }

        peers.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(peers)
    }

    pub async fn get_network_summary(
        &self,
        network_id: Uuid,
    ) -> Result<NetworkSummary, CoordinationError> {
        let network_record = {
            let networks = self.networks.read().await;
            networks
                .get(&network_id)
                .cloned()
                .ok_or(CoordinationError::NetworkNotFound)?
        };

        let users = self.users.read().await;
        let owner = users
            .get(&network_record.owner_username_lookup)
            .ok_or(CoordinationError::InconsistentState)?;

        let mut members = Vec::with_capacity(network_record.member_usernames_lookup.len());
        for lookup in &network_record.member_usernames_lookup {
            let user = users
                .get(lookup)
                .ok_or(CoordinationError::InconsistentState)?;
            members.push(PeerIdentity {
                username: user.username.clone(),
                public_key: user.public_key.clone(),
            });
        }
        members.sort_by(|a, b| a.username.cmp(&b.username));

        Ok(NetworkSummary {
            network_id: network_record.network_id,
            name: network_record.name,
            owner: owner.username.clone(),
            members,
            created_at: network_record.created_at,
        })
    }
}

fn normalize_lookup(username: &str) -> String {
    username.trim().to_ascii_lowercase()
}

fn validate_username(username: &str) -> Result<(), CoordinationError> {
    static USERNAME_PATTERN: OnceLock<Regex> = OnceLock::new();
    let username = username.trim();

    let regex = USERNAME_PATTERN.get_or_init(|| match Regex::new(r"^[a-zA-Z0-9_.-]{3,32}$") {
        Ok(compiled) => compiled,
        Err(_) => unreachable!("hardcoded username regex must compile"),
    });

    if regex.is_match(username) {
        Ok(())
    } else {
        Err(CoordinationError::InvalidUsername)
    }
}

fn validate_password_strength(password: &str) -> Result<(), CoordinationError> {
    let has_upper = password.chars().any(|ch| ch.is_ascii_uppercase());
    let has_lower = password.chars().any(|ch| ch.is_ascii_lowercase());
    let has_digit = password.chars().any(|ch| ch.is_ascii_digit());

    if password.len() < MIN_PASSWORD_LEN || !has_upper || !has_lower || !has_digit {
        return Err(CoordinationError::WeakPassword);
    }

    Ok(())
}

fn validate_network_name(name: &str) -> Result<(), CoordinationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_NETWORK_NAME_LEN {
        return Err(CoordinationError::InvalidNetworkName);
    }

    Ok(())
}

fn hash_password(password: &SecretString) -> Result<String, CoordinationError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.expose_secret().as_bytes(), &salt)
        .map(|hashed| hashed.to_string())
        .map_err(|_| CoordinationError::PasswordHashFailure)
}

fn verify_password(password_hash: &str, password: &SecretString) -> Result<(), CoordinationError> {
    let parsed_hash =
        PasswordHash::new(password_hash).map_err(|_| CoordinationError::PasswordHashFailure)?;

    Argon2::default()
        .verify_password(password.expose_secret().as_bytes(), &parsed_hash)
        .map_err(|_| CoordinationError::InvalidCredentials)
}

fn parse_rfc3339_utc(raw: &str) -> Result<DateTime<Utc>, CoordinationError> {
    DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CoordinationError::InconsistentState)
}

fn sqlite_err(err: rusqlite::Error) -> CoordinationError {
    CoordinationError::StorageFailure(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_public_key(seed: u8) -> String {
        BASE64_STANDARD.encode([seed; 32])
    }

    fn cleanup_sqlite_files(database_path: &Path) {
        let _ = std::fs::remove_file(database_path);
        let _ = std::fs::remove_file(format!("{}-wal", database_path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", database_path.display()));
    }

    #[test]
    fn public_key_parser_rejects_invalid_key_data() {
        assert!(PublicKey::parse("not-a-valid-key").is_err());
        let short_key = BASE64_STANDARD.encode([9_u8; 31]);
        assert!(PublicKey::parse(&short_key).is_err());
    }

    #[tokio::test]
    async fn register_and_authenticate_user_round_trip() {
        let state = ControlPlaneState::new();
        let password = SecretString::new("ValidPassword123".to_owned());
        let register = state
            .register_user("alice", &password, &fixture_public_key(1))
            .await;
        assert!(register.is_ok());

        let auth = state.authenticate_user("alice", &password).await;
        assert!(auth.is_ok());
    }

    #[tokio::test]
    async fn network_membership_returns_all_peers() {
        let state = ControlPlaneState::new();
        let alice_password = SecretString::new("ValidPassword123".to_owned());
        let bob_password = SecretString::new("DifferentPass123".to_owned());

        let register_alice = state
            .register_user("alice", &alice_password, &fixture_public_key(3))
            .await;
        let register_bob = state
            .register_user("bob", &bob_password, &fixture_public_key(4))
            .await;
        assert!(register_alice.is_ok());
        assert!(register_bob.is_ok());

        let network = state.create_network("alice", "friends").await;
        assert!(network.is_ok());
        let network_id = if let Ok(summary) = network {
            summary.network_id
        } else {
            Uuid::nil()
        };

        assert_ne!(network_id, Uuid::nil());

        let join = state.join_network(network_id, "bob").await;
        assert!(join.is_ok());

        let peers = state.list_peers(network_id, "alice").await;
        assert!(peers.is_ok());

        let peer_count = if let Ok(items) = peers {
            items.len()
        } else {
            0
        };
        assert_eq!(peer_count, 2);
    }

    #[tokio::test]
    async fn sqlite_storage_survives_restart() {
        let database_path =
            std::env::temp_dir().join(format!("kakachi-coordination-{}.db", Uuid::new_v4()));
        cleanup_sqlite_files(&database_path);

        let created_network_id = {
            let state_result = ControlPlaneState::new_with_sqlite(&database_path);
            assert!(state_result.is_ok());
            let state = if let Ok(value) = state_result {
                value
            } else {
                return;
            };

            let alice_password = SecretString::new("ValidPassword123".to_owned());
            let bob_password = SecretString::new("DifferentPass123".to_owned());

            let register_alice = state
                .register_user("alice", &alice_password, &fixture_public_key(5))
                .await;
            let register_bob = state
                .register_user("bob", &bob_password, &fixture_public_key(6))
                .await;
            assert!(register_alice.is_ok());
            assert!(register_bob.is_ok());

            let network = state.create_network("alice", "persisted").await;
            assert!(network.is_ok());
            let network_id = if let Ok(summary) = network {
                summary.network_id
            } else {
                Uuid::nil()
            };

            assert_ne!(network_id, Uuid::nil());
            let join = state.join_network(network_id, "bob").await;
            assert!(join.is_ok());
            network_id
        };

        let reloaded_result = ControlPlaneState::new_with_sqlite(&database_path);
        assert!(reloaded_result.is_ok());
        let reloaded = if let Ok(value) = reloaded_result {
            value
        } else {
            cleanup_sqlite_files(&database_path);
            return;
        };

        let peers = reloaded.list_peers(created_network_id, "alice").await;
        assert!(peers.is_ok());
        let peer_count = if let Ok(items) = peers {
            items.len()
        } else {
            0
        };
        assert_eq!(peer_count, 2);

        cleanup_sqlite_files(&database_path);
    }
}
