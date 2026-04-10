use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, PasswordHasher, SaltString};
use argon2::{Argon2, PasswordVerifier};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use rand::rngs::OsRng;
use regex::Regex;
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
pub struct ControlPlaneState {
    users: RwLock<HashMap<String, UserRecord>>,
    networks: RwLock<HashMap<Uuid, NetworkRecord>>,
}

impl ControlPlaneState {
    pub fn new() -> Self {
        Self::default()
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
        network.member_usernames_lookup.insert(username_lookup);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_public_key(seed: u8) -> String {
        BASE64_STANDARD.encode([seed; 32])
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
}
