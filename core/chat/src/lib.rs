use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_CIPHERTEXT_BYTES: usize = 32 * 1024;

#[derive(Debug, Error)]
pub enum ChatError {
    #[error("sender public key is missing")]
    MissingSenderKey,
    #[error("ciphertext payload is empty")]
    EmptyCiphertext,
    #[error("ciphertext payload is too large")]
    OversizedCiphertext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransportPath {
    DirectP2p,
    RelayWebSocket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatEnvelope {
    pub message_id: Uuid,
    pub network_id: Uuid,
    pub sender_public_key: String,
    pub ciphertext: Vec<u8>,
    pub sent_at: DateTime<Utc>,
}

impl ChatEnvelope {
    pub fn new(network_id: Uuid, sender_public_key: String, ciphertext: Vec<u8>) -> Self {
        Self {
            message_id: Uuid::new_v4(),
            network_id,
            sender_public_key,
            ciphertext,
            sent_at: Utc::now(),
        }
    }

    pub fn validate(&self) -> Result<(), ChatError> {
        if self.sender_public_key.trim().is_empty() {
            return Err(ChatError::MissingSenderKey);
        }

        if self.ciphertext.is_empty() {
            return Err(ChatError::EmptyCiphertext);
        }

        if self.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
            return Err(ChatError::OversizedCiphertext);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceUpdate {
    pub network_id: Uuid,
    pub username: String,
    pub online: bool,
    pub observed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub message_id: Uuid,
    pub network_id: Uuid,
    pub sender_public_key: String,
    pub ciphertext: Vec<u8>,
    pub sent_at: DateTime<Utc>,
    pub transport_path: TransportPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_rejects_oversized_payload() {
        let envelope = ChatEnvelope::new(
            Uuid::new_v4(),
            "sender-key".to_owned(),
            vec![7_u8; MAX_CIPHERTEXT_BYTES + 1],
        );

        assert!(envelope.validate().is_err());
    }

    #[test]
    fn envelope_accepts_valid_payload() {
        let envelope = ChatEnvelope::new(Uuid::new_v4(), "sender-key".to_owned(), vec![1, 2, 3]);
        assert!(envelope.validate().is_ok());
    }
}
