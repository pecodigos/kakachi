use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_NETWORK_NAME_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("network name cannot be empty or larger than {MAX_NETWORK_NAME_LEN} chars")]
    InvalidNetworkName,
    #[error("cidr must be a valid IP network")]
    InvalidCidr,
    #[error("cidr must use private IP space")]
    NonPrivateCidr,
    #[error("only IPv4 cidr blocks are currently supported")]
    UnsupportedAddressFamily,
    #[error("traversal policy is invalid: {0}")]
    InvalidTraversalPolicy(&'static str),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatObservation {
    pub observed_addr: SocketAddr,
    pub nat_type: NatType,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEndpointHints {
    pub network_id: Uuid,
    pub peer_public_key: String,
    pub direct_candidates: Vec<SocketAddr>,
    pub last_observation: Option<NatObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalPolicy {
    pub max_hole_punch_attempts: u8,
    pub direct_connect_timeout_secs: u16,
    pub relay_backoff_secs: u16,
}

impl Default for TraversalPolicy {
    fn default() -> Self {
        Self {
            max_hole_punch_attempts: 6,
            direct_connect_timeout_secs: 7,
            relay_backoff_secs: 3,
        }
    }
}

impl TraversalPolicy {
    pub fn validate(&self) -> Result<(), NetError> {
        if self.max_hole_punch_attempts == 0 || self.max_hole_punch_attempts > 20 {
            return Err(NetError::InvalidTraversalPolicy(
                "max_hole_punch_attempts must be 1..=20",
            ));
        }

        if self.direct_connect_timeout_secs == 0 || self.direct_connect_timeout_secs > 60 {
            return Err(NetError::InvalidTraversalPolicy(
                "direct_connect_timeout_secs must be 1..=60",
            ));
        }

        if self.relay_backoff_secs == 0 || self.relay_backoff_secs > 30 {
            return Err(NetError::InvalidTraversalPolicy(
                "relay_backoff_secs must be 1..=30",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualNetwork {
    pub id: Uuid,
    pub name: String,
    pub cidr: IpNet,
    pub created_at: DateTime<Utc>,
}

impl VirtualNetwork {
    pub fn new(id: Uuid, name: &str, cidr: &str) -> Result<Self, NetError> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() || trimmed_name.len() > MAX_NETWORK_NAME_LEN {
            return Err(NetError::InvalidNetworkName);
        }

        let parsed_cidr: IpNet = cidr.parse().map_err(|_| NetError::InvalidCidr)?;
        match parsed_cidr {
            IpNet::V4(v4) => {
                if !v4.addr().is_private() {
                    return Err(NetError::NonPrivateCidr);
                }
            }
            IpNet::V6(_) => return Err(NetError::UnsupportedAddressFamily),
        }

        Ok(Self {
            id,
            name: trimmed_name.to_owned(),
            cidr: parsed_cidr,
            created_at: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traversal_policy_rejects_zero_attempts() {
        let policy = TraversalPolicy {
            max_hole_punch_attempts: 0,
            ..TraversalPolicy::default()
        };

        assert!(policy.validate().is_err());
    }

    #[test]
    fn virtual_network_accepts_private_cidr() {
        let network = VirtualNetwork::new(Uuid::new_v4(), "friends", "10.42.0.0/24");
        assert!(network.is_ok());
    }

    #[test]
    fn virtual_network_rejects_public_cidr() {
        let network = VirtualNetwork::new(Uuid::new_v4(), "public", "8.8.8.0/24");
        assert!(network.is_err());
    }
}
