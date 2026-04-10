use std::net::SocketAddr;

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const MAX_NETWORK_NAME_LEN: usize = 64;
const MAX_STUN_SERVERS: usize = 8;

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
    #[error("invalid STUN server address")]
    InvalidStunServer,
    #[error("too many STUN servers, max allowed is {MAX_STUN_SERVERS}")]
    TooManyStunServers,
    #[error("at least one STUN server is required")]
    MissingStunServers,
    #[error("invalid session report: {0}")]
    InvalidSessionReport(&'static str),
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StunServer {
    pub addr: SocketAddr,
    pub priority: u8,
}

pub fn parse_stun_servers(raw_servers: &[String]) -> Result<Vec<StunServer>, NetError> {
    if raw_servers.len() > MAX_STUN_SERVERS {
        return Err(NetError::TooManyStunServers);
    }

    let mut servers = Vec::with_capacity(raw_servers.len());
    for (index, raw) in raw_servers.iter().enumerate() {
        let parsed = raw
            .trim()
            .parse::<SocketAddr>()
            .map_err(|_| NetError::InvalidStunServer)?;
        servers.push(StunServer {
            addr: parsed,
            priority: (index as u8) + 1,
        });
    }

    Ok(servers)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectivityPath {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionReason {
    AwaitingReports,
    DirectReady,
    SymmetricNatDetected,
    MissingCandidates,
    MaxAttemptsExceeded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionReport {
    pub nat_type: NatType,
    pub attempt: u8,
    pub candidate_count: u8,
    pub direct_ready: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDecision {
    pub path: ConnectivityPath,
    pub reason: DecisionReason,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StunProbePlan {
    pub servers: Vec<StunServer>,
    pub probe_timeout_secs: u16,
}

pub fn build_stun_probe_plan(
    policy: &TraversalPolicy,
    raw_servers: &[String],
) -> Result<StunProbePlan, NetError> {
    policy.validate()?;
    let servers = parse_stun_servers(raw_servers)?;
    if servers.is_empty() {
        return Err(NetError::MissingStunServers);
    }

    Ok(StunProbePlan {
        servers,
        probe_timeout_secs: policy.direct_connect_timeout_secs,
    })
}

pub fn infer_nat_type(observations: &[NatObservation]) -> NatType {
    if observations.is_empty() {
        return NatType::Unknown;
    }

    let first = observations[0].observed_addr;
    let stable_mapping = observations
        .iter()
        .all(|entry| entry.observed_addr == first);

    if stable_mapping {
        NatType::RestrictedCone
    } else {
        NatType::Symmetric
    }
}

pub fn build_session_report(
    policy: &TraversalPolicy,
    attempt: u8,
    candidate_count: usize,
    direct_ready: bool,
    observations: &[NatObservation],
) -> Result<SessionReport, NetError> {
    let candidate_count_u8 = u8::try_from(candidate_count)
        .map_err(|_| NetError::InvalidSessionReport("candidate_count exceeds u8::MAX"))?;

    let report = SessionReport {
        nat_type: infer_nat_type(observations),
        attempt,
        candidate_count: candidate_count_u8,
        direct_ready,
    };
    validate_session_report(policy, &report)?;
    Ok(report)
}

pub fn decide_session_path(
    policy: &TraversalPolicy,
    initiator: &SessionReport,
    responder: &SessionReport,
) -> Result<SessionDecision, NetError> {
    policy.validate()?;
    validate_session_report(policy, initiator)?;
    validate_session_report(policy, responder)?;

    if initiator.direct_ready && responder.direct_ready {
        return Ok(SessionDecision {
            path: ConnectivityPath::Direct,
            reason: DecisionReason::DirectReady,
        });
    }

    if initiator.nat_type == NatType::Symmetric || responder.nat_type == NatType::Symmetric {
        return Ok(SessionDecision {
            path: ConnectivityPath::Relay,
            reason: DecisionReason::SymmetricNatDetected,
        });
    }

    if initiator.candidate_count == 0 || responder.candidate_count == 0 {
        return Ok(SessionDecision {
            path: ConnectivityPath::Relay,
            reason: DecisionReason::MissingCandidates,
        });
    }

    let max_attempt = initiator.attempt.max(responder.attempt);
    if max_attempt >= policy.max_hole_punch_attempts {
        return Ok(SessionDecision {
            path: ConnectivityPath::Relay,
            reason: DecisionReason::MaxAttemptsExceeded,
        });
    }

    Ok(SessionDecision {
        path: ConnectivityPath::Direct,
        reason: DecisionReason::AwaitingReports,
    })
}

fn validate_session_report(
    policy: &TraversalPolicy,
    report: &SessionReport,
) -> Result<(), NetError> {
    if report.attempt == 0 || report.attempt > policy.max_hole_punch_attempts {
        return Err(NetError::InvalidSessionReport(
            "attempt must be in 1..=max_hole_punch_attempts",
        ));
    }

    Ok(())
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

    #[test]
    fn parse_stun_servers_rejects_invalid_addr() {
        let servers = parse_stun_servers(&["bad-address".to_owned()]);
        assert!(servers.is_err());
    }

    #[test]
    fn decide_session_path_prefers_relay_for_symmetric_nat() {
        let policy = TraversalPolicy::default();
        let initiator = SessionReport {
            nat_type: NatType::Symmetric,
            attempt: 1,
            candidate_count: 2,
            direct_ready: false,
        };
        let responder = SessionReport {
            nat_type: NatType::FullCone,
            attempt: 1,
            candidate_count: 2,
            direct_ready: false,
        };

        let decision = decide_session_path(&policy, &initiator, &responder);
        assert!(decision.is_ok());
        let decision = if let Ok(value) = decision {
            value
        } else {
            return;
        };

        assert_eq!(decision.path, ConnectivityPath::Relay);
        assert_eq!(decision.reason, DecisionReason::SymmetricNatDetected);
    }

    #[test]
    fn decide_session_path_marks_direct_ready() {
        let policy = TraversalPolicy::default();
        let initiator = SessionReport {
            nat_type: NatType::RestrictedCone,
            attempt: 2,
            candidate_count: 3,
            direct_ready: true,
        };
        let responder = SessionReport {
            nat_type: NatType::RestrictedCone,
            attempt: 2,
            candidate_count: 2,
            direct_ready: true,
        };

        let decision = decide_session_path(&policy, &initiator, &responder);
        assert!(decision.is_ok());
        let decision = if let Ok(value) = decision {
            value
        } else {
            return;
        };

        assert_eq!(decision.path, ConnectivityPath::Direct);
        assert_eq!(decision.reason, DecisionReason::DirectReady);
    }

    #[test]
    fn build_stun_probe_plan_rejects_empty_server_list() {
        let policy = TraversalPolicy::default();
        let plan = build_stun_probe_plan(&policy, &[]);
        assert!(plan.is_err());
    }

    #[test]
    fn infer_nat_type_detects_symmetric_when_mapping_changes() {
        let first_addr = match "198.51.100.11:51820".parse::<SocketAddr>() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse first addr: {error}"),
        };
        let second_addr = match "198.51.100.11:51821".parse::<SocketAddr>() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse second addr: {error}"),
        };

        let observations = vec![
            NatObservation {
                observed_addr: first_addr,
                nat_type: NatType::Unknown,
                recorded_at: Utc::now(),
            },
            NatObservation {
                observed_addr: second_addr,
                nat_type: NatType::Unknown,
                recorded_at: Utc::now(),
            },
        ];

        let inferred = infer_nat_type(&observations);
        assert_eq!(inferred, NatType::Symmetric);
    }

    #[test]
    fn build_session_report_generates_valid_payload() {
        let addr = match "198.51.100.44:51820".parse::<SocketAddr>() {
            Ok(value) => value,
            Err(error) => panic!("failed to parse addr: {error}"),
        };

        let observations = vec![NatObservation {
            observed_addr: addr,
            nat_type: NatType::Unknown,
            recorded_at: Utc::now(),
        }];

        let report = build_session_report(&TraversalPolicy::default(), 1, 2, false, &observations);
        assert!(report.is_ok());

        let report = if let Ok(value) = report {
            value
        } else {
            return;
        };
        assert_eq!(report.nat_type, NatType::RestrictedCone);
        assert_eq!(report.attempt, 1);
        assert_eq!(report.candidate_count, 2);
    }
}
