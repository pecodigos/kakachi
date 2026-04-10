use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ipnet::IpNet;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

#[derive(Debug, Error)]
pub enum WgError {
    #[error("invalid WireGuard base64 key")]
    InvalidKey,
    #[error("invalid interface name")]
    InvalidInterfaceName,
    #[error("listen port must be in 1..=65535")]
    InvalidListenPort,
    #[error("private key file path must be set")]
    InvalidPrivateKeyFile,
    #[error("invalid peer allowed IP: {0}")]
    InvalidAllowedIp(String),
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("windows tunnel config path must be set")]
    InvalidWindowsTunnelConfig,
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WireGuardPrivateKey(String);

impl fmt::Debug for WireGuardPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WireGuardPrivateKey(REDACTED)")
    }
}

impl WireGuardPrivateKey {
    pub fn parse(raw: &str) -> Result<Self, WgError> {
        let trimmed = raw.trim();
        validate_base64_key(trimmed)?;
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGuardPublicKey(String);

impl WireGuardPublicKey {
    pub fn parse(raw: &str) -> Result<Self, WgError> {
        let trimmed = raw.trim();
        validate_base64_key(trimmed)?;
        Ok(Self(trimmed.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct WireGuardKeyPair {
    pub private_key: WireGuardPrivateKey,
    pub public_key: WireGuardPublicKey,
}

impl WireGuardKeyPair {
    pub fn generate() -> Self {
        let private = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&private);

        let private_key = WireGuardPrivateKey(BASE64_STANDARD.encode(private.to_bytes()));
        let public_key = WireGuardPublicKey(BASE64_STANDARD.encode(public.as_bytes()));

        Self {
            private_key,
            public_key,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    pub public_key: WireGuardPublicKey,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive_secs: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceConfig {
    pub interface_name: String,
    pub address_cidr: String,
    pub listen_port: u16,
    pub private_key_file: String,
    pub peers: Vec<PeerConfig>,
}

impl InterfaceConfig {
    pub fn validate(&self) -> Result<(), WgError> {
        validate_interface_name(&self.interface_name)?;

        if self.listen_port == 0 {
            return Err(WgError::InvalidListenPort);
        }

        if self.private_key_file.trim().is_empty() {
            return Err(WgError::InvalidPrivateKeyFile);
        }

        let _: IpNet = self
            .address_cidr
            .parse()
            .map_err(|_| WgError::InvalidAllowedIp(self.address_cidr.clone()))?;

        for peer in &self.peers {
            if peer.allowed_ips.is_empty() {
                return Err(WgError::InvalidAllowedIp(
                    "peer allowed_ips cannot be empty".to_owned(),
                ));
            }

            for allowed in &peer.allowed_ips {
                let _: IpNet = allowed
                    .parse()
                    .map_err(|_| WgError::InvalidAllowedIp(allowed.clone()))?;
            }

            if let Some(endpoint) = &peer.endpoint {
                if endpoint.trim().is_empty() || !endpoint.contains(':') {
                    return Err(WgError::InvalidEndpoint(endpoint.clone()));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgCommandPlan {
    pub commands: Vec<Vec<String>>,
}

pub trait WireGuardBackend {
    fn build_plan(&self, config: &InterfaceConfig) -> Result<WgCommandPlan, WgError>;
}

#[derive(Debug, Default)]
pub struct LinuxWgCliBackend;

impl WireGuardBackend for LinuxWgCliBackend {
    fn build_plan(&self, config: &InterfaceConfig) -> Result<WgCommandPlan, WgError> {
        config.validate()?;

        let mut commands = vec![
            vec![
                "ip".to_owned(),
                "link".to_owned(),
                "add".to_owned(),
                "dev".to_owned(),
                config.interface_name.clone(),
                "type".to_owned(),
                "wireguard".to_owned(),
            ],
            vec![
                "ip".to_owned(),
                "address".to_owned(),
                "add".to_owned(),
                config.address_cidr.clone(),
                "dev".to_owned(),
                config.interface_name.clone(),
            ],
            vec![
                "wg".to_owned(),
                "set".to_owned(),
                config.interface_name.clone(),
                "private-key".to_owned(),
                config.private_key_file.clone(),
                "listen-port".to_owned(),
                config.listen_port.to_string(),
            ],
        ];

        for peer in &config.peers {
            let mut peer_command = vec![
                "wg".to_owned(),
                "set".to_owned(),
                config.interface_name.clone(),
                "peer".to_owned(),
                peer.public_key.as_str().to_owned(),
                "allowed-ips".to_owned(),
                peer.allowed_ips.join(","),
            ];

            if let Some(endpoint) = &peer.endpoint {
                peer_command.push("endpoint".to_owned());
                peer_command.push(endpoint.clone());
            }

            if let Some(keepalive) = peer.persistent_keepalive_secs {
                peer_command.push("persistent-keepalive".to_owned());
                peer_command.push(keepalive.to_string());
            }

            commands.push(peer_command);
        }

        commands.push(vec![
            "ip".to_owned(),
            "link".to_owned(),
            "set".to_owned(),
            "up".to_owned(),
            "dev".to_owned(),
            config.interface_name.clone(),
        ]);

        Ok(WgCommandPlan { commands })
    }
}

#[derive(Debug, Clone)]
pub struct WindowsWgNtBackend {
    pub tunnel_config_path: String,
}

impl WireGuardBackend for WindowsWgNtBackend {
    fn build_plan(&self, config: &InterfaceConfig) -> Result<WgCommandPlan, WgError> {
        config.validate()?;

        if self.tunnel_config_path.trim().is_empty() {
            return Err(WgError::InvalidWindowsTunnelConfig);
        }

        Ok(WgCommandPlan {
            commands: vec![vec![
                "wireguard.exe".to_owned(),
                "/installtunnelservice".to_owned(),
                self.tunnel_config_path.clone(),
            ]],
        })
    }
}

fn validate_base64_key(raw: &str) -> Result<(), WgError> {
    let decoded = BASE64_STANDARD
        .decode(raw)
        .map_err(|_| WgError::InvalidKey)?;
    if decoded.len() != 32 {
        return Err(WgError::InvalidKey);
    }
    Ok(())
}

fn validate_interface_name(interface_name: &str) -> Result<(), WgError> {
    if interface_name.is_empty() || interface_name.len() > 15 {
        return Err(WgError::InvalidInterfaceName);
    }

    if interface_name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
    {
        Ok(())
    } else {
        Err(WgError::InvalidInterfaceName)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypair_parses_successfully() {
        let keypair = WireGuardKeyPair::generate();
        assert!(WireGuardPrivateKey::parse(keypair.private_key.as_str()).is_ok());
        assert!(WireGuardPublicKey::parse(keypair.public_key.as_str()).is_ok());
    }

    #[test]
    fn interface_validation_rejects_empty_peer_allowed_ips() {
        let peer_key = WireGuardKeyPair::generate().public_key;
        let config = InterfaceConfig {
            interface_name: "kak0".to_owned(),
            address_cidr: "10.0.0.1/24".to_owned(),
            listen_port: 51820,
            private_key_file: "/tmp/private.key".to_owned(),
            peers: vec![PeerConfig {
                public_key: peer_key,
                endpoint: None,
                allowed_ips: Vec::new(),
                persistent_keepalive_secs: Some(25),
            }],
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn linux_backend_builds_command_plan() {
        let peer_key = WireGuardKeyPair::generate().public_key;
        let config = InterfaceConfig {
            interface_name: "kak0".to_owned(),
            address_cidr: "10.0.0.1/24".to_owned(),
            listen_port: 51820,
            private_key_file: "/etc/kakachi/private.key".to_owned(),
            peers: vec![PeerConfig {
                public_key: peer_key,
                endpoint: Some("198.51.100.10:51820".to_owned()),
                allowed_ips: vec!["10.0.0.2/32".to_owned()],
                persistent_keepalive_secs: Some(25),
            }],
        };

        let backend = LinuxWgCliBackend;
        let plan = backend.build_plan(&config);
        assert!(plan.is_ok());

        let command_count = if let Ok(plan) = plan {
            plan.commands.len()
        } else {
            0
        };
        assert!(command_count >= 4);
    }
}
