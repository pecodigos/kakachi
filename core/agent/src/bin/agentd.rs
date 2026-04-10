use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Context;
use kakachi_agent::{AgentConfig, AgentService, ControlPlaneClient};
use kakachi_net::TraversalPolicy;
use tracing::info;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let data_dir = std::env::var("KAKACHI_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("./.kakachi"));

    let database_path = std::env::var("KAKACHI_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| data_dir.join("agent.db"));

    let config = AgentConfig {
        control_plane_url: std::env::var("KAKACHI_CONTROL_PLANE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080".to_owned()),
        local_bind_addr: std::env::var("KAKACHI_AGENT_BIND")
            .unwrap_or_else(|_| "127.0.0.1:7000".to_owned()),
        data_dir,
        database_path,
    };

    let service = AgentService::new(config, TraversalPolicy::default())?;

    info!(
        control_plane = %service.config().control_plane_url,
        bind = %service.config().local_bind_addr,
        "kakachi agent daemon initialized"
    );

    if let Some(run) = load_negotiation_run_config()? {
        info!(
            network_id = %run.network_id,
            peer = %run.peer_username,
            session_id = ?run.session_id,
            stun_servers = ?run.stun_servers,
            "running one-shot session negotiation"
        );

        let control_plane =
            ControlPlaneClient::new(&service.config().control_plane_url, run.access_token)?;

        let summary = service
            .run_session_negotiation(
                &control_plane,
                run.network_id,
                &run.peer_username,
                run.session_id,
                &run.stun_servers,
            )
            .await?;

        info!(
            session_id = %summary.session_id,
            state = ?summary.final_state,
            path = ?summary.final_path,
            reason = ?summary.final_reason,
            attempts = summary.attempts_sent,
            "session negotiation completed"
        );

        return Ok(());
    }

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");

    Ok(())
}

fn init_tracing() {
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "kakachi_agent=info".to_owned());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .compact()
        .init();
}

struct NegotiationRunConfig {
    network_id: Uuid,
    peer_username: String,
    session_id: Option<Uuid>,
    access_token: String,
    stun_servers: Vec<String>,
}

fn load_negotiation_run_config() -> anyhow::Result<Option<NegotiationRunConfig>> {
    let network_id_raw = match std::env::var("KAKACHI_AGENT_NEGOTIATE_NETWORK_ID") {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => return Ok(None),
        Err(error) => return Err(error.into()),
    };

    let network_id = Uuid::from_str(network_id_raw.trim())
        .context("KAKACHI_AGENT_NEGOTIATE_NETWORK_ID must be a valid UUID")?;

    let session_id = match std::env::var("KAKACHI_AGENT_NEGOTIATE_SESSION_ID") {
        Ok(value) => Some(
            Uuid::from_str(value.trim())
                .context("KAKACHI_AGENT_NEGOTIATE_SESSION_ID must be a valid UUID")?,
        ),
        Err(std::env::VarError::NotPresent) => None,
        Err(error) => return Err(error.into()),
    };

    let peer_username = std::env::var("KAKACHI_AGENT_NEGOTIATE_PEER")
        .context("KAKACHI_AGENT_NEGOTIATE_PEER is required when negotiation mode is enabled")?
        .trim()
        .to_owned();
    if peer_username.is_empty() {
        anyhow::bail!("KAKACHI_AGENT_NEGOTIATE_PEER cannot be empty");
    }

    let access_token = std::env::var("KAKACHI_AGENT_AUTH_TOKEN")
        .context("KAKACHI_AGENT_AUTH_TOKEN is required when negotiation mode is enabled")?
        .trim()
        .to_owned();
    if access_token.is_empty() {
        anyhow::bail!("KAKACHI_AGENT_AUTH_TOKEN cannot be empty");
    }

    let stun_servers_raw = std::env::var("KAKACHI_AGENT_STUN_SERVERS")
        .context("KAKACHI_AGENT_STUN_SERVERS is required when negotiation mode is enabled")?;
    let stun_servers = stun_servers_raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if stun_servers.is_empty() {
        anyhow::bail!("KAKACHI_AGENT_STUN_SERVERS must contain at least one ip:port entry");
    }

    Ok(Some(NegotiationRunConfig {
        network_id,
        peer_username,
        session_id,
        access_token,
        stun_servers,
    }))
}
