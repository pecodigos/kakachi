use std::path::PathBuf;

use kakachi_agent::{AgentConfig, AgentService};
use kakachi_net::TraversalPolicy;
use tracing::info;

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
