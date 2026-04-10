# Kakachi

Kakachi is a production-oriented Hamachi-like VPN system in Rust for real-world friend-to-friend use.

This repository now contains the Phase 1 foundation:

- Control plane server (HTTPS/WebSocket-ready API skeleton)
- Core agent daemon crate with local SQLite state
- Core networking, WireGuard, and chat domain crates
- Security-first defaults (input validation, key validation, no custom cryptography)

## Workspace Layout

- core/agent: local daemon, SQLite storage, WireGuard command plan staging
- core/net: virtual network and NAT traversal models
- core/wg: WireGuard key management and backend command plans
- core/chat: encrypted payload envelope model and transport metadata
- server/coordination: auth and room membership coordination logic
- server/api: Axum HTTP/WebSocket control-plane API
- desktop: reserved for Tauri + React app (Phase 3)

## Security Baseline In This Phase

- WireGuard key format validation (32-byte base64 keys)
- Argon2 password hashing
- JWT auth tokens with required secret length
- Strict input validation for usernames, passwords, network names, CIDRs
- Relay path modeling keeps end-to-end encryption responsibility in clients
- unsafe Rust disallowed at workspace lint level

## Prerequisites

### Linux

- Rust stable toolchain
- pkg-config and build essentials
- wireguard-tools and iproute2 for real tunnel provisioning

Example package install:

```bash
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev wireguard-tools iproute2
```

### Windows

- Rust stable toolchain (MSVC target)
- Visual Studio Build Tools (C++ workload)
- WireGuard for Windows installed
- Administrator rights for tunnel setup operations

## Environment Variables

Control plane server:

- KAKACHI_JWT_SECRET: required, at least 32 chars
- KAKACHI_API_BIND: optional, default 127.0.0.1:8080

Agent daemon:

- KAKACHI_CONTROL_PLANE_URL: default http://127.0.0.1:8080
- KAKACHI_AGENT_BIND: default 127.0.0.1:7000
- KAKACHI_DATA_DIR: default ./.kakachi
- KAKACHI_DB_PATH: default <KAKACHI_DATA_DIR>/agent.db

See server/api/.env.example for API env template.

## Build, Lint, Test

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Run Control Plane

```bash
export KAKACHI_JWT_SECRET="replace-with-a-long-random-secret-at-least-32-characters"
cargo run -p kakachi-api
```

Health check:

```bash
curl http://127.0.0.1:8080/healthz
```

## Run Agent Daemon

```bash
cargo run -p kakachi-agent --bin agentd
```

## Implemented API Endpoints (Phase 1)

- POST /v1/auth/register
- POST /v1/auth/login
- POST /v1/networks
- GET /v1/networks/{network_id}
- POST /v1/networks/{network_id}/join
- GET /v1/networks/{network_id}/peers
- GET /v1/ws?token=<jwt>&network_id=<uuid>

## Current Risks And Gaps

- API currently runs over HTTP locally; TLS termination and cert management still required for deployment.
- Coordination state is in-memory and not yet persistent.
- NAT traversal and relay transport are modeled but not fully wired into live packet flow.
- Desktop UI is not started yet (planned for Tauri + React in Phase 3).

## Next Slice

- Add persistent server-side storage (accounts, networks, membership).
- Introduce DTLS/QUIC or UDP session manager for direct peer session establishment.
- Implement deterministic relay path for VPN packets and chat payload transport.
