# Kakachi

Kakachi is a production-oriented Hamachi-like VPN system in Rust for real-world friend-to-friend use.

This repository now contains the Phase 1 foundation:

- Control plane server (HTTPS/WebSocket-ready API skeleton)
- Core agent daemon crate with local SQLite state
- Core networking, WireGuard, and chat domain crates
- Desktop app (Tauri + React) with IPC bridge to control-plane and local agent services
- Security-first defaults (input validation, key validation, no custom cryptography)

## Workspace Layout

- core/agent: local daemon, SQLite storage, WireGuard command plan staging
- core/net: virtual network and NAT traversal models
- core/wg: WireGuard key management and backend command plans
- core/chat: encrypted payload envelope model and transport metadata
- server/coordination: auth and room membership coordination logic
- server/api: Axum HTTP/WebSocket control-plane API
- desktop: Tauri + React desktop UI and IPC backend

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
- KAKACHI_COORDINATION_DB: optional, default ./.kakachi/control-plane.db

Agent daemon:

- KAKACHI_CONTROL_PLANE_URL: default http://127.0.0.1:8080
- KAKACHI_AGENT_BIND: default 127.0.0.1:7000
- KAKACHI_DATA_DIR: default ./.kakachi
- KAKACHI_DB_PATH: default <KAKACHI_DATA_DIR>/agent.db

See server/api/.env.example for API env template.

For simpler local runs without shell exports, use a root `.env` file.
Template: `env.example`.

## Build, Lint, Test

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Run Control Plane

```bash
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

## Run Desktop App

```bash
cd desktop
npm install
npm run tauri dev
```

Desktop setup and flow details: [desktop/README.md](desktop/README.md)

### Run One-Shot Session Negotiation

Set these variables to execute a single live STUN + session report run:

- KAKACHI_AGENT_NEGOTIATE_NETWORK_ID: target network UUID
- KAKACHI_AGENT_NEGOTIATE_PEER: peer username
- KAKACHI_AGENT_AUTH_TOKEN: JWT from /v1/auth/login
- KAKACHI_AGENT_STUN_SERVERS: comma-separated STUN IP:port list (example: 74.125.250.129:19302)
- KAKACHI_AGENT_NEGOTIATE_SESSION_ID: optional existing session UUID to report into

Example:

```bash
export KAKACHI_CONTROL_PLANE_URL="http://127.0.0.1:8080"
export KAKACHI_AGENT_BIND="0.0.0.0:7000"
export KAKACHI_AGENT_NEGOTIATE_NETWORK_ID="<network-id>"
export KAKACHI_AGENT_NEGOTIATE_PEER="bob"
export KAKACHI_AGENT_AUTH_TOKEN="<jwt-token>"
export KAKACHI_AGENT_STUN_SERVERS="74.125.250.129:19302"
cargo run -p kakachi-agent --bin agentd
```

## Implemented API Endpoints (Phase 1)

- POST /v1/auth/register
- POST /v1/auth/login
- POST /v1/networks
- GET /v1/networks/{network_id}
- POST /v1/networks/{network_id}/join
- GET /v1/networks/{network_id}/peers
- POST /v1/networks/{network_id}/endpoint-candidates
- GET /v1/networks/{network_id}/endpoint-candidates
- POST /v1/networks/{network_id}/sessions
- GET /v1/networks/{network_id}/sessions/{session_id}
- POST /v1/networks/{network_id}/sessions/{session_id}/report
- GET /v1/ws?token=<jwt>&network_id=<uuid>

## Quick Local Self-Test (Two Peer Accounts)

1. Start the control plane:

```bash
cargo run -p kakachi-api
```

2. Register two users (alice and bob) with WireGuard public keys:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/auth/register -H 'content-type: application/json' -d '{"username":"alice","password":"very-strong-password-123","public_key":"<alice-public-key>"}'
curl -sS -X POST http://127.0.0.1:8080/v1/auth/register -H 'content-type: application/json' -d '{"username":"bob","password":"very-strong-password-456","public_key":"<bob-public-key>"}'
```

3. Login both users and capture each `access_token` from response JSON.

4. Create a network as alice, then join it as bob:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/networks -H "authorization: Bearer <alice-token>" -H 'content-type: application/json' -d '{"name":"friends-net"}'
curl -sS -X POST http://127.0.0.1:8080/v1/networks/<network-id>/join -H "authorization: Bearer <bob-token>"
```

5. Run alice one-shot negotiation and copy the emitted `session_id` from agent logs.

6. Run bob one-shot negotiation with the same network and set `KAKACHI_AGENT_NEGOTIATE_SESSION_ID=<alice-session-id>` so both peers report into one session.

7. Fetch final session state:

```bash
curl -sS http://127.0.0.1:8080/v1/networks/<network-id>/sessions/<session-id> -H "authorization: Bearer <alice-token>"
```

## Current Risks And Gaps

- API currently runs over HTTP locally; TLS termination and cert management still required for deployment.
- Coordination persistence currently uses a single-node SQLite file without schema migrations yet.
- Session negotiation state now decides direct-vs-relay deterministically, but live UDP hole-punch execution is not wired yet.
- Agent negotiation now performs live STUN transactions plus UDP hello/ack hole-punch attempts with telemetry, but sustained tunnel health checks are not wired yet.
- Relay packet forwarding is still pending; current relay requirement is signaling only.
- Desktop app now supports auth, network, peer, and session negotiation workflows through Tauri IPC, but chat and tunnel lifecycle UX are still pending.

## Next Slice

- Add migration/versioning flow for coordination schema and backup/restore tooling.
- Add connect-time health checks and retry strategy tuning for direct UDP punch sessions.
- Implement deterministic relay path for VPN packets and chat payload transport.
- Expand desktop UI to include connection telemetry, chat transport, and tunnel lifecycle controls.

## Project Governance

- Versioning and source-control workflow: [docs/versioning-control-plan.md](docs/versioning-control-plan.md)
