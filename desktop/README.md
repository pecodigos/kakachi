# Kakachi Desktop (Tauri + React)

This desktop app is now implemented as a Tauri shell with a React UI and a Rust IPC bridge.

Current responsibilities:

- Minimal login-first flow with optional saved login on the same device
- Create account screen (username, email, password, confirm password)
- Network creation, join, and peer listing
- Guided friend connect flow for LAN-style use and remote VPN-style use
- One-click `Quick connect` that auto-discovers online peers and picks the safest available path
- Live STUN-backed negotiation trigger via local agent service, including UDP hole-punch hello/ack telemetry

## Architecture Boundary

The React UI never calls the control plane directly. It uses Tauri IPC commands, and the Rust desktop backend performs all network actions.

## Linux Prerequisites

Install Tauri runtime requirements plus Node:

```bash
sudo apt update
sudo apt install -y \
	pkg-config libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev \
	libwebkit2gtk-4.1-dev build-essential curl
```

Install Node.js 20+ if not already present.

## Install Desktop Dependencies

From repository root:

```bash
cd desktop
npm install
```

## Run For Front-End Testing

1. Start control-plane API in one terminal:

```bash
cd /mnt/hdd/Code/rust
cargo run -p kakachi-api
```

Environment is loaded from root `.env` automatically.
Template: `env.example`.

2. Start desktop app in another terminal:

```bash
cd /mnt/hdd/Code/rust/desktop
npm run tauri dev
```

3. In the desktop UI, execute this flow:

1. Sign in on first screen.
2. Optional: use `Save login on this device` for next app launch.
3. If needed, click `Create account` and fill username, email, password, confirm password.
4. After login, create a network or join with invite code.
5. Choose LAN game/app or Remote VPN mode.
6. Press `Quick connect`.

Manual friend selection is available under `Manual friend selection`.

Advanced settings are available under `Advanced connection settings`, but normal users can ignore them.

## Optional Environment Variables

- `KAKACHI_DESKTOP_DATA_DIR`: local desktop agent state directory (default `./.kakachi/desktop`)

## Front-End Build Check

```bash
cd /mnt/hdd/Code/rust/desktop
npm run build
```
