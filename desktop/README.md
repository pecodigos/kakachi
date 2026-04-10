# Kakachi Desktop (Tauri + React)

This desktop app is now implemented as a Tauri shell with a React UI and a Rust IPC bridge.

Current responsibilities:

- Minimal login-first flow with optional saved login on the same device
- Saved login is stored through desktop secure storage (OS keyring via Tauri backend)
- Create account screen (username, email, password, confirm password)
- Network creation and join
- Local IPv4 and IPv6 display for this device
- Power toggle (`On`/`Off`) for connection lifecycle
- Server list as the primary surface (Hamachi-style)
- Member list for selected server with online/offline status

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
5. Use the power button (`On`/`Off`) to enable or pause connectivity.
6. Select a server from the server list.
7. View members and their online/offline state.

## Optional Environment Variables

- `KAKACHI_DESKTOP_DATA_DIR`: local desktop agent state directory (default `./.kakachi/desktop`)

## Front-End Build Check

```bash
cd /mnt/hdd/Code/rust/desktop
npm run build
```
