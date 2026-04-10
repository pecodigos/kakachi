# Kakachi Desktop (Tauri + React)

This desktop app is now implemented as a Tauri shell with a React UI and a Rust IPC bridge.

Current responsibilities:

- Control-plane health check
- WireGuard key generation
- User register and login
- Network creation, join, and peer listing
- Session open/get
- Live STUN-backed session negotiation trigger via local agent service

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
export KAKACHI_JWT_SECRET="replace-with-a-long-random-secret-at-least-32-characters"
cargo run -p kakachi-api
```

2. Start desktop app in another terminal:

```bash
cd /mnt/hdd/Code/rust/desktop
npm run tauri dev
```

3. In the desktop UI, execute this flow:

- Check API health
- Generate WireGuard keypair
- Register user
- Login user
- Create or join network
- List peers
- Open session and run live negotiation

## Optional Environment Variables

- `KAKACHI_DESKTOP_DATA_DIR`: local desktop agent state directory (default `./.kakachi/desktop`)

## Front-End Build Check

```bash
cd /mnt/hdd/Code/rust/desktop
npm run build
```
