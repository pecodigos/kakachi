---
name: Kakachi Rust Quality Gates
description: "Use when implementing Rust code for Kakachi networking, WireGuard integration, NAT traversal, relay logic, and control-plane APIs. Enforces security and validation gates before completion."
applyTo: ["**/*.rs", "**/Cargo.toml"]
---
# Kakachi Rust Quality Gates

## Security Baseline
- Do not implement custom cryptography.
- Use WireGuard for tunnel encryption and key-based authentication.
- Keep relay paths end-to-end encrypted.
- Treat all network input as untrusted; validate early and fail safely.
- Minimize unsafe Rust. Any unsafe block must include a short safety rationale.

## Architecture Boundaries
- Keep desktop UI and networking core separated via local IPC.
- Preserve modular crate boundaries for core/agent, core/net, core/wg, core/chat, and server modules.
- Keep server zero-trust for payload confidentiality.

## Reliability Requirements
- Add structured logging for connection lifecycle, retries, and failures.
- Include bounded retry with backoff for reconnect paths.
- Ensure deterministic fallback to relay when direct P2P fails.
- Avoid panics in long-running services; return typed errors with context.

## Validation Checklist
- Run formatting: cargo fmt --all
- Run linting: cargo clippy --workspace --all-targets -- -D warnings
- Run tests: cargo test --workspace
- If dependency changes were made and cargo-audit is available: cargo audit

## Delivery Format
When returning results, include:
- What changed and why.
- Security implications and mitigations.
- Exact run and test commands.
- Remaining risks and the next iteration step.