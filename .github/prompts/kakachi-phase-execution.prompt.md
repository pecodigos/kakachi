---
name: create-kakachi-phase-slice
description: "Plan and execute one Kakachi phase slice with production security constraints, runnable deliverables, and validation commands."
argument-hint: "Phase number, target modules, acceptance criteria, and platform focus (Linux, Windows, or both)."
agent: Kakachi Rust VPN Engineer
---
Build exactly one implementation slice for Kakachi from the user input.

Treat this as production software for real friend-to-friend usage.

## Inputs To Extract
- Phase and scope boundary.
- Target crates and modules.
- Required behavior and acceptance criteria.
- Platform scope: Linux, Windows, or both.
- Explicit constraints and non-goals.

If critical inputs are missing, ask at most 3 concise clarifying questions before implementation.

## Mandatory Constraints
- Use WireGuard for encrypted tunnels; no custom cryptography.
- Keep end-to-end encryption and key-based authentication explicit.
- Assume hostile networks; validate untrusted input and fail safely.
- Keep UI and networking core separated via local IPC.
- Relay fallback must preserve E2E guarantees.

## Execution Workflow
1. Restate the chosen phase slice with explicit acceptance criteria.
2. Propose the smallest robust design and justify tradeoffs.
3. Implement code changes in the selected crates and modules.
4. Add or update tests for modified behavior.
5. Run formatting, linting, and tests for changed crates.
6. Provide Linux and Windows run/setup steps for the delivered slice.

## Required Output Format
Return sections in this order:

1. Implemented
- What was implemented.
- Why this design was chosen.

2. Files And Interfaces
- Files changed.
- Key interfaces, structs, APIs, and protocol messages added or modified.

3. Security Review
- Security implications.
- Mitigations applied.
- Remaining security risks.

4. Run And Validate
- Exact commands to build, run, and test.
- Any environment prerequisites.

5. Remaining Risks And Next Iteration
- Operational and correctness risks.
- Concrete next steps for the following slice.

## Tradeoff Rule
When major tradeoffs exist (for example UDP vs QUIC, relay design, chat channel design), provide options considered and justify the selected production-ready option.
