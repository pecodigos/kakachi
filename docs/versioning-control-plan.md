# Kakachi Versioning And Source Control Plan

## Repository Policy

- Keep `.github/` tracked. It contains agent, prompt, and instruction configuration that must stay versioned.
- Keep `main` as the stable branch.
- Commit every logical update as a separate commit with clear scope.

## Branching Model

- `main`: production-ready integration branch.
- `feature/<scope>`: normal implementation work.
- `hotfix/<scope>`: urgent fixes.

For solo flow, direct commits to `main` are acceptable if all quality gates pass.

## Commit Convention

Use Conventional Commits:

- `feat:` new functionality
- `fix:` bug fix
- `refactor:` internal structure changes without behavior change
- `docs:` documentation changes
- `chore:` tooling and maintenance
- `test:` test additions or updates

Examples:

- `feat(coordination): add network membership APIs`
- `fix(agent): validate control-plane endpoint scheme`
- `docs(release): add versioning checklist`

## Versioning Scheme

Use Semantic Versioning with pre-1.0 discipline:

- `0.x.y` while APIs are evolving quickly.
- Bump `x` for breaking changes.
- Bump `y` for backward-compatible fixes and features (grouped as needed).

After stabilization, move to `1.0.0` and standard SemVer:

- `MAJOR` for breaking changes
- `MINOR` for backward-compatible features
- `PATCH` for backward-compatible fixes

## Release Process

1. Ensure `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` all pass.
2. Update changelog/release notes for user-visible changes and security impact.
3. Tag release with annotated tag, for example `v0.2.0`:
   `git tag -a v0.2.0 -m "Kakachi v0.2.0"`
4. Push branch and tags:
   `git push origin main --follow-tags`

## Security And Auditability

- Never commit secrets, private keys, runtime databases, or `.env` files.
- Keep security-relevant changes in focused commits with clear messages.
- Prefer signed commits and signed tags for release points.

## Operational Rule

After each meaningful update in this repository:

- run quality gates,
- commit with a clear message,
- push to `origin/main`.
