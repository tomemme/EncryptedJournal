# Merge Policy

## Branch Roles
- `main`: Cross-platform baseline (Windows, macOS, Linux).
- `omarchy-version`: Linux/Omarchy-focused UX, packaging, and platform behavior.

## What To Merge Into `main`
- Security fixes (encryption, password handling, data safety).
- Data integrity fixes (atomic writes, corruption handling).
- Cross-platform bug fixes that do not assume Linux-only paths or tooling.
- Test and CI improvements that work across platforms.

## What Stays In `omarchy-version`
- Omarchy-specific UX/layout/theming behavior.
- Linux-first storage defaults (XDG) when they diverge from cross-platform defaults.
- Optional Linux keyring UX decisions.
- Arch/AUR packaging files and Omarchy installer integration.

## Safe Promotion Workflow (`omarchy-version` -> `main`)
1. Identify commits that are platform-neutral.
2. Cherry-pick only those commits onto a `main` feature branch.
3. Run cross-platform sanity checks.
4. Open PR into `main` with explicit "cross-platform safe" notes.

## Development Defaults
- New Linux/Omarchy features start in `omarchy-version`.
- New security/data-integrity fixes should be evaluated for both branches.
- If uncertain, default to `omarchy-version` first, then promote selectively.
