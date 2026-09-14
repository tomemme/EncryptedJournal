# Production Hardening TODO

Legend:
- `[x]` done
- `[~]` partially done
- `[ ]` remaining

## 1) Automated Tests In CI
- [x] Add GitHub Actions to run `py_compile` and smoke tests on Linux.
- [x] Run core + TUI smoke tests headless (the Tkinter GUI and its Xvfb-based smoke test were removed; this project is now TUI-only).
- [~] Add unit/smoke coverage for core flows (local smoke script exists; broader tests pending).

## 2) Backup Retention + Restore
- [x] Keep only the last 10 backups.
- [x] Prune older `journal.json.gz.bak-*` files automatically.
- [x] Add a restore-from-backup flow in the UI.

## 3) Logging And Error Handling
- [x] Replace `print(...)` with structured logging.
- [x] Write logs to rotating files.
- [x] Keep popup messages concise and log detailed traces separately.

## 4) Strict Data Validation
- [x] Validate journal schema on load (`date`, `entry`).
- [x] Skip invalid records with warnings.
- [x] Avoid failing entire file due to one bad entry.

## 5) Session Lock Features
- [x] Add optional inactivity auto-lock.
- [~] Add optional password cache duration setting.
- [x] Add a manual `Lock now` action.

Note: the Tkinter GUI (`secure_journal.py`) has been removed; the Textual TUI
(`journal_tui.py`) is now the only frontend. It implements inactivity auto-lock
(`ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS`, default 300s) and a manual `l` lock-now action.
The "password cache duration" item is `[~]` rather than `[x]` because that env var is a
global default, not a live in-app per-session setting.

## v1 — Explicitly Deferred
Deferred scope from the original TUI effort (see `docs/TUI_PLAN.md` "Explicitly out of
scope this round"), still deferred now that the Tkinter GUI has been removed and this
project is TUI-only.
- [ ] Add password rotation.
- [ ] Add spellcheck.
- [ ] Add Omarchy `colors.toml` theme integration.
- [ ] Add `omarchy-tui-install` / `.desktop` launcher packaging.

## 6) Secure Storage Options
- [x] Add optional Linux keyring integration.
- [x] Move default storage to XDG paths (`~/.local/share/...`).
- [x] Keep existing path configurable for compatibility.
- [ ] Improve password-manager interoperability (test and document expected behavior with desktop managers such as 1Password via system keyring/clipboard/autofill workflows).

## 7) Packaging + Distribution
- [x] Add distro package metadata for desktop/app-menu integration.
- [x] Add `.desktop` launcher and icon install support.
- [x] Document clean launch commands for Omarchy/Arch users.
- [ ] Add AppStream/metainfo metadata for richer software-center integration.

## 8) Accessibility + UX
- [x] Add keyboard shortcuts (Save/Load/Delete/Help).
- [ ] Improve focus traversal and focus visibility.
- [ ] Polish shortcut-driven tree selection flow (for example, focus the entry list before prompting for a password when `Load` is triggered without a selected entry).
- [ ] Link help overlay to backup/restore guidance.

## 9) Security Documentation
- [x] Add `SECURITY.md` with threat model and limitations.
- [x] Document recovery constraints (lost password is unrecoverable).
- [x] Add vulnerability reporting instructions.

## 10) Performance + Scale
- [ ] Test with large journal datasets.
- [ ] Profile tree rendering and load times.
- [ ] Add lazy loading for tree groups if needed.
