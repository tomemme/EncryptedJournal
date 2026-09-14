# Production Hardening TODO

Legend:
- `[x]` done
- `[~]` partially done
- `[ ]` remaining

## 1) Automated Tests In CI
- [x] Add GitHub Actions to run `py_compile` and smoke tests on Linux.
- [x] Run core + TUI smoke tests headless, plus the GUI's Xvfb-based smoke test (`scripts/smoke_test.py`) now that the Tkinter GUI (`secure_journal.py`) is back alongside the TUI, both sharing `journal_core.py`.
- [~] Add unit/smoke coverage for core flows (local smoke scripts exist; broader tests pending).

## 2) Backup Retention + Restore
- [x] Keep only the last 10 backups (`journal_core.create_journal_backup`, shared).
- [x] Prune older `journal.json.gz.bak-*` files automatically.
- [x] Add a restore-from-backup flow in the GUI (Settings dialog). Not yet exposed in the TUI - the underlying `journal_core` logic is ready for it.

## 3) Logging And Error Handling
- [x] Replace `print(...)` with structured logging.
- [x] Write logs to rotating files (`journal_core.configure_rotating_logger`, shared by both frontends).
- [x] Keep popup messages concise and log detailed traces separately.

## 4) Strict Data Validation
- [x] Validate journal schema on load (`date`, `entry`).
- [x] Skip invalid records with warnings.
- [x] Avoid failing entire file due to one bad entry.

## 5) Session Lock Features
- [x] Add optional inactivity auto-lock.
- [~] Add optional password cache duration setting.
- [x] Add a manual `Lock now` action.

Note: the Textual TUI (`journal_tui.py`) implements inactivity auto-lock
(`ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS`, default 300s) and a manual `l` lock-now action.
The Tkinter GUI (`secure_journal.py`) has its own independent 5-failed-attempt lockout
(`self.max_attempts`) restored alongside it - the two aren't unified onto one shared
mechanism yet (possible future cleanup). The "password cache duration" item is `[~]`
rather than `[x]` because that env var is a global default, not a live in-app
per-session setting.

## v1 — Explicitly Deferred
Deferred scope from the original TUI effort (see `docs/TUI_PLAN.md` "Explicitly out of
scope this round"). The Tkinter GUI (`secure_journal.py`) is back in this repo alongside
the TUI, sharing `journal_core.py`, so most of this is now done for the GUI - the TUI
itself doesn't have its own screens for these yet.
- [x] Add password rotation (GUI, via Settings; shared logic in `journal_core.rotate_journal_password`). No TUI screen yet.
- [x] Add spellcheck (GUI only, via `pyenchant`; not applicable to a terminal UI).
- [x] Add Omarchy `colors.toml` theme integration (both frontends, via shared `journal_core` Omarchy-reading functions).
- [ ] Add `omarchy-tui-install` / a TUI-specific `.desktop` launcher. A second launcher command (`encrypted-journal-tui`) was added to the Arch package, but no dedicated install script or `.desktop` entry - the TUI is meant for terminal/SSH use, not an app-menu target.

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
