# Production Hardening TODO

Legend:
- `[x]` done
- `[~]` partially done
- `[ ]` remaining

## 1) Automated Tests In CI
- [x] Add GitHub Actions to run `py_compile` and smoke tests on Linux.
- [x] Run smoke tests under `xvfb-run` for Tkinter UI.
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
- [ ] Add optional inactivity auto-lock.
- [ ] Add optional password cache duration setting.
- [ ] Add a manual `Lock now` action.

Note: the Textual TUI (`journal_tui.py`, TUI_PLAN Tasks 5 & 8) now has both inactivity
auto-lock (`ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS`, default 300s) and a manual `l` lock-now
action. The Tkinter GUI (`secure_journal.py`) still does not implement either, so the
`[ ]` items above remain accurate for the GUI.

## TUI (v1) — Explicitly Deferred
Deferred scope from the TUI effort (see `docs/TUI_PLAN.md` "Explicitly out of scope this
round"); none of this applies to the GUI, which is unaffected by the TUI plan.
- [ ] Add password rotation to the TUI.
- [ ] Add spellcheck to the TUI.
- [ ] Add Omarchy `colors.toml` theme integration for the TUI.
- [ ] Add `omarchy-tui-install` / `.desktop` launcher packaging for the TUI.

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
