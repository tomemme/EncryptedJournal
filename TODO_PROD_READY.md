# Production Hardening TODO

## 1) Automated Tests In CI
- Add GitHub Actions to run `py_compile` and smoke tests on Linux.
- Run smoke tests under `xvfb-run` for Tkinter UI.
- Add unit tests for crypto helpers and JSON load/save edge cases.

## 2) Backup Retention + Restore
- Keep only the last N backups (for example 10).
- Prune older `journal.json.gz.bak-*` files automatically.
- Add a restore-from-backup flow in the UI.

## 3) Logging And Error Handling
- Replace `print(...)` with structured logging.
- Write logs to rotating files.
- Keep popup messages concise and log detailed traces separately.

## 4) Strict Data Validation
- Validate journal schema on load (`date`, `entry`).
- Skip invalid records with warnings.
- Avoid failing entire file due to one bad entry.

## 5) Session Lock Features
- Add optional inactivity auto-lock.
- Add optional password cache duration setting.
- Add a manual `Lock now` action.

## 6) Secure Storage Options
- Add optional Linux keyring integration.
- Move default storage to XDG paths (`~/.local/share/...`).
- Keep existing path configurable for compatibility.

## 7) Packaging + Distribution
- Add AppImage or distro package metadata.
- Add `.desktop` launcher and icon install support.
- Document clean launch commands for Omarchy users.

## 8) Accessibility + UX
- Add keyboard shortcuts (Save/Load/Delete/Help).
- Improve focus traversal and focus visibility.
- Link help overlay to backup/restore guidance.

## 9) Security Documentation
- Add `SECURITY.md` with threat model and limitations.
- Document recovery constraints (lost password is unrecoverable).
- Add vulnerability reporting instructions.

## 10) Performance + Scale
- Test with large journal datasets.
- Profile tree rendering and load times.
- Add lazy loading for tree groups if needed.
