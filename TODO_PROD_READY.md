# Production Hardening TODO

Legend:
- `[x]` done
- `[~]` partially done
- `[ ]` remaining

## 1) Automated Tests In CI
- [ ] Add GitHub Actions to run `py_compile` and smoke tests on Linux.
- [ ] Run smoke tests under `xvfb-run` for Tkinter UI.
- [~] Add unit/smoke coverage for core flows (local smoke script exists; broader tests pending).

## 2) Backup Retention + Restore
- [x] Keep only the last 10 backups.
- [x] Prune older `journal.json.gz.bak-*` files automatically.
- [ ] Add a restore-from-backup flow in the UI.

## 3) Logging And Error Handling
- [ ] Replace `print(...)` with structured logging.
- [ ] Write logs to rotating files.
- [ ] Keep popup messages concise and log detailed traces separately.

## 4) Strict Data Validation
- [ ] Validate journal schema on load (`date`, `entry`).
- [ ] Skip invalid records with warnings.
- [ ] Avoid failing entire file due to one bad entry.

## 5) Session Lock Features
- [ ] Add optional inactivity auto-lock.
- [ ] Add optional password cache duration setting.
- [ ] Add a manual `Lock now` action.

## 6) Secure Storage Options
- [x] Add optional Linux keyring integration.
- [x] Move default storage to XDG paths (`~/.local/share/...`).
- [x] Keep existing path configurable for compatibility.

## 7) Packaging + Distribution
- [ ] Add AppImage or distro package metadata.
- [x] Add `.desktop` launcher and icon install support.
- [x] Document clean launch commands for Omarchy/Arch users.

## 8) Accessibility + UX
- [ ] Add keyboard shortcuts (Save/Load/Delete/Help).
- [ ] Improve focus traversal and focus visibility.
- [ ] Link help overlay to backup/restore guidance.

## 9) Security Documentation
- [ ] Add `SECURITY.md` with threat model and limitations.
- [ ] Document recovery constraints (lost password is unrecoverable).
- [ ] Add vulnerability reporting instructions.

## 10) Performance + Scale
- [ ] Test with large journal datasets.
- [ ] Profile tree rendering and load times.
- [ ] Add lazy loading for tree groups if needed.
