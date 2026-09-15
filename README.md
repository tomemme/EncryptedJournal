# Encrypted Journal
A cross-platform encrypted journal application built with Python and the `cryptography` library, with two frontends sharing the same core logic (`journal_core.py`) and journal file format: a [Textual](https://textual.textualize.io/) terminal UI (`journal_tui.py`) — great as a lightweight command center over SSH/Tailscale — and a Tkinter desktop GUI (`secure_journal.py`) for local use. Securely write, save, load, and delete journal entries with AES-GCM encryption, with session auto-lock for added security. Entries are stored in a compressed JSON file (`journal.json.gz`) that works seamlessly across Windows, macOS, and Linux.

# Features
- **Secure Encryption**: Entries are encrypted using AES-GCM with keys derived via Scrypt from your password, using cryptographically secure salts and nonces.
- **Save and Load Entries**: Encrypt and save entries to `journal.json.gz`, and decrypt them by date using a Tree-based navigation view grouped by year-month.
- **Delete Entries**: Remove specific entries with a Yes/No confirmation.
- **Overwrite Guard**: creating/saving an entry for a date that already has one (e.g. pressing `n` in the TUI, or saving a blank editor in the GUI without explicitly loading first) opens the existing entry for editing instead of silently overwriting it — clear it (`ctrl+r` in the TUI, the Clear button in the GUI) if you want to start blank.
- **Session Security**: Inactivity auto-lock (`ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS`, default 5 minutes, TUI only) plus a manual lock-now key, with secure password cleanup from memory.
- **Backups + Restore** (both frontends, via Settings): timestamped backups (`journal.json.gz.bak-<timestamp>`) are created automatically before a password rotation or restore, and on demand; the newest 10 are kept. Restore safety-backs-up the current journal first, then loads the backup you pick. The GUI picks a file via a native dialog; the TUI's restore screen (`s`) also accepts any path typed/pasted in — not just backups already sitting beside the journal file — so a backup living anywhere on disk can be restored directly with no manual copying first.
- **Password Rotation** (GUI, via Settings): re-encrypts every entry under a new password, aborting without writing anything if more than 10% of entries fail to re-encrypt.
- **Rotating-File Logging**: both frontends log to `<journal directory>/encrypted-journal.log` (512KB, 5 backups kept), overridable via `ENCRYPTED_JOURNAL_LOG_FILE`/`ENCRYPTED_JOURNAL_LOG_LEVEL`.
- **Cross-Platform**: Works on Windows, macOS, and Linux with consistent file handling and permissions.
- **Days Since Last Entry**: Displays the time since your last journal entry.
- **Omarchy Theming**: On Omarchy, both frontends automatically match your current desktop theme's colors (both poll every ~1s for live updates). Falls back to each frontend's own default theme when Omarchy isn't present.

The TUI does not yet have its own screen for password rotation — that logic lives in `journal_core.py` today for the GUI to use, ready for the TUI to build on next (see `TODO_PROD_READY.md`).

# Requirements
- Python 3.11+
- Dependencies:
  - `textual` (terminal UI)
  - `cryptography` (for encryption/decryption)
  - `tk`/Tkinter (desktop GUI; a system package, not pip-installable — e.g. `python3-tk` on Debian/Ubuntu, `tk` on Arch)
  - `pyenchant` (optional, GUI spell-check; needs a system `enchant` library, e.g. `libenchant-2-2`/`hunspell-en-us` on Debian/Ubuntu)
  - `keyring` (optional, for saved passwords via system keyring)
  - `pywin32` (optional, for Windows file permissions)

# Installation
```bash
git clone <repo-url> encrypted-journal
cd encrypted-journal
pip install -r requirements.txt
python journal_tui.py       # terminal UI
python secure_journal.py    # desktop GUI
```

# Example JSON File Structure
[
    {"date": "2025-02-20", "entry": "base64_encoded_encrypted_data"},
    {"date": "2025-02-21", "entry": "another_base64_encoded_encrypted_data"}
]

# Usage
## TUI (`journal_tui.py`) key bindings
- `n` — new entry
- `v` / `enter` — view/edit the selected entry
- `d` — delete the selected entry (with a Yes/No confirmation)
- `s` — open Settings (create a backup, or restore from one)
- `l` — lock now (clears the in-memory password, returns to the unlock screen)
- `q` — quit
- `ctrl+s` — save an entry
- `ctrl+r` — clear the entry body (e.g. after the overwrite guard opens an existing entry you didn't mean to edit)
- `escape` — cancel/discard and return to the entry list

Session lock: `ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS` (default `300`, i.e. 5 minutes) sets an inactivity auto-lock. After that many seconds without a tracked action, the in-memory password is cleared; the next action that needs decryption re-prompts for the password in place, without discarding unsaved edits. The `l` key triggers the same lock manually, independent of the timer.

Settings (`s`): create a backup of the current journal on demand, or restore one — either by picking from the list of backups already sitting beside the journal file, or by typing/pasting the path to a backup located anywhere else on disk. Restoring safety-backs-up the current journal first (same as the GUI); if that safety backup itself fails, you're asked to confirm before restoring anyway.

## GUI (`secure_journal.py`) key bindings
- `ctrl/cmd+s` — save, `ctrl/cmd+l` — load selected entry, `ctrl/cmd+d` — delete selected entry, `ctrl/cmd+h` — help
- **Settings** dialog: create a backup now, restore from a backup, or rotate the journal password.

# Smoke Test
Run the local smoke tests to verify core journal flows end-to-end:

```bash
python scripts/core_smoke_test.py         # journal_core.py logic, headless
python scripts/tui_smoke_test.py          # journal_tui.py, headless (Textual's own test harness)
python scripts/omarchy_theme_smoke_test.py  # Omarchy theme parsing, headless
python scripts/smoke_test.py              # secure_journal.py, needs a display (or Xvfb)
```

# Storage + Keyring Options
Default journal location now follows XDG conventions:
- `~/.local/share/encrypted-journal/journal.json.gz` (or `$XDG_DATA_HOME/encrypted-journal/journal.json.gz`)

Compatibility behavior:
- If a legacy `journal.json.gz` exists in the app directory, it is still used automatically.

Environment overrides:
- `ENCRYPTED_JOURNAL_FILE=/custom/path/journal.json.gz` to force a specific file location.
- `ENCRYPTED_JOURNAL_USE_KEYRING=1` to enable optional system keyring integration for remembered passwords.
- `ENCRYPTED_JOURNAL_KEYRING_USER=<name>` to customize the keyring account key.
- `ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH=/custom/path/colors.toml` to override where the Omarchy theme colors are read from (default: `~/.local/state/omarchy/current/theme/colors.toml`).
- `ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH=/custom/path/theme.name` to override where the Omarchy theme name is read from (default: `~/.local/state/omarchy/current/theme.name`).
- `ENCRYPTED_JOURNAL_LOG_FILE=/custom/path/app.log` to override the rotating log file location (default: `encrypted-journal.log` beside the journal file).
- `ENCRYPTED_JOURNAL_LOG_LEVEL=DEBUG` to change the log level (default: `INFO`).

Note: `pyenchant` (GUI spellcheck) is declared in `requirements.txt` with the *import* itself still guarded (`try`/`except ImportError`) inside `secure_journal.py` — unlike `keyring`/`pywin32`, which are guarded-only and not declared at all. This matches how the GUI's own upstream project treats it, since `pyenchant` needs a system `enchant` library that isn't available everywhere.

# Arch / Omarchy Packaging
This repo includes Arch packaging files at `packaging/arch/` so the app can be published to AUR and discovered from Omarchy package search tools.

## Build Locally (Arch)
```bash
cd packaging/arch
makepkg -si
```

## Publish To AUR
1. Create an AUR package repo named `encrypted-journal-git`.
2. Copy `PKGBUILD`, `.SRCINFO`, `encrypted-journal.desktop`, `encrypted-journal-launcher`, and `encrypted-journal-tui-launcher` from `packaging/arch/`.
3. Commit and push to the AUR repo.
4. After AUR indexing, users can search/install it from Omarchy package installer UIs.

# Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Creating a Pull Request
If you are new to GitHub pull requests, follow these steps to share your changes and test them before merging:

1. **Create a new branch** for your change so the `main` (or `omarchy`) branch stays clean:
   ```bash
   git checkout -b feature/refresh-theme
   ```
2. **Stage and commit your work** once it is ready:
   ```bash
   git add journal_tui.py
   git commit -m "Describe your change"
   ```
3. **Push the branch to GitHub**:
   ```bash
   git push -u origin feature/refresh-theme
   ```
4. **Open a pull request** on GitHub by selecting your branch as the source and the `omarchy` branch (or another target) as the destination. Describe the change, include testing notes, and submit the PR.
5. **Test the PR locally** by checking out the branch from GitHub (`git fetch origin pull/<id>/head:pr-test && git checkout pr-test`). This lets you verify the changes before approving and merging them into the `omarchy` branch.
6. **Merge the PR** once testing looks good. GitHub will offer a merge button (e.g., “Merge pull request”) after approvals and status checks pass. Choose the merge strategy that fits your workflow.

These steps create a temporary review branch that teammates can pull down to try out the update (such as the automatic Omarchy theme refresh) before the code lands in the shared `omarchy` branch.

# License
This project is licensed under the MIT License. See the LICENSE file for more details.


