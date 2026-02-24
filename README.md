# Encrypted Journal
A cross-platform encrypted journal application built with Python, Tkinter, and the `cryptography` library. Securely write, save, load, and delete journal entries with AES-GCM encryption, featuring a modern GUI, spell checking, and session timeout for added security. Entries are stored in a compressed JSON file (`journal.json.gz`) that works seamlessly across Windows, macOS, and Linux.

# Features
- **Secure Encryption**: Entries are encrypted using AES-GCM with keys derived via Scrypt from your password, using cryptographically secure salts and nonces.
- **Save and Load Entries**: Encrypt and save entries to `journal.json.gz`, and decrypt them by date using a treeview interface.
- **Delete Entries**: Remove specific entries with confirmation prompts.
- **Spell Checking**: Real-time spell checking with right-click suggestions (powered by `pyenchant`).
- **Session Security**: 5-minute session timeout requires re-entering your password, with secure password cleanup from memory.
- **Cross-Platform**: Works on Windows, macOS, and Linux with consistent file handling and permissions.
- **Theming**: Toggle between light and dark themes using the `azure.tcl` theme file.
- **Days Since Last Entry**: Displays the time since your last journal entry.
- **Clear Entry**: Reset the text and date fields with a single click.

# Requirements
- Python 3.6+
- Dependencies:
  - `cryptography` (for encryption/decryption)
  - `pyenchant` (for spell checking)
  - `pywin32` (optional, for Windows file permissions)

# Installation
1. Clone the Repository
    cd encrypted-journal

![GUI](https://github.com/tomemme/EncryptedJournal/blob/main/duoTheme.PNG)

# Example JSON File Structure
[
    {"date": "2025-02-20", "entry": "base64_encoded_encrypted_data"},
    {"date": "2025-02-21", "entry": "another_base64_encoded_encrypted_data"}
]

# Smoke Test
Run the local smoke test to verify core journal flows (save, load, delete, and password change):

```bash
python scripts/smoke_test.py
```

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
   git add secure_journal.py
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
