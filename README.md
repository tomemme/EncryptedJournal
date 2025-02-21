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

# bug report
- i type after loading an entry and in a rush to save the entry before timer, i hit load and it deleted my entry need to add in a safety feature.

# Requirements
- Python 3.6+
- Dependencies:
  - `cryptography` (for encryption/decryption)
  - `pyenchant` (for spell checking)
  - `pywin32` (optional, for Windows file permissions)

# Installation
1. Clone the Repository - git clone https://github.com/tomemme/encrypted-journal.git
    cd encrypted-journal

![GUI](https://github.com/tomemme/EncryptedJournal/blob/main/ThemeGui.PNG)

# Example JSON File Structure
[
    {"date": "2025-02-20", "entry": "base64_encoded_encrypted_data"},
    {"date": "2025-02-21", "entry": "another_base64_encoded_encrypted_data"}
]

# Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

# License
This project is licensed under the MIT License. See the LICENSE file for more details.
