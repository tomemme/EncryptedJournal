# Encrypted Journal
An encrypted journal application written in Python using Tkinter for the GUI and cryptography for encryption. This application allows you to securely save, load, and delete journal entries with encryption.

# Features
- Save Journal Entries: Encrypt and save your journal entries to a .json file.
- Load Journal Entries: Decrypt and load your journal entries from the .json file.
- Delete Journal Entries: Delete specific journal entries from the .json file.
- Days Since Last Entry: Display the number of days since the last journal entry was made.

# Requirements
- Python 3.6+
- The following Python packages:
    - tkinter
    cryptography
    json

# Installation
1. Clone the Repository - git clone https://github.com/tomemme/encrypted-journal.git
    cd encrypted-journal
2. Install Dependencies:
- Install the required Python packages: pip install cryptography

# Usage
1. Run the Application: python journal.py
2. Enter Your Password:
- When prompted, enter a password for encryption and decryption. Ensure you remember this password, as you will need it to decrypt your journal entries.
3. Save a Journal Entry:
- Write your journal entry in the text box.
- Click the "Save Entry" button to encrypt and save the entry.
4. Load a Journal Entry:
- Select a date from the list and click the "Load Entry" button to decrypt and load the entry.
5. Delete a Journal Entry:
-Select a date from the list and click the "Delete Entry" button to delete the entry.

# Code Overview
journal.py
The main script for the encrypted journal application. It uses the following key functions:
1. derive_key - Derives an encryption key from the password using PBKDF2HMAC with SHA-512.
2. encrypt_message - Encrypts a journal entry using the derived key and returns the encrypted message with a salt.
3. decrypt_message - Decrypts an encrypted journal entry using the derived key and returns the original message.
4. save_journal_entry - Encrypts the journal entry and saves it to the .json file with the current date.
5. load_journal_entry - Loads an encrypted journal entry from the .json file, decrypts it, and displays it in the text box.
6. delete_journal_entry - Deletes a specific journal entry from the .json file based on the selected date.
7. update_listbox - Updates the listbox with all available journal entry dates from the .json file.
8. days_since_last_entry - Calculates and returns the number of days since the last journal entry was made.

# Tkinter GUI: Provides the user interface for interacting with the journal.
Encryption and Decryption
The application uses the cryptography library for encryption and decryption of journal entries. Password-based key derivation is used to securely generate encryption keys from user passwords.

# JSON File Storage
Journal entries are stored in a .json file, where each entry is encrypted. The .json file structure allows for easy management and retrieval of entries based on their dates.

# Example JSON File Structure
[
    {
        "date": "2024-07-12",
        "entry": "encrypted_entry_here"
    },
    {
        "date": "2024-07-13",
        "entry": "another_encrypted_entry_here"
    }
]
# Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

# License
This project is licensed under the MIT License. See the LICENSE file for more details.
