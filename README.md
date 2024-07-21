# Encrypted Journal
An encrypted journal application written in Python using Tkinter for the GUI and cryptography for encryption. This application allows you to securely save, load, and delete journal entries with encryption. Your password is hashed with SHA512 after you supply it to the program and the hash expires after 5 mins and you will need to provide your password again. The entries are encrypted using AES encryption combined with a derived key made by using the hashed password and salt again.

# Features
- Encrypt and save your journal entries to a compressed .json file.
- Decrypt and load your journal entries from the compressed .json file.
- Delete specific journal entries from the compressed .json file.
- Display the number of days since the last journal entry was made.
- Clear text entry widget.

# Requirements
- Python 3.6+

# Installation
1. Clone the Repository - git clone https://github.com/tomemme/encrypted-journal.git
    cd encrypted-journal
2. Install Python Dependencies:
- pip install cryptography
- pip install tkcalendar

# Usage
1. Run the Application: python journal.py
2. Enter Your Password:
- When prompted, enter a password for encryption and decryption. Ensure you remember this password, as you will need it to decrypt your journal entries.
3. Save a Journal Entry:
- Write your journal entry in the text box.
- Populate date if your entry isnt for the current day and you cant load an entry.
- Click the "Save Entry" button to encrypt and save the entry.
4. Load a Journal Entry:
- Select a date from the list and click the "Load Entry" button to decrypt and load the entry.
5. Delete a Journal Entry:
-Select a date from the list and click the "Delete Entry" button to delete the entry. 

# Tkinter GUI: Provides the user interface for interacting with the journal.
Encryption and Decryption
The application uses the cryptography library for encryption and decryption of journal entries. Password-based key derivation is used to securely generate encryption keys from user passwords.

![GUI](https://github.com/user-attachments/assets/bcbc7b89-7898-482e-930f-be9540c3c833)

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
