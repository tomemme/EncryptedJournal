# Encrypted Journal
An encrypted journal application written in Python using Tkinter for the GUI and cryptography for encryption. This application allows you to securely save, load, and delete journal entries with encryption.

# Features
Save Journal Entries: Encrypt and save your journal entries to a .json file.
Load Journal Entries: Decrypt and load your journal entries from the .json file.
Delete Journal Entries: Delete specific journal entries from the .json file.
Days Since Last Entry: Display the number of days since the last journal entry was made.
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

Make sure you have Python 3.6+ installed.
Install the required Python packages:
bash
Copy code
pip install cryptography
Usage
Run the Application:

bash
Copy code
python journal.py
Enter Your Password:

When prompted, enter a password for encryption and decryption. Ensure you remember this password, as you will need it to decrypt your journal entries.
Save a Journal Entry:

Write your journal entry in the text box.
Click the "Save Entry" button to encrypt and save the entry.
Load a Journal Entry:

Select a date from the list and click the "Load Entry" button to decrypt and load the entry.
Delete a Journal Entry:

Select a date from the list and click the "Delete Entry" button to delete the entry.
Code Overview
journal.py
The main script for the encrypted journal application. It uses the following key components:

JournalService Class: Handles encryption, decryption, and management of journal entries.
FileRepository Class: Manages saving, loading, and deleting journal entries in a .json file.
Tkinter GUI: Provides the user interface for interacting with the journal.
Encryption and Decryption
The application uses the cryptography library for encryption and decryption of journal entries. Password-based key derivation is used to securely generate encryption keys from user passwords.

JSON File Storage
Journal entries are stored in a .json file, where each entry is encrypted. The .json file structure allows for easy management and retrieval of entries based on their dates.

Example JSON File Structure
json
Copy code
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
Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

License
This project is licensed under the MIT License. See the LICENSE file for more details.
