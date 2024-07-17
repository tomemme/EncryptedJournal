# adding gzip to json file on save.

import tkinter as tk
from tkinter import messagebox, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import json
import os
import gzip
from datetime import datetime, timedelta
import getpass

# Flag to indicate if an entry has been loaded
entry_loaded = False
loaded_date = ""

# Function to derive a key from a password and salt
def derive_key(password, salt):
    # Use PBKDF2HMAC to derive a key from the password and salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Function to encrypt a message
def encrypt_message(message, password):
    # Generate a random 16-byte salt
    salt = os.urandom(16)
    key = derive_key(password, salt)
    f = Fernet(key)
    encrypted_message = f.encrypt(message.encode())
    # Prepend the salt to the encrypted message
    return salt + encrypted_message

# Function to decrypt a message
def decrypt_message(encrypted_message, password):
    # Extract the salt from the beginning of the encrypted message
    salt = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    key = derive_key(password, salt)
    f = Fernet(key)
    decrypted_message = f.decrypt(encrypted_message)
    return decrypted_message.decode()

# Prompt the user for a password and derive the key
password = getpass.getpass("Enter a password for encryption/decryption: ")

# Function to save the journal entry
def save_journal_entry():
    global entry_loaded, loaded_date
    journal_entry = text_entry.get("1.0", tk.END).strip()
    if journal_entry:
        # Encrypt the new journal entry
        encrypted_entry = encrypt_message(journal_entry, password)
        date_str = datetime.now().strftime("%Y-%m-%d")  # Use only the date part as timestamp
        entry = {"date": date_str, "entry": encrypted_entry.hex()}  # Store as hex for JSON compatibility
        
        # Load existing entries if they exist
        data = load_json()
        
        if entry_loaded and loaded_date == date_str:
            # If an entry was loaded and the date matches, overwrite the existing entry
            for existing_entry in data:
                if existing_entry["date"] == date_str:
                    existing_entry["entry"] = encrypted_entry.hex()
                    break
        else:
            # Check if an entry for the same date already exists
            for existing_entry in data:
                if existing_entry["date"] == date_str:
                    # Decrypt the existing entry
                    existing_encrypted_entry = bytes.fromhex(existing_entry["entry"])
                    existing_decrypted_entry = decrypt_message(existing_encrypted_entry, password)
                    
                    # Concatenate the new journal entry to the existing one
                    combined_entry = existing_decrypted_entry + "\n" + journal_entry
                    
                    # Encrypt the combined entry
                    encrypted_combined_entry = encrypt_message(combined_entry, password)
                    
                    # Update the existing entry
                    existing_entry["entry"] = encrypted_combined_entry.hex()
                    break
            else:
                # Add a new entry if none exists for the date
                data.append(entry)

        # Save the updated entries back to the file
        save_json(data)

        messagebox.showinfo("Success", "Your journal entry has been encrypted and saved.")
        text_entry.delete("1.0", tk.END)
        update_listbox()  # Refresh the listbox values
        days_since_label.config(text=days_since_last_entry())

        # Reset the entry_loaded flag after saving
        entry_loaded = False
    else:
        messagebox.showwarning("Warning", "Journal entry cannot be empty.")

# Function to load and decrypt a journal entry
def load_journal_entry():
    global entry_loaded, loaded_date
    try:
        selected_date = listbox.get(listbox.curselection())
        if not selected_date:
            messagebox.showwarning("Warning", "No date selected.")
            return
        data = load_json()
        for entry in data:
            if entry["date"] == selected_date:
                encrypted_entry = bytes.fromhex(entry["entry"])
                decrypted_entry = decrypt_message(encrypted_entry, password)
                text_entry.delete("1.0", tk.END)
                text_entry.insert(tk.END, decrypted_entry)
                
                # Set the flag and loaded_date
                entry_loaded = True
                loaded_date = selected_date
                
                return
        messagebox.showwarning("Warning", "No entry found for the given date.")
    except FileNotFoundError:
        messagebox.showwarning("Warning", "No journal entries found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to delete a journal entry
def delete_journal_entry():
    global entry_loaded
    try:
        selected_date = listbox.get(listbox.curselection())
        if not selected_date:
            messagebox.showwarning("Warning", "No date selected.")
            return
        data = load_json()
        new_data = [entry for entry in data if entry["date"] != selected_date]
        if len(new_data) == len(data):
            messagebox.showwarning("Warning", "No entry found for the given date.")
        else:
            save_json(new_data)
            messagebox.showinfo("Success", "Journal entry deleted successfully.")
            update_listbox()  # Refresh the listbox values
            days_since_label.config(text=days_since_last_entry())

            # Reset the entry_loaded flag after deleting
            entry_loaded = False
    except FileNotFoundError:
        messagebox.showwarning("Warning", "No journal entries found.")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

# Function to clear the text box instead of saving
def clear_journal_entry():
    text_entry.delete("1.0", tk.END)

# Function to update the listbox with dates
def update_listbox():
    data = load_json()
    dates = [entry["date"] for entry in data if "date" in entry]
    listbox.delete(0, tk.END)  # Clear the listbox
    for date in dates:
        listbox.insert(tk.END, date)  # Insert dates into the listbox

# Function to display number of days since an entry was made
def days_since_last_entry():
    data = load_json()
    if not data:
        return "No entries found."
    
    # Find the most recent entry date
    most_recent_date = max(entry["date"] for entry in data if "date" in entry)
    most_recent_date = datetime.strptime(most_recent_date, "%Y-%m-%d").date()
    current_date = datetime.now().date()
    days_since = (current_date - most_recent_date).days

    return f"It has been {days_since} days since the last entry."

# Function to load JSON data from the compressed file
def load_json():
    if not os.path.exists("journal.json.gz"):
        return []
    with gzip.open("journal.json.gz", "rt", encoding="utf-8") as file:
        return json.load(file)

# Function to save JSON data to the compressed file
def save_json(data):
    with gzip.open("journal.json.gz", "wt", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

# Set up the GUI
root = tk.Tk()  # Create the main window
root.title("Toms Encrypted Journal")  # Set the title of the window

# Frame for shaded padding around the text widget
text_frame = tk.Frame(root, bg='lightgrey', padx=10, pady=10)
text_frame.pack(padx=10, pady=10)

# Text widget for journal entry with a background color
text_entry = tk.Text(text_frame, wrap=tk.WORD, width=60, height=20, bg='white', fg='black')
text_entry.pack()

# Change pointer when inside the text widget
text_entry.focus_set()

# Customize the cursor
text_entry.config(insertwidth=5)  # Adjust the width of the cursor to make it look like an underscore
text_entry.config(insertbackground='black')  # Set the cursor color

# Frame for buttons
button_frame = tk.Frame(root)
button_frame.pack(padx=10, pady=10)

# Label to display days since last entry
days_since_label = tk.Label(root, text=days_since_last_entry(), bg='lightgrey', fg='black')
days_since_label.pack(pady=5)

# Save button
save_button = tk.Button(button_frame, text="Save Entry", command=save_journal_entry)
save_button.grid(row=0, column=0, padx=5)

# Load button
load_button = tk.Button(button_frame, text="Load Entry", command=load_journal_entry)
load_button.grid(row=0, column=1, padx=5)

# Delete button
delete_button = tk.Button(button_frame, text="Delete Entry", command=delete_journal_entry)
delete_button.grid(row=0, column=2, padx=5)

# Clear text box button, clears text or loaded entry
clear_button = tk.Button(button_frame, text="Clear Entry", command=clear_journal_entry)
clear_button.grid(row=0, column=3, padx=5)

# Frame for the listbox and scrollbar
listbox_frame = tk.Frame(root)
listbox_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Scrollbar for the listbox
scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Listbox for selecting dates
listbox = tk.Listbox(listbox_frame, yscrollcommand=scrollbar.set)
listbox.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
scrollbar.config(command=listbox.yview)

# Initial update of listbox values
update_listbox()

# Start the GUI event loop
root.mainloop()
