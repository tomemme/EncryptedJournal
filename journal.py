# ver 1.8 added new function on modified to prevent clearing on new text.
#           has file permission setting need to test...
import sys
import tkinter as tk
from tkinter import ttk, simpledialog, messagebox, font, scrolledtext
from tkcalendar import DateEntry
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import json
import os
import gzip
import platform
from datetime import datetime, timedelta
import getpass

# new 1.8 code
# Add this function to locate the theme file and directory
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# new 1.8 code
# Function to set file permissions
def set_file_permissions(filename, readable_only=True):
    if platform.system() == 'Windows':
        if readable_only:
            os.chmod(filename, 0o444)  # Read-only
        else:
            os.chmod(filename, 0o666)  # Read/write
    else:
        if readable_only:
            os.chmod(filename, 0o400)  # Read-only for owner
        else:
            os.chmod(filename, 0o600)  # Read/write for owner

class JournalApp:
    SESSION_TIMEOUT = 300  # 5 minutes

    def __init__(self, root):
        self.root = root
        self.hashed_password = None
        self.last_activity_time = None
        self.entry_loaded = False
        self.loaded_date = ""

        self.setup_ui()
        self.hashed_password = self.prompt_for_password()
        self.print_session_timeout()
        self.filename = resource_path('journal.json.gz')
        self.is_modified = False  # Track if the text has been modified
        

    def prompt_for_password(self):
        password = simpledialog.askstring("Password", "Enter a password for encryption/decryption:", show='*')
        if not password:
            self.root.quit()  # Exit if no password is entered
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(password.encode())
        hashed_password = digest.finalize()
        self.last_activity_time = datetime.now()
        return hashed_password

    def check_session_timeout(self):
        if self.last_activity_time and (datetime.now() - self.last_activity_time > timedelta(seconds=self.SESSION_TIMEOUT)):
            self.hashed_password = None
            messagebox.showinfo("Session Expired", "Your session has expired. Please re-enter your password.")
            self.hashed_password = self.prompt_for_password()
            return True
        return False

    def derive_key(self, password_hash, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password_hash)

    def encrypt_message(self, message, password_hash):
        salt = os.urandom(16)
        key = self.derive_key(password_hash, salt)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()
        return salt + iv + encrypted_message

    def decrypt_message(self, encrypted_message, password_hash):
        salt = encrypted_message[:16]
        iv = encrypted_message[16:32]
        encrypted_message = encrypted_message[32:]
        key = self.derive_key(password_hash, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
        return decrypted_message.decode()
    
    def save_journal_entry(self):
        if self.check_session_timeout() or not self.hashed_password:
            self.hashed_password = self.prompt_for_password()

        journal_entry = self.text_entry.get("1.0", tk.END).strip()
        date_str = self.date_entry.get().strip()

        if journal_entry:
            if not date_str:
                date_str = datetime.now().strftime("%Y-%m-%d")  # Use current date if no date is provided
            else:
                try:
                    # Validate the date format
                    datetime.strptime(date_str, "%Y-%m-%d")
                except ValueError:
                    messagebox.showerror("Error", "Invalid date format. Use YYYY-MM-DD.")
                    return

            encrypted_entry = self.encrypt_message(journal_entry, self.hashed_password)
            entry = {"date": date_str, "entry": encrypted_entry.hex()}

            data = self.load_json()

            if self.entry_loaded and self.loaded_date == date_str:
                for existing_entry in data:
                    if existing_entry["date"] == date_str:
                        existing_entry["entry"] = encrypted_entry.hex()
                        break
            else:
                for existing_entry in data:
                    if existing_entry["date"] == date_str:
                        existing_encrypted_entry = bytes.fromhex(existing_entry["entry"])
                        existing_decrypted_entry = self.decrypt_message(existing_encrypted_entry, self.hashed_password)
                        combined_entry = existing_decrypted_entry + "\n" + journal_entry
                        encrypted_combined_entry = self.encrypt_message(combined_entry, self.hashed_password)
                        existing_entry["entry"] = encrypted_combined_entry.hex()
                        break
                else:
                    data.append(entry)

            # ensure the file is writable
            if os.name == 'nt':
                os.chmod(self.filename, 0o666)  #windows make it writable
            else:
                os.chmod(self.filename, 0o6000) # unix make it writable by owner

            try:
                self.save_json(data)
            except PermissionError as e:
                messagebox.showerror("Error", f"Failed to save entry: {e}")
                return

            self.is_modified = False  # reset the modified flag after a good save

            messagebox.showinfo("Success", "Your journal entry has been encrypted and saved.")
            self.text_entry.delete("1.0", tk.END)
            self.date_entry.delete(0, tk.END)
            self.update_treeview()
            self.days_since_label.config(text=self.days_since_last_entry())

            self.entry_loaded = False
        else:
            messagebox.showwarning("Warning", "Journal entry cannot be empty.")

    def load_journal_entry(self):
        if self.check_session_timeout() or not self.hashed_password:
            self.hashed_password = self.prompt_for_password()

        # preserve selected date before any prompts
        selected_items = self.treeview.selection()
        if not selected_items:
            messagebox.showwarning("Warning", "No date selected.")
            return
        
        selected_item = self.treeview.selection()[0]
        selected_date = self.treeview.item(selected_item, 'text')

        if self.is_modified:
            response = messagebox.askyesnocancel("Unsaved Changes",
                                                 "You have unsaved changes. Would you like to save them before loading a new entry?")
            
            if response is None: # cancel
                return
            elif response:  # yes, save changes
                self.save_journal_entry()

        try:
            if not selected_items:
                messagebox.showwarning("Warning", "No date selected.")
                return

            
            if not selected_date:
                messagebox.showwarning("Warning", "No date selected.")
                return
            data = self.load_json()
            for entry in data:
                if entry["date"] == selected_date:
                    encrypted_entry = bytes.fromhex(entry["entry"])
                    decrypted_entry = self.decrypt_message(encrypted_entry, self.hashed_password)
                    self.text_entry.delete("1.0", tk.END)
                    self.text_entry.insert(tk.END, decrypted_entry)
                    self.date_entry.delete(0, tk.END)
                    self.date_entry.insert(0, selected_date)

                    # reset the modified flag since we've jusut loaded fresh data
                    self.is_modified = False
                    self.entry_loaded = True
                    self.loaded_date = selected_date
                    return
            messagebox.showwarning("Warning", "No entry found for the given date.")
        except FileNotFoundError:
            messagebox.showwarning("Warning", "No journal entries found.")
        except IndexError as e:
            messagebox.showerror("Error", f"An error occurred: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def delete_journal_entry(self):
        if self.check_session_timeout() or not self.hashed_password:
            self.hashed_password = self.prompt_for_password()

        try:
            selected_item = self.treeview.selection()[0]
            selected_date = self.treeview.item(selected_item, 'text')
            if not selected_date:
                messagebox.showwarning("Warning", "No date selected.")
                return
            
            # confirm you want to delete and entry
            confirm = messagebox.askyesno("Confirm Delete", f"Are your sure you want to delete the entry for {selected_date}?")
            if not confirm:
                return; 
        
            data = self.load_json()
            new_data = [entry for entry in data if entry["date"] != selected_date]
            if len(new_data) == len(data):
                messagebox.showwarning("Warning", "No entry found for the given date.")
            else:
                if os.name == 'nt':
                    os.chmod(self.filename, 0o666)  #windows make it writable
                else:
                    os.chmod(self.filename, 0o6000) # unix make it writable by owner

                self.save_json(new_data)
                self.is_modified = False  # Reset the modified flag after deleting
                messagebox.showinfo("Success", "Journal entry deleted successfully.")
                self.update_treeview()
                self.days_since_label.config(text=self.days_since_last_entry())

                self.entry_loaded = False
        except FileNotFoundError:
            messagebox.showwarning("Warning", "No journal entries found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def clear_journal_entry(self):
        self.text_entry.delete("1.0", tk.END)
        self.date_entry.delete(0, tk.END)

    def update_treeview(self):
        data = self.load_json()
        self.treeview.delete(*self.treeview.get_children())
        grouped_data = {}
        for entry in data:
            date_str = entry["date"]
            year_month = date_str[:7]  # Extract YYYY-MM
            if year_month not in grouped_data:
                grouped_data[year_month] = []
            grouped_data[year_month].append(date_str)

        sorted_year_months = sorted(grouped_data.keys(), key=lambda ym: datetime.strptime(ym, "%Y-%m"), reverse=True)

        for year_month in sorted_year_months:
            dates = sorted(grouped_data[year_month], key=lambda date: datetime.strptime(date, "%Y-%m-%d"), reverse=True)
            parent = self.treeview.insert("", "end", text=year_month, open=False)
            for date in dates:
                self.treeview.insert(parent, "end", text=date)

    def days_since_last_entry(self):
        data = self.load_json()
        if not data:
            return "No entries found."

        most_recent_date = max(entry["date"] for entry in data if "date" in entry)
        most_recent_date = datetime.strptime(most_recent_date, "%Y-%m-%d").date()
        current_date = datetime.now().date()
        days_since = (current_date - most_recent_date).days

        return f"It has been {days_since} days since the last entry."

    def load_json(self):
        if not os.path.exists("journal.json.gz"):
            return []
        with gzip.open("journal.json.gz", "rt", encoding="utf-8") as file:
            return json.load(file)

    def save_json(self, data):
        with gzip.open(self.filename, "wt", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        set_file_permissions(self.filename, readable_only=True)

    # new 1.8 code
    def on_modified(self, event=None):
        self.is_modified = True
        self.text_entry.edit_modified(False)  # Reset the modified flag on the text widget

    def print_session_timeout(self):
        if self.last_activity_time:
            elapsed_time = (datetime.now() - self.last_activity_time).total_seconds()
            remaining_time = max(self.SESSION_TIMEOUT - elapsed_time, 0)
            print(f"Session time remaining: {int(remaining_time)} seconds")
            if remaining_time == 0:
                self.check_session_timeout()
        else:
            print("Session expired. Please re-enter your password.")
        self.root.after(10000, self.print_session_timeout)
    
    def setup_ui(self):
        self.root.title("Toms Encrypted Journal")

        try:
            self.root.tk.call("source", "azure.tcl")
            self.root.tk.call("set_theme", "dark")  # Change to "dark" for dark mode
        except tk.TclError as e:
            print(f"Error loading theme: {e}")
            messagebox.showerror("Error", "Unable to load theme. Make sure the azure.tcl file is in the correct directory.")

        date_frame = ttk.Frame(self.root, padding=10)
        date_frame.pack(padx=0, pady=0)

        date_label = ttk.Label(date_frame, text="Journal Entry Date (YYYY-MM-DD):")
        date_label.grid(row=0, column=0, padx=0)

        self.date_entry = tk.Entry(date_frame, width=12, bg='lightgrey', fg='black')
        self.date_entry.grid(row=0, column=1, padx=0)

        # main frame for text and buttons
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        text_frame = ttk.Frame(main_frame, padding=0, style="TFrame")
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_entry = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, width=65, height=20, bg='lightgrey', fg='black')
        self.text_entry.pack()

        text_font = font.Font(family="Verdana", size=10)
        self.text_entry.configure(font=text_font)
        self.text_entry.focus_set()
        self.text_entry.config(insertwidth=5, insertbackground='black')

        # Label to display days since last entry
        self.days_since_label = tk.Label(self.root, text=self.days_since_last_entry(), bg='lightgrey', fg='black')
        self.days_since_label.pack(pady=5)

        button_frame = ttk.Frame(self.root)
        button_frame.pack(padx=5, pady=5)

        self.text_entry.bind("<<Modified>>", self.on_modified)

        save_button = ttk.Button(button_frame, text="Save Entry", command=self.save_journal_entry)
        save_button.grid(row=1, column=0, padx=5)

        load_button = ttk.Button(button_frame, text="Load Entry", command=self.load_journal_entry)
        load_button.grid(row=1, column=1, padx=5)

        delete_button = ttk.Button(button_frame, text="Delete Entry", command=self.delete_journal_entry)
        delete_button.grid(row=1, column=2, padx=5)

        clear_button = ttk.Button(button_frame, text="Clear Entry", command=self.clear_journal_entry)
        clear_button.grid(row=1, column=3, padx=5)

        treeview_frame = ttk.Frame(self.root)
        treeview_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(treeview_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.treeview = ttk.Treeview(treeview_frame, yscrollcommand=scrollbar.set)
        self.treeview.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.treeview.yview)

        self.update_treeview()

if __name__ == "__main__":
    # Ensure the blank JSON file is created if it doesn't exist
    if not os.path.exists(resource_path('journal.json.gz')):
        with gzip.open(resource_path('journal.json.gz'), 'wt', encoding="utf-8") as file:
            json.dump([], file, indent=4)

    root = tk.Tk()
    app = JournalApp(root)
    root.mainloop()
