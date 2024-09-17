import tkinter as tk
from tkinter import ttk, messagebox, font, scrolledtext
from tkinter.simpledialog import askstring
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import sys
import gzip
import json
from datetime import datetime, timedelta

class SecureJournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encrypted Journal")
        self.session_timeout = 300  # 5 minutes
        self.last_action_time = datetime.now()
        self.hashed_password = None
        self.filename = "journal.json.gz"
        self.is_modified = False
        self.entry_loaded = False
        self.failed_attempts = 0
        self.max_attempts = 5
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        # Frame for the date selection
        date_frame = tk.Frame(self.root, padx=5, pady=5)
        date_frame.pack(padx=5, pady=5)

        # Entry widget for date input
        date_label = tk.Label(date_frame, text="Enter Date (YYYY-MM-DD):")
        date_label.grid(row=0, column=0, padx=0)
        
        self.date_entry = tk.Entry(date_frame, width=12)
        self.date_entry.grid(row=0, column=1, padx=0)

        # main frame for text and buttons
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        text_frame = ttk.Frame(main_frame, padding=0, style="TFrame")
        text_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_entry = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, width=65, height=20)
        self.text_entry.pack()

        text_font = font.Font(family="Verdana", size=10)
        self.text_entry.configure(font=text_font)
        self.text_entry.focus_set()
        self.text_entry.config(insertwidth=5, insertbackground='black')

        # Label to display days since last entry
        self.days_since_label = ttk.Label(self.root,text=self.days_since_last_entry())
        self.days_since_label.pack(pady=5)

        # Buttons
        button_frame = tk.Frame(self.root)
        button_frame.pack(padx=10, pady=10)

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

        # Treeview for date navigation
        #self.treeview = ttk.Treeview(self.root, columns=("Date"), show='tree')
        #self.treeview.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.treeview = ttk.Treeview(treeview_frame, yscrollcommand=scrollbar.set)
        self.treeview.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.treeview.bind('<<TreeviewSelect>>', self.on_treeview_select)

        # Initial update of treeview
        self.update_treeview()

    def days_since_last_entry(self):
        data = self.load_json()
        if not data:
            return "No entries found."

        # Extract valid dates from entries
        dates = []
        for entry in data:
            date_str = entry.get("date")
            if date_str:
                try:
                    date = datetime.strptime(date_str, "%Y-%m-%d").date()
                    dates.append(date)
                except ValueError:
                    pass  # Ignore invalid date formats

        if not dates:
            return "No valid entries found."

        most_recent_date = max(dates)
        current_date = datetime.now().date()
        days_since = (current_date - most_recent_date).days

        if days_since == 0:
            return "You have made an entry today."
        elif days_since == 1:
            return "It has been 1 day since your last entry."
        else:
            return f"It has been {days_since} days since your last entry."

    def resource_path(self, relative_path):
        try:
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    def apply_theme(self):
        try:
            # Construct the full path to the azure.tcl file using resource_path
            azure_tcl_path = self.resource_path('azure.tcl')

            # Source the azure.tcl file
            self.root.tk.call('source', azure_tcl_path)

            # Set the theme to 'azure'
            self.root.tk.call('set_theme', 'dark')  # Change to 'light' for light mode
        except tk.TclError as e:
            print(f"Error loading theme: {e}")
            messagebox.showerror(
                "Error",
                "Unable to load theme. Make sure the azure.tcl file is in the correct directory."
            )

    def on_treeview_select(self, event):
        self.last_action_time = datetime.now()

    def prompt_for_password(self):
        if self.failed_attempts >= self.max_attempts:
            messagebox.showerror("Error", "Too many failed attempts. Application will exit.")
            self.root.destroy()
            return None

        password = askstring("Password Required", "Enter your journal password:", show='*')
        if password is None:
            raise Exception("Password input canceled by the user.")
        return password

    def derive_key(self, password, salt):
        try:
            # Use Scrypt, a secure KDF, to derive a key from the password
            kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
            key = kdf.derive(password.encode())
            # Reset failed attempts on successful key derivation
            self.failed_attempts = 0
            return key
        except Exception:
            # Increment failed attempts on failure
            self.failed_attempts += 1
            raise

    def encrypt_message(self, message, password):
        salt = os.urandom(16)
        try:
            key = self.derive_key(password, salt)
        except Exception:
            messagebox.showerror("Error", "Incorrect password.")
            return None
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # Standard nonce size for AESGCM
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        return base64.urlsafe_b64encode(salt + nonce + ciphertext).decode('utf-8')

    def decrypt_message(self, encrypted_message, password):
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_message)
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            # Reset failed attempts on successful decryption
            self.failed_attempts = 0
            return plaintext.decode('utf-8')
        except Exception:
            # Increment failed attempts on failure
            self.failed_attempts += 1
            raise ValueError("Incorrect password or corrupted data.")

    def save_json(self, data):
        # Secure file handling with restricted permissions
        with gzip.open(self.filename, "wt", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        # Adjust file permissions
        try:
            if os.name == 'nt':
                # On Windows, file permissions are handled differently
                # Ensure the file is only accessible by the owner
                import win32security
                import ntsecuritycon as con
                user, domain, type = win32security.LookupAccountName("", os.getlogin())
                sd = win32security.GetFileSecurity(self.filename, win32security.DACL_SECURITY_INFORMATION)
                dacl = win32security.ACL()
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE, user)
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(self.filename, win32security.DACL_SECURITY_INFORMATION, sd)
            else:
                os.chmod(self.filename, 0o600)
        except Exception as e:
            messagebox.showwarning("Warning", f"Failed to set file permissions: {e}")

    def load_json(self):
        if os.path.exists(self.filename):
            with gzip.open(self.filename, "rt", encoding="utf-8") as file:
                return json.load(file)
        return []

    def save_journal_entry(self):
        self.last_action_time = datetime.now()
        if self.check_session_timeout() or not self.hashed_password:
            password = self.prompt_for_password()
            if password is None:
                return
            self.hashed_password = password

        journal_entry = self.text_entry.get("1.0", tk.END).strip()
        date_str = self.date_entry.get().strip()

        if journal_entry:
            if not date_str:
                date_str = datetime.now().strftime("%Y-%m-%d")
            encrypted_entry = self.encrypt_message(journal_entry, self.hashed_password)
            if encrypted_entry is None:
                self.hashed_password = None
                return
            entry = {"date": date_str, "entry": encrypted_entry}

            data = self.load_json()
            for existing_entry in data:
                if existing_entry["date"] == date_str:
                    existing_entry["entry"] = encrypted_entry
                    break
            else:
                data.append(entry)

            self.save_json(data)
            messagebox.showinfo("Success", "Your journal entry has been encrypted and saved.")
            self.clear_journal_entry()
            self.update_treeview()
            self.days_since_label.config(text=self.days_since_last_entry())

        else:
            messagebox.showwarning("Warning", "Journal entry cannot be empty.")

        # Clear password from memory
        self.hashed_password = None

    def load_journal_entry(self):
        self.last_action_time = datetime.now()
        if self.check_session_timeout() or not self.hashed_password:
            password = self.prompt_for_password()
            if password is None:
                return
            self.hashed_password = password

        try:
            selected_item = self.treeview.selection()[0]
            selected_date = self.treeview.item(selected_item, 'text')
            if self.treeview.parent(selected_item):
                # If the selected item has a parent, it's a date
                data = self.load_json()
                for entry in data:
                    if entry["date"] == selected_date:
                        decrypted_entry = self.decrypt_message(entry["entry"], self.hashed_password)
                        self.text_entry.delete("1.0", tk.END)
                        self.text_entry.insert(tk.END, decrypted_entry)
                        self.date_entry.delete(0, tk.END)
                        self.date_entry.insert(0, selected_date)
                        self.entry_loaded = True
                        break
                else:
                    messagebox.showwarning("Warning", "No entry found for the selected date.")
            else:
                messagebox.showinfo("Information", "Please select a date, not a month.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            self.hashed_password = None
        except IndexError:
            messagebox.showwarning("Warning", "Please select a date from the list.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entry: {e}")
            self.hashed_password = None

        # Clear password from memory
        self.hashed_password = None

    def delete_journal_entry(self):
        self.last_action_time = datetime.now()
        if self.check_session_timeout() or not self.hashed_password:
            password = self.prompt_for_password()
            if password is None:
                return
            self.hashed_password = password

        try:
            selected_item = self.treeview.selection()[0]
            selected_date = self.treeview.item(selected_item, 'text')
            if self.treeview.parent(selected_item):
                # If the selected item has a parent, it's a date
                confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the entry for {selected_date}?")
                if not confirm:
                    return

                data = self.load_json()
                new_data = [entry for entry in data if entry["date"] != selected_date]
                self.save_json(new_data)

                messagebox.showinfo("Success", "Journal entry deleted successfully.")
                self.clear_journal_entry()
                self.update_treeview()
                self.days_since_label.config(text=self.days_since_last_entry())
            else:
                messagebox.showinfo("Information", "Please select a date to delete, not a month.")
        except IndexError:
            messagebox.showwarning("Warning", "Please select a date from the list.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {e}")
        finally:
            # Clear password from memory
            self.hashed_password = None

    def clear_journal_entry(self):
        self.text_entry.delete("1.0", tk.END)
        self.date_entry.delete(0, tk.END)
        self.entry_loaded = False

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

    def check_session_timeout(self):
        if (datetime.now() - self.last_action_time).seconds > self.session_timeout:
            messagebox.showwarning("Session Timeout", "Your session has expired. Please enter your password again.")
            self.hashed_password = None
            return True
        return False

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureJournalApp(root)
    root.mainloop()
