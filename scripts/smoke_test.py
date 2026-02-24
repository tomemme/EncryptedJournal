#!/usr/bin/env python3
import os
import sys
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import messagebox

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secure_journal import SecureJournalApp


def _select_date_node(app, date_str):
    app.update_treeview()
    for month_node in app.treeview.get_children():
        for date_node in app.treeview.get_children(month_node):
            if app.treeview.item(date_node, "text") == date_str:
                app.treeview.selection_set(date_node)
                app.treeview.focus(date_node)
                return True
    return False


def _patch_messageboxes():
    original = {
        "showinfo": messagebox.showinfo,
        "showwarning": messagebox.showwarning,
        "showerror": messagebox.showerror,
        "askyesno": messagebox.askyesno,
    }
    messagebox.showinfo = lambda *args, **kwargs: None
    messagebox.showwarning = lambda *args, **kwargs: None
    messagebox.showerror = lambda *args, **kwargs: None
    messagebox.askyesno = lambda *args, **kwargs: True
    return original


def _restore_messageboxes(original):
    messagebox.showinfo = original["showinfo"]
    messagebox.showwarning = original["showwarning"]
    messagebox.showerror = original["showerror"]
    messagebox.askyesno = original["askyesno"]


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    if (
        sys.platform.startswith("linux")
        and not os.environ.get("DISPLAY")
        and not os.environ.get("WAYLAND_DISPLAY")
    ):
        print("SKIP: no display available for Tkinter smoke test.")
        return 0

    original_messageboxes = _patch_messageboxes()
    root = None
    temp_dir = None

    try:
        temp_dir = tempfile.TemporaryDirectory(prefix="journal-smoke-")
        journal_path = os.path.join(temp_dir.name, "journal.json.gz")

        try:
            root = tk.Tk(className="JournalSmoke")
        except tk.TclError as error:
            print(f"SKIP: unable to initialize Tkinter display: {error}")
            return 0
        root.withdraw()

        app = SecureJournalApp(root)
        app.filename = journal_path
        app.update_treeview()

        primary_date = "2026-02-24"
        secondary_date = "2026-02-23"
        primary_text = "Smoke test entry primary."
        secondary_text = "Smoke test entry secondary."

        # Save two entries.
        app.prompt_for_password = lambda: "pw-one"
        app.text_entry.delete("1.0", tk.END)
        app.text_entry.insert("1.0", primary_text)
        app.date_entry.delete(0, tk.END)
        app.date_entry.insert(0, primary_date)
        app.save_journal_entry()

        app.prompt_for_password = lambda: "pw-one"
        app.text_entry.delete("1.0", tk.END)
        app.text_entry.insert("1.0", secondary_text)
        app.date_entry.delete(0, tk.END)
        app.date_entry.insert(0, secondary_date)
        app.save_journal_entry()

        saved_data = app.load_json()
        _assert(len(saved_data) == 2, "Expected two encrypted entries after save.")

        # Load and validate first entry.
        _assert(_select_date_node(app, primary_date), "Could not select primary date.")
        app.prompt_for_password = lambda: "pw-one"
        app.load_journal_entry()
        loaded_text = app.text_entry.get("1.0", tk.END).strip()
        _assert(loaded_text == primary_text, "Loaded text did not match saved entry.")

        # Delete secondary entry.
        _assert(_select_date_node(app, secondary_date), "Could not select secondary date.")
        app.prompt_for_password = lambda: "pw-one"
        app.delete_journal_entry()
        remaining = app.load_json()
        _assert(
            all(entry.get("date") != secondary_date for entry in remaining),
            "Secondary entry was not deleted.",
        )

        # Change password for remaining entries.
        app.prompt_for_password = lambda: "pw-one"
        app.prompt_for_new_password = lambda: "pw-two"
        app.change_journal_password()

        # Verify load works with new password.
        _assert(_select_date_node(app, primary_date), "Could not re-select primary date.")
        app.prompt_for_password = lambda: "pw-two"
        app.load_journal_entry()
        reloaded_text = app.text_entry.get("1.0", tk.END).strip()
        _assert(
            reloaded_text == primary_text,
            "Entry did not decrypt correctly after password change.",
        )

        print("PASS: smoke test completed successfully.")
        return 0
    except Exception as error:
        print(f"FAIL: smoke test failed: {error}")
        return 1
    finally:
        if root is not None:
            try:
                root.destroy()
            except Exception:
                pass
        if temp_dir is not None:
            temp_dir.cleanup()
        _restore_messageboxes(original_messageboxes)


if __name__ == "__main__":
    raise SystemExit(main())
