#!/usr/bin/env python3
import os
import sys
import tempfile
import time
import tkinter as tk
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tkinter import filedialog, messagebox

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import journal_core
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
    original_journal_file = os.environ.get("ENCRYPTED_JOURNAL_FILE")

    try:
        temp_dir = tempfile.TemporaryDirectory(prefix="journal-smoke-")
        journal_path = os.path.join(temp_dir.name, "journal.json.gz")
        # Set before construction so SecureJournalApp.__init__'s own
        # _resolve_journal_path()/configure_rotating_logger() calls resolve
        # to this tempdir too, not the real default journal/log location.
        os.environ["ENCRYPTED_JOURNAL_FILE"] = journal_path

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

        # Overwrite guard: saving a different body for a date that already
        # has an entry, without having explicitly Loaded it first, should
        # populate the editor with the existing entry instead of
        # overwriting it on disk.
        guard_date = "2026-02-22"
        guard_original_text = "Guard original text."
        app.prompt_for_password = lambda: "pw-one"
        app.text_entry.delete("1.0", tk.END)
        app.text_entry.insert("1.0", guard_original_text)
        app.date_entry.delete(0, tk.END)
        app.date_entry.insert(0, guard_date)
        app.save_journal_entry()

        app.prompt_for_password = lambda: "pw-one"
        app.text_entry.delete("1.0", tk.END)
        app.text_entry.insert("1.0", "Attempted overwrite text.")
        app.date_entry.delete(0, tk.END)
        app.date_entry.insert(0, guard_date)
        _assert(
            not app.entry_loaded,
            "entry_loaded should be False before triggering the overwrite guard.",
        )
        app.save_journal_entry()

        _assert(
            app.entry_loaded and app.loaded_entry_date == guard_date,
            "Overwrite guard should have loaded the existing entry instead "
            "of saving over it.",
        )
        guarded_editor_text = app.text_entry.get("1.0", tk.END).strip()
        _assert(
            guarded_editor_text == guard_original_text,
            "Overwrite guard should have populated the editor with the "
            f"existing entry's text, got {guarded_editor_text!r}.",
        )
        on_disk_after_guard = app.load_json()
        guarded_entry = next(
            (e for e in on_disk_after_guard if e.get("date") == guard_date), None
        )
        _assert(guarded_entry is not None, "Guarded entry should still exist on disk.")
        decrypted_guarded = journal_core.decrypt_message(
            guarded_entry["entry"], "pw-one"
        )
        _assert(
            decrypted_guarded == guard_original_text,
            "On-disk entry should be unchanged after the overwrite guard "
            f"fired, got {decrypted_guarded!r}.",
        )

        # Clear (the actual button handler, not the internal full-reset
        # clear_journal_entry) + type new text + Save should actually
        # replace it, without the guard re-triggering and reloading the
        # old content over the new text.
        app.clear_entry_text()
        _assert(
            app.text_entry.get("1.0", tk.END).strip() == "",
            "clear_entry_text should blank the entry body.",
        )
        _assert(
            app.entry_loaded and app.loaded_entry_date == guard_date,
            "clear_entry_text should preserve entry_loaded/loaded_entry_date "
            "so the next Save for the same date isn't guarded again.",
        )
        _assert(
            app.date_entry.get().strip() == guard_date,
            "clear_entry_text should not touch the date field.",
        )
        app.prompt_for_password = lambda: "pw-one"
        app.text_entry.delete("1.0", tk.END)
        app.text_entry.insert("1.0", "Replacement text after Clear.")
        app.save_journal_entry()
        on_disk_after_replace = app.load_json()
        replaced_entry = next(
            (e for e in on_disk_after_replace if e.get("date") == guard_date), None
        )
        decrypted_replaced = journal_core.decrypt_message(
            replaced_entry["entry"], "pw-one"
        )
        _assert(
            decrypted_replaced == "Replacement text after Clear.",
            "Entry should be replaced after Clear + re-save, got "
            f"{decrypted_replaced!r}.",
        )

        app._current_datetime = lambda: datetime(2026, 2, 24, 12, 30, 15)
        app.refresh_days_since_label()
        _assert(
            app.days_since_label.cget("text") == "You have made an entry today.",
            "Days-since label should reflect same-day entry status.",
        )

        scheduled = {}
        original_after = app.root.after

        def fake_after(delay_ms, callback):
            scheduled["delay_ms"] = delay_ms
            scheduled["callback"] = callback
            return "after-test-id"

        try:
            if app._days_since_refresh_after_id is not None:
                app.root.after_cancel(app._days_since_refresh_after_id)
                app._days_since_refresh_after_id = None

            app.root.after = fake_after
            app._schedule_days_since_refresh()
            _assert(
                scheduled.get("delay_ms") == 41385000,
                f"Unexpected midnight refresh delay: {scheduled.get('delay_ms')}",
            )
            _assert(
                scheduled.get("callback") == app._handle_day_rollover,
                "Midnight refresh should schedule the rollover callback.",
            )

            app._current_datetime = lambda: datetime(2026, 2, 25, 0, 0, 5)
            app._handle_day_rollover()
            _assert(
                app.days_since_label.cget("text")
                == "It has been 1 day since your last entry.",
                "Days-since label should update after midnight rollover.",
            )
            _assert(
                app._days_since_refresh_after_id == "after-test-id",
                "Rollover should schedule the next midnight refresh.",
            )
        finally:
            app.root.after = original_after

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

        # Rotating-file logger: journal_core.configure_rotating_logger should
        # have attached a real file handler pointed at the journal's directory.
        _assert(
            any(isinstance(h, RotatingFileHandler) for h in app.logger.handlers),
            "app.logger should have a RotatingFileHandler attached.",
        )
        expected_log_path = os.path.join(temp_dir.name, "encrypted-journal.log")
        file_handlers = [
            h for h in app.logger.handlers if isinstance(h, RotatingFileHandler)
        ]
        _assert(
            file_handlers and file_handlers[0].baseFilename == expected_log_path,
            "app.logger's file handler should point at the journal's own directory.",
        )

        # Manual backup: create_manual_backup should produce a .bak-* file
        # beside the journal.
        app.create_manual_backup()
        backups_after_manual = journal_core.list_journal_backups(app.filename)
        _assert(
            len(backups_after_manual) >= 1,
            "create_manual_backup should have produced at least one backup file.",
        )
        pre_restore_backup_count = len(backups_after_manual)

        # create_journal_backup's timestamp suffix has 1-second granularity
        # (journal_core.create_journal_backup: "%Y%m%d-%H%M%S") - two backups
        # within the same wall-clock second collide on filename and silently
        # overwrite each other rather than both existing. A real user won't
        # click backup-then-restore within the same second, but this
        # automated test runs fast enough to hit that race, so force a gap.
        time.sleep(1.1)

        # Restore from backup: monkeypatch the native file picker to select
        # the manual backup just created, then verify the journal's content
        # matches that backup's, and that a safety backup was made too.
        selected_backup = backups_after_manual[0]
        expected_restored_data = journal_core.load_json(selected_backup)

        original_askopenfilename = filedialog.askopenfilename
        filedialog.askopenfilename = lambda *args, **kwargs: selected_backup
        try:
            app.restore_journal_backup()
        finally:
            filedialog.askopenfilename = original_askopenfilename

        restored_data = app.load_json()
        _assert(
            restored_data == expected_restored_data,
            "Journal content after restore should match the selected backup.",
        )
        backups_after_restore = journal_core.list_journal_backups(app.filename)
        _assert(
            len(backups_after_restore) > pre_restore_backup_count,
            "restore_journal_backup should create a safety backup of the "
            "pre-restore journal before overwriting it.",
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
        if original_journal_file is not None:
            os.environ["ENCRYPTED_JOURNAL_FILE"] = original_journal_file
        else:
            os.environ.pop("ENCRYPTED_JOURNAL_FILE", None)


if __name__ == "__main__":
    raise SystemExit(main())
