#!/usr/bin/env python3
"""
Encrypted Journal - Textual TUI frontend.

Standalone script, independent of secure_journal.py (the Tkinter GUI).
Must never import tkinter or secure_journal, directly or transitively -
only journal_core plus Textual, so it stays usable headless / over SSH.
"""

import getpass
import os
from datetime import datetime

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    OptionList,
    TextArea,
    Tree,
)
from textual.widgets.option_list import Option

import journal_core
import omarchy_theme

# Writes to a rotating file (shared with secure_journal.py via
# journal_core.configure_rotating_logger) instead of leaving the logger
# unhandled: an unhandled warning from journal_core (e.g. load_json skipping
# a malformed record) would otherwise fall through to logging.lastResort and
# write raw to stderr, corrupting the actively-rendered Textual frame. A real
# handler is always attached, which is what actually prevents that - a
# NullHandler would only have silenced the symptom. User-facing errors/status
# are still surfaced via screen UI, not via this logger.
logger = journal_core.configure_rotating_logger(
    journal_core.resolve_journal_path(), logger_name="journal_tui"
)

MAX_FAILED_ATTEMPTS = 5  # matches SecureJournalApp.max_attempts in secure_journal.py

DEFAULT_LOCK_SECONDS = 300  # 5 minutes, overridable via ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS
SESSION_LOCK_CHECK_INTERVAL = 0.25  # seconds between inactivity-timer checks
OMARCHY_THEME_POLL_INTERVAL = 1  # seconds; two small file reads, cheap enough to poll fast


class EntryViewScreen(Screen):
    """Create/view/edit a single journal entry.

    Two modes land on this same screen:
    - "new": empty body, date pre-filled to today.
    - "view": body decrypted from the on-disk entry for `date` and
      populated; date pre-filled to that date. If decryption fails (e.g. a
      stale in-memory app.password), falls back to an in-place password
      re-prompt instead of crashing or showing garbage.

    ctrl+s saves (matching SecureJournalApp.save_journal_entry's exact
    validation/error strings and update-or-append-by-date logic); ctrl+r
    clears the body text (see action_clear_entry); escape discards and
    returns to EntryListScreen unsaved.

    EntryListScreen.action_new_entry is an overwrite guard: pressing 'n'
    for a date that already has an entry opens this screen in "view" mode
    with a `notice` instead of a blank "new" editor, so a same-date save
    can't silently clobber existing content.
    """

    BINDINGS = [
        Binding("ctrl+s", "save_entry", "Save"),
        Binding("ctrl+r", "clear_entry", "Clear"),
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, *, mode: str, date: str, notice: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.mode = mode
        self.date = date
        # Optional message shown once the editor is visible - used by
        # EntryListScreen.action_new_entry to explain why an entry already
        # exists for this date is being opened for editing rather than a
        # blank "new" editor (the overwrite guard).
        self.notice = notice
        self._encrypted_entry_text: str | None = None
        # What the password re-prompt is resuming once a valid password is
        # re-entered: "view" (decrypt-and-populate) or "save" (encrypt-and-
        # write). Set right before _show_password_reprompt() is called.
        self._reprompt_mode: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="entryview-dialog"):
            yield Label(self._title_text(), id="entryview-title")
            with Vertical(id="entryview-editor"):
                yield Label("Date (YYYY-MM-DD):", id="entryview-date-label")
                yield Input(id="entryview-date-input")
                yield TextArea(id="entryview-body")
                yield Label("", id="entryview-message")
            with Vertical(id="entryview-reprompt", classes="hidden"):
                yield Label("", id="entryview-reprompt-message")
                yield Input(
                    placeholder="Password",
                    password=True,
                    id="entryview-reprompt-password",
                )
                yield Button(
                    "Retry", id="entryview-reprompt-submit", variant="primary"
                )
        yield Footer()

    def _title_text(self) -> str:
        label = "New entry" if self.mode == "new" else "View/edit entry"
        return f"{label} — {self.date}"

    def on_mount(self) -> None:
        self.query_one("#entryview-date-input", Input).value = self.date
        if self.mode == "view":
            self._load_entry_for_view()
        else:
            self.query_one("#entryview-body", TextArea).focus()

    # -- view-mode decrypt / password re-prompt -----------------------

    def _load_entry_for_view(self) -> None:
        data = journal_core.load_json(self.app.journal_path, logger=logger)
        entry = journal_core.find_entry_by_date(data, self.date)
        if entry is None:
            self._set_message(f"No entry found for {self.date}.")
            return
        self._encrypted_entry_text = entry.get("entry", "")
        self._try_decrypt_and_populate()

    def _try_decrypt_and_populate(self) -> None:
        try:
            plaintext = journal_core.decrypt_message(
                self._encrypted_entry_text, self.app.password
            )
        except ValueError:
            # Covers both a stale/wrong password and no password currently
            # held at all (a session-lock timer expiry) - decrypt_message
            # wraps every failure, including deriving from a None password,
            # into ValueError, so both cases land here identically.
            self._reprompt_mode = "view"
            self._show_password_reprompt(
                "Could not decrypt this entry with the current password "
                "(it may be stale, or the session may have locked). Enter "
                "your password to continue."
            )
            return
        self.query_one("#entryview-body", TextArea).text = plaintext
        self._show_editor()

    def _show_password_reprompt(self, message: str) -> None:
        self.query_one("#entryview-editor", Vertical).add_class("hidden")
        self.query_one("#entryview-reprompt", Vertical).remove_class("hidden")
        self.query_one("#entryview-reprompt-message", Label).update(message)
        password_input = self.query_one("#entryview-reprompt-password", Input)
        password_input.value = ""
        password_input.focus()

    def _show_editor(self) -> None:
        self.query_one("#entryview-reprompt", Vertical).add_class("hidden")
        self.query_one("#entryview-editor", Vertical).remove_class("hidden")
        if self.notice:
            self._set_message(self.notice)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "entryview-reprompt-password":
            self._retry_password(event.input.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "entryview-reprompt-submit":
            self._retry_password(
                self.query_one("#entryview-reprompt-password", Input).value
            )

    def _retry_password(self, typed_password: str) -> None:
        candidate = bytearray(typed_password, "utf-8")
        is_save_resume = self._reprompt_mode == "save"

        if is_save_resume:
            # No specific ciphertext to validate against for a brand-new
            # entry - fall back to the same "first entry" check UnlockScreen
            # uses, and skip validation entirely on an empty/new journal.
            data = journal_core.load_json(self.app.journal_path, logger=logger)
            reference_ciphertext = data[0].get("entry", "") if data else None
        else:
            reference_ciphertext = self._encrypted_entry_text

        plaintext = None
        if reference_ciphertext is not None:
            try:
                plaintext = journal_core.decrypt_message(
                    reference_ciphertext, candidate
                )
            except ValueError:
                for i in range(len(candidate)):
                    candidate[i] = 0
                self.query_one("#entryview-reprompt-message", Label).update(
                    "Incorrect password. Try again."
                )
                self.query_one("#entryview-reprompt-password", Input).value = ""
                return

        # Correct password (or nothing on disk yet to validate against):
        # adopt it as the app's current session password.
        self.query_one("#entryview-reprompt-password", Input).value = ""
        self.app._wipe_password()
        self.app.password = candidate
        self._show_editor()

        if is_save_resume:
            self._do_save()
        elif plaintext is not None:
            self.query_one("#entryview-body", TextArea).text = plaintext

    # -- save / cancel --------------------------------------------------

    def _set_message(self, text: str) -> None:
        self.query_one("#entryview-message", Label).update(text)

    def action_save_entry(self) -> None:
        body_area = self.query_one("#entryview-body", TextArea)
        date_input = self.query_one("#entryview-date-input", Input)

        journal_entry = body_area.text.strip()
        date_str = date_input.value.strip()

        if not journal_entry:
            self._set_message("Journal entry cannot be empty.")
            return

        if not date_str:
            date_str = datetime.now().strftime("%Y-%m-%d")
        else:
            try:
                datetime.strptime(date_str, "%Y-%m-%d")
            except ValueError:
                self._set_message("Invalid date format. Use YYYY-MM-DD")
                return

        self.app.record_action()

        if self.app.password is None:
            # Session lock fired mid-edit: the typed body/date above are
            # untouched (still sitting in their widgets) - re-prompt in
            # place and resume the save once a password is re-entered,
            # rather than losing the edit or crashing on a None password.
            self._reprompt_mode = "save"
            self._show_password_reprompt(
                "Session locked. Enter your password to continue saving."
            )
            return

        self._do_save(date_str, journal_entry)

    def _do_save(
        self, date_str: str | None = None, journal_entry: str | None = None
    ) -> None:
        if date_str is None or journal_entry is None:
            body_area = self.query_one("#entryview-body", TextArea)
            date_input = self.query_one("#entryview-date-input", Input)
            journal_entry = body_area.text.strip()
            date_str = date_input.value.strip() or datetime.now().strftime(
                "%Y-%m-%d"
            )

        try:
            encrypted_entry = journal_core.encrypt_message(
                journal_entry, self.app.password
            )
        except Exception as error:
            self._set_message(f"Failed to save entry: {error}")
            return

        data = journal_core.load_json(self.app.journal_path, logger=logger)

        for existing_entry in data:
            if existing_entry.get("date") == date_str:
                existing_entry["entry"] = encrypted_entry
                break
        else:
            data.append({"date": date_str, "entry": encrypted_entry})

        try:
            journal_core.save_json(self.app.journal_path, data, logger=logger)
        except Exception as error:
            self._set_message(f"Failed to save entry: {error}")
            return

        self._return_to_list(f"Saved entry for {date_str}.")

    def action_cancel(self) -> None:
        self.app.pop_screen()

    def action_clear_entry(self) -> None:
        # Only clears the body text (not the date field) - lets the
        # overwrite guard's "opened the existing entry for editing" flow
        # be turned into a genuinely blank entry for the same date without
        # having to retype the date.
        self.query_one("#entryview-body", TextArea).text = ""
        self._set_message("Cleared. Save to write a blank entry, or type a new one.")
        self.query_one("#entryview-body", TextArea).focus()

    def _return_to_list(self, message: str) -> None:
        self.app.pop_screen()
        list_screen = self.app.screen
        if isinstance(list_screen, EntryListScreen):
            list_screen.refresh_entries()
            list_screen._set_message(message)


class DeleteConfirmScreen(ModalScreen[bool]):
    """Yes/No confirmation modal for deleting a single dated journal entry.

    Reachable only for a "date" leaf - EntryListScreen.action_delete_entry
    guards month/root nodes before ever constructing this screen.

    Mirrors SecureJournalApp.delete_journal_entry's decrypt-then-confirm
    order: the entry is decrypted with the app's current in-memory
    password BEFORE the Yes/No prompt is shown. If that decryption fails -
    a stale/wrong password, or no password currently held at all because a
    session-lock timer expired - an in-place password re-prompt is shown
    instead (same pattern as EntryViewScreen's), and the Yes/No prompt
    resumes once a valid password is re-entered.

    Dismisses with True only if the entry was actually deleted from disk;
    False for No, Escape, a missing entry, or a save failure.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, *, date: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.date = date
        self._encrypted_entry_text: str | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="delete-confirm-dialog"):
            with Vertical(id="delete-confirm-prompt"):
                yield Label(
                    f"Delete entry for {self.date}? This cannot be undone.",
                    id="delete-confirm-message",
                )
                with Horizontal(id="delete-confirm-buttons"):
                    yield Button("Yes", id="delete-confirm-yes", variant="error")
                    yield Button("No", id="delete-confirm-no", variant="primary")
            with Vertical(id="delete-confirm-error", classes="hidden"):
                yield Label("", id="delete-confirm-error-message")
                yield Button("OK", id="delete-confirm-ok", variant="primary")
            with Vertical(id="delete-confirm-reprompt", classes="hidden"):
                yield Label("", id="delete-confirm-reprompt-message")
                yield Input(
                    placeholder="Password",
                    password=True,
                    id="delete-confirm-reprompt-password",
                )
                yield Button(
                    "Retry", id="delete-confirm-reprompt-submit", variant="primary"
                )

    def on_mount(self) -> None:
        data = journal_core.load_json(self.app.journal_path, logger=logger)
        entry = next((e for e in data if e.get("date") == self.date), None)

        if entry is None:
            self._show_error(f"No entry found for {self.date}.")
            return

        self._encrypted_entry_text = entry.get("entry", "")
        self._try_decrypt_and_confirm()

    def _try_decrypt_and_confirm(self) -> None:
        try:
            journal_core.decrypt_message(
                self._encrypted_entry_text, self.app.password
            )
        except ValueError:
            # Covers both a stale/wrong password and no password currently
            # held (session-lock expiry) - decrypt_message wraps both into
            # ValueError identically.
            self._show_password_reprompt(
                "Could not decrypt this entry with the current password "
                "(it may be stale, or the session may have locked). Enter "
                "your password to continue with deletion."
            )
            return

        self.query_one("#delete-confirm-yes", Button).focus()

    def _show_error(self, message: str) -> None:
        self.query_one("#delete-confirm-prompt", Vertical).add_class("hidden")
        self.query_one("#delete-confirm-reprompt", Vertical).add_class("hidden")
        self.query_one("#delete-confirm-error", Vertical).remove_class("hidden")
        self.query_one("#delete-confirm-error-message", Label).update(message)
        self.query_one("#delete-confirm-ok", Button).focus()

    def _show_password_reprompt(self, message: str) -> None:
        self.query_one("#delete-confirm-prompt", Vertical).add_class("hidden")
        self.query_one("#delete-confirm-error", Vertical).add_class("hidden")
        self.query_one("#delete-confirm-reprompt", Vertical).remove_class("hidden")
        self.query_one("#delete-confirm-reprompt-message", Label).update(message)
        password_input = self.query_one("#delete-confirm-reprompt-password", Input)
        password_input.value = ""
        password_input.focus()

    def _show_prompt(self) -> None:
        self.query_one("#delete-confirm-reprompt", Vertical).add_class("hidden")
        self.query_one("#delete-confirm-prompt", Vertical).remove_class("hidden")
        self.query_one("#delete-confirm-yes", Button).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "delete-confirm-reprompt-password":
            self._retry_password(event.input.value)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "delete-confirm-yes":
            self._do_delete()
        elif event.button.id in ("delete-confirm-no", "delete-confirm-ok"):
            self.dismiss(False)
        elif event.button.id == "delete-confirm-reprompt-submit":
            self._retry_password(
                self.query_one("#delete-confirm-reprompt-password", Input).value
            )

    def _retry_password(self, typed_password: str) -> None:
        candidate = bytearray(typed_password, "utf-8")
        try:
            journal_core.decrypt_message(self._encrypted_entry_text, candidate)
        except ValueError:
            for i in range(len(candidate)):
                candidate[i] = 0
            self.query_one("#delete-confirm-reprompt-message", Label).update(
                "Incorrect password. Try again."
            )
            self.query_one("#delete-confirm-reprompt-password", Input).value = ""
            return
        # Correct password: adopt it as the app's current session password.
        self.query_one("#delete-confirm-reprompt-password", Input).value = ""
        self.app._wipe_password()
        self.app.password = candidate
        self._show_prompt()

    def action_cancel(self) -> None:
        self.dismiss(False)

    def _do_delete(self) -> None:
        data = journal_core.load_json(self.app.journal_path, logger=logger)
        new_data = [entry for entry in data if entry.get("date") != self.date]
        try:
            journal_core.save_json(self.app.journal_path, new_data, logger=logger)
        except Exception as error:
            self._show_error(f"Failed to delete entry: {error}")
            return
        self.dismiss(True)


class SettingsScreen(Screen):
    """Backup/restore screen, reached from EntryListScreen via 's'.

    Neither action needs the journal password - both operate on the whole
    encrypted file as opaque bytes, not on individual decrypted entries -
    so there's no password-reprompt path here (contrast EntryViewScreen /
    DeleteConfirmScreen).

    Two sections toggled via the "hidden" class (same pattern as
    EntryViewScreen's editor/reprompt and DeleteConfirmScreen's
    prompt/error/reprompt), rather than a separate pushed screen for
    restore:
    - "main": Create Backup Now / Restore From Backup.
    - "restore": a list of backups found beside the journal
      (`journal_core.list_journal_backups`) plus a free-text path Input -
      restoring works the same way from either, so a backup that lives
      anywhere on disk (not just beside the journal file) can be restored
      directly, with no manual copy-into-the-folder step first.

    A third, normally-hidden sub-section under "restore"
    (#settings-restore-skip-backup) only appears if the pre-restore safety
    backup of the *current* journal fails - mirrors the GUI's
    askyesno("...Continue restoring anyway?") fallback instead of either
    silently skipping the safety backup or blocking the restore entirely.
    """

    BINDINGS = [
        Binding("escape", "close", "Back"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="settings-dialog"):
            yield Label("Settings", id="settings-title")
            with Vertical(id="settings-main"):
                yield Button("Create Backup Now", id="settings-backup-btn")
                yield Button("Restore From Backup", id="settings-restore-btn")
                yield Label("", id="settings-message")
            with Vertical(id="settings-restore", classes="hidden"):
                yield Label("Restore From Backup", id="settings-restore-title")
                yield Label(
                    "Existing backups (select to fill in the path below):",
                    id="settings-restore-list-label",
                )
                yield OptionList(id="settings-restore-list")
                yield Label(
                    "Or enter/paste any backup file path:",
                    id="settings-restore-path-label",
                )
                yield Input(
                    placeholder="/path/to/journal.json.gz.bak-...",
                    id="settings-restore-path-input",
                )
                yield Label("", id="settings-restore-message")
                with Horizontal(id="settings-restore-buttons"):
                    yield Button(
                        "Restore", id="settings-restore-submit", variant="primary"
                    )
                    yield Button("Back", id="settings-restore-back")
                with Vertical(
                    id="settings-restore-skip-backup", classes="hidden"
                ):
                    yield Label("", id="settings-restore-skip-message")
                    with Horizontal(id="settings-restore-skip-buttons"):
                        yield Button(
                            "Restore Anyway",
                            id="settings-restore-skip-confirm",
                            variant="error",
                        )
                        yield Button("Cancel", id="settings-restore-skip-cancel")
        yield Footer()

    def on_mount(self) -> None:
        self.app.record_action()
        self._pending_restore_path: str | None = None
        self._pending_restore_data = None

    # -- main section -----------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "settings-backup-btn":
            self._create_backup()
        elif event.button.id == "settings-restore-btn":
            self._show_restore_section()
        elif event.button.id == "settings-restore-submit":
            self._attempt_restore()
        elif event.button.id == "settings-restore-back":
            self._show_main_section()
        elif event.button.id == "settings-restore-skip-confirm":
            self._finish_restore(self._pending_restore_path, self._pending_restore_data)
        elif event.button.id == "settings-restore-skip-cancel":
            self._hide_skip_backup_section()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "settings-restore-path-input":
            self._attempt_restore()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        if event.option_list.id == "settings-restore-list" and event.option.id:
            self.query_one(
                "#settings-restore-path-input", Input
            ).value = event.option.id

    def _create_backup(self) -> None:
        self.app.record_action()
        message = self.query_one("#settings-message", Label)
        if not os.path.exists(self.app.journal_path):
            message.update("There is no journal file to back up yet.")
            return
        try:
            backup_path = journal_core.create_journal_backup(self.app.journal_path)
        except Exception as error:
            message.update(f"Unable to create a backup: {error}")
            return
        message.update(f"Backup created at:\n{backup_path}")

    # -- restore section ----------------------------------------------------

    def _show_restore_section(self) -> None:
        self.app.record_action()
        self.query_one("#settings-title", Label).add_class("hidden")
        self.query_one("#settings-main", Vertical).add_class("hidden")
        self.query_one("#settings-restore", Vertical).remove_class("hidden")
        self._hide_skip_backup_section()

        option_list = self.query_one("#settings-restore-list", OptionList)
        option_list.clear_options()
        backups = journal_core.list_journal_backups(self.app.journal_path)
        if backups:
            option_list.add_options(
                Option(os.path.basename(path), id=path) for path in backups
            )
        else:
            option_list.add_option(Option("No backups found.", disabled=True))

        path_input = self.query_one("#settings-restore-path-input", Input)
        path_input.value = ""
        self.query_one("#settings-restore-message", Label).update("")
        path_input.focus()

    def _show_main_section(self) -> None:
        self.query_one("#settings-restore", Vertical).add_class("hidden")
        self.query_one("#settings-title", Label).remove_class("hidden")
        self.query_one("#settings-main", Vertical).remove_class("hidden")

    def _hide_skip_backup_section(self) -> None:
        self.query_one("#settings-restore-skip-backup", Vertical).add_class("hidden")
        self._pending_restore_path = None
        self._pending_restore_data = None

    def _attempt_restore(self) -> None:
        self.app.record_action()
        path_input = self.query_one("#settings-restore-path-input", Input)
        message = self.query_one("#settings-restore-message", Label)

        raw_path = path_input.value.strip()
        if not raw_path:
            message.update("Enter a backup path or select one from the list above.")
            return
        path = os.path.abspath(os.path.expanduser(raw_path))

        try:
            data = journal_core.validate_backup_file(path)
        except ValueError as error:
            message.update(str(error))
            return

        message.update("")

        if os.path.exists(self.app.journal_path):
            try:
                journal_core.create_journal_backup(self.app.journal_path)
            except Exception as error:
                self._pending_restore_path = path
                self._pending_restore_data = data
                self.query_one(
                    "#settings-restore-skip-message", Label
                ).update(
                    "The current journal could not be backed up before "
                    f"restoring.\n\nDetails: {error}\n\nContinue anyway?"
                )
                self.query_one(
                    "#settings-restore-skip-backup", Vertical
                ).remove_class("hidden")
                return

        self._finish_restore(path, data)

    def _finish_restore(self, path: str, data) -> None:
        message = self.query_one("#settings-restore-message", Label)
        try:
            journal_core.save_json(self.app.journal_path, data, logger=logger)
        except Exception as error:
            message.update(f"Unable to restore the selected backup: {error}")
            return

        self._hide_skip_backup_section()
        self._return_to_list(f"Journal restored from:\n{path}")

    def action_close(self) -> None:
        self._return_to_list(None)

    def _return_to_list(self, message: str | None) -> None:
        self.app.pop_screen()
        list_screen = self.app.screen
        if isinstance(list_screen, EntryListScreen):
            list_screen.refresh_entries()
            if message is not None:
                list_screen._set_message(message)


class EntryListScreen(Screen):
    """Main navigation screen: a Tree of journal entries grouped by
    Year-Month, shown after a successful unlock.
    """

    BINDINGS = [
        Binding("n", "new_entry", "New"),
        Binding("v", "view_entry", "View"),
        Binding("d", "delete_entry", "Delete"),
        Binding("s", "settings", "Settings"),
        Binding("l", "lock", "Lock"),
        Binding("q", "quit_app", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="entrylist-dialog"):
            yield Label("", id="entrylist-days-status")
            yield Tree("Journal Entries", id="entrylist-tree")
            yield Label("", id="entrylist-message")
        yield Footer()

    def on_mount(self) -> None:
        tree = self.query_one("#entrylist-tree", Tree)
        tree.root.data = {"kind": "root"}
        tree.show_root = False
        self.refresh_entries()
        tree.focus()

    def refresh_entries(self) -> None:
        """Reload journal data from disk and repopulate the Tree.

        Adapted from SecureJournalApp.update_treeview's grouping/sort logic:
        group by date_str[:7] (YYYY-MM), sort groups and dates within each
        group descending (most recent first).
        """
        data = journal_core.load_json(self.app.journal_path, logger=logger)

        self.query_one("#entrylist-days-status", Label).update(
            journal_core.days_since_last_entry(data)
        )

        tree = self.query_one("#entrylist-tree", Tree)
        tree.clear()
        tree.root.data = {"kind": "root"}

        grouped_data = {}
        for entry in data:
            date_str = entry.get("date")
            if not date_str:
                continue
            year_month = date_str[:7]
            grouped_data.setdefault(year_month, []).append(date_str)

        sorted_year_months = sorted(
            grouped_data.keys(),
            key=lambda ym: datetime.strptime(ym, "%Y-%m"),
            reverse=True,
        )

        for year_month in sorted_year_months:
            dates = sorted(
                grouped_data[year_month],
                key=lambda date: datetime.strptime(date, "%Y-%m-%d"),
                reverse=True,
            )
            month_node = tree.root.add(
                year_month, data={"kind": "month"}, expand=False
            )
            for date_str in dates:
                month_node.add_leaf(
                    date_str, data={"kind": "date", "date": date_str}
                )

    def _set_message(self, text: str) -> None:
        self.query_one("#entrylist-message", Label).update(text)

    def action_new_entry(self) -> None:
        today = datetime.now().strftime("%Y-%m-%d")
        data = journal_core.load_json(self.app.journal_path, logger=logger)
        if journal_core.find_entry_by_date(data, today) is not None:
            # Overwrite guard: don't hand the user a blank editor that
            # would silently replace today's existing entry on save - open
            # that entry for editing instead, with a notice explaining why.
            self.app.push_screen(
                EntryViewScreen(
                    mode="view",
                    date=today,
                    notice=(
                        f"An entry already exists for {today} - opening it "
                        "for editing instead of starting blank. Press "
                        "ctrl+r to clear it if you want to start over."
                    ),
                )
            )
            return
        self.app.push_screen(EntryViewScreen(mode="new", date=today))

    def action_view_entry(self) -> None:
        self._view_node(self.query_one("#entrylist-tree", Tree).cursor_node)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        # Fired by Tree's own "enter" binding (Tree.BINDINGS binds enter to
        # select_cursor before it would reach this screen's own bindings).
        self._view_node(event.node)

    def _view_node(self, node) -> None:
        self.app.record_action()
        if node is None or node.data is None:
            return
        kind = node.data.get("kind")
        if kind == "month":
            self._set_message(
                "Select a dated journal entry, not a month heading."
            )
            return
        if kind != "date":
            return
        self._set_message("")
        self.app.push_screen(EntryViewScreen(mode="view", date=node.data["date"]))

    def action_delete_entry(self) -> None:
        self.app.record_action()
        node = self.query_one("#entrylist-tree", Tree).cursor_node
        if node is None or node.data is None:
            return
        kind = node.data.get("kind")
        if kind == "month":
            self._set_message("Please select a date to delete, not a month.")
            return
        if kind != "date":
            return
        self._set_message("")
        self.app.push_screen(
            DeleteConfirmScreen(date=node.data["date"]),
            self._handle_delete_result,
        )

    def _handle_delete_result(self, deleted: bool) -> None:
        if deleted:
            self.refresh_entries()
            self._set_message("Entry deleted.")

    def action_settings(self) -> None:
        self.app.record_action()
        self.app.push_screen(SettingsScreen())

    def action_lock(self) -> None:
        # Manual, on-demand lock - independent of the inactivity timer.
        self.app.lock_now()

    def action_quit_app(self) -> None:
        self.app.exit()


class UnlockScreen(Screen):
    """Prompts for the journal password and validates it against the
    first entry of the (already loaded) journal file.
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="unlock-dialog"):
            yield Label("Unlock your encrypted journal", id="unlock-title")
            yield Label(
                "Enter your journal password:", id="unlock-prompt"
            )
            yield Input(
                placeholder="Password", password=True, id="password-input"
            )
            if self.app.keyring_available:
                yield Checkbox(
                    "Remember password on this machine",
                    id="remember-checkbox",
                )
            yield Label("", id="unlock-error")
            yield Button("Unlock", id="unlock-submit", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        self.failed_attempts = 0

        if self.app.keyring_available:
            stored_password = journal_core.keyring_get_password(
                self.app.keyring_service,
                self.app.keyring_username,
                available=self.app.keyring_available,
                logger=logger,
            )
            if stored_password:
                self.query_one("#password-input", Input).value = stored_password
                self.query_one("#remember-checkbox", Checkbox).value = True

        self.query_one("#password-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "password-input":
            self.attempt_unlock()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "unlock-submit":
            self.attempt_unlock()

    def attempt_unlock(self) -> None:
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS:
            return

        password_input = self.query_one("#password-input", Input)
        error_label = self.query_one("#unlock-error", Label)
        typed_password = password_input.value

        data = journal_core.load_json(self.app.journal_path, logger=logger)

        if not data:
            # Brand-new/empty journal: nothing to validate against yet.
            self._unlock_success(typed_password, password_input)
            return

        first_entry = data[0].get("entry", "")
        try:
            journal_core.decrypt_message(first_entry, typed_password)
        except ValueError:
            self.failed_attempts += 1
            remaining = MAX_FAILED_ATTEMPTS - self.failed_attempts
            password_input.value = ""

            if remaining <= 0:
                error_label.update(
                    "Too many failed attempts. Locked for this session."
                )
                password_input.disabled = True
                self.query_one("#unlock-submit", Button).disabled = True
                if self.app.keyring_available:
                    self.query_one("#remember-checkbox", Checkbox).disabled = True
            else:
                attempt_word = "attempt" if remaining == 1 else "attempts"
                error_label.update(
                    f"Incorrect password. {remaining} {attempt_word} remaining."
                )
                password_input.focus()
            return

        self._unlock_success(typed_password, password_input)

    def _unlock_success(self, typed_password: str, password_input: Input) -> None:
        # Store the password as a bytearray, never a lingering bare str.
        self.app.password = bytearray(typed_password, "utf-8")

        if self.app.keyring_available:
            remember_checkbox = self.query_one("#remember-checkbox", Checkbox)
            if remember_checkbox.value:
                journal_core.keyring_set_password(
                    self.app.keyring_service,
                    self.app.keyring_username,
                    typed_password,
                    available=self.app.keyring_available,
                    logger=logger,
                )

        password_input.value = ""
        typed_password = None  # drop our only other reference to the str

        self.app.record_action()

        # switch_screen (not push_screen): this UnlockScreen may itself be
        # the result of a previous lock_now()/switch_screen, so pushing
        # here would grow the screen stack by one every lock/unlock cycle.
        # Replacing the current top keeps the stack depth constant.
        self.app.switch_screen(EntryListScreen())


class JournalApp(App):
    """App shell for the Encrypted Journal TUI.

    Owns the in-memory session password and the inactivity-based session
    lock: a `set_interval` timer compares elapsed time since
    `last_action_time` against `lock_seconds` and wipes the password on
    expiry. Expiry only wipes the password - it never navigates screens,
    so whichever screen the user is on (including a mid-edit
    EntryViewScreen) keeps working; the next action that needs the
    password re-prompts for it in place. The manual `l` key
    (EntryListScreen.action_lock -> lock_now()) is the only path that
    actually returns the user to UnlockScreen.
    """

    CSS_PATH = "journal_tui.tcss"
    TITLE = "Encrypted Journal"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.journal_path = journal_core.resolve_journal_path()

        # In-memory password: only ever a bytearray, never a persisted str.
        self.password: bytearray | None = None

        # Session lock: threshold (seconds of inactivity before the
        # password is auto-wiped) and the clock it's measured against.
        # Clamped to a minimum of 1s: env_int (like env_bool) is permissive
        # by design and won't reject 0/negative values itself, but a
        # non-positive threshold here would re-lock the session immediately
        # after every action, making the app unusable.
        self.lock_seconds = max(
            1,
            journal_core.env_int(
                "ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS", DEFAULT_LOCK_SECONDS
            ),
        )
        self.last_action_time = datetime.now()

        self.keyring_service = "encrypted-journal"
        self.keyring_username = os.environ.get(
            "ENCRYPTED_JOURNAL_KEYRING_USER", getpass.getuser() or "default"
        )
        self.keyring_enabled = journal_core.env_bool(
            "ENCRYPTED_JOURNAL_USE_KEYRING", False
        )
        # Mirrors SecureJournalApp: available only if the keyring package
        # actually imported AND the user opted in via env var.
        self.keyring_available = (
            journal_core.keyring is not None and self.keyring_enabled
        )

        # Name of the currently-applied Omarchy-derived theme (if any), so
        # _apply_omarchy_theme can tell an unchanged poll apart from an
        # actual theme switch. None if no Omarchy theme has been applied
        # yet (including "Omarchy isn't present on this machine").
        self._omarchy_theme_name: str | None = None

    def on_mount(self) -> None:
        self._apply_omarchy_theme()
        self.push_screen(UnlockScreen())
        self.set_interval(SESSION_LOCK_CHECK_INTERVAL, self._check_session_lock)
        self.set_interval(OMARCHY_THEME_POLL_INTERVAL, self._apply_omarchy_theme)

    def _apply_omarchy_theme(self) -> None:
        """Best-effort: load the current Omarchy colors.toml and, if it
        parses and names a theme different from whichever Omarchy theme (if
        any) is currently applied, register and switch to it live. No-ops
        otherwise, leaving whichever theme is already active - an earlier
        Omarchy theme, or Textual's own default if Omarchy isn't present or
        its files are unreadable/malformed.

        Called once at startup and then every OMARCHY_THEME_POLL_INTERVAL
        seconds via set_interval, so a theme switch made on this machine
        while the app is running is picked up within a few seconds, with no
        restart and no manual reload keybinding needed. omarchy_theme.
        load_omarchy_theme() never raises, so this method needs no
        try/except of its own.
        """
        theme = omarchy_theme.load_omarchy_theme()
        if theme is None or theme.name == self._omarchy_theme_name:
            return
        previous_name = self._omarchy_theme_name
        self.register_theme(theme)
        self.theme = theme.name
        self._omarchy_theme_name = theme.name
        if previous_name is not None:
            self.unregister_theme(previous_name)

    def record_action(self) -> None:
        """Reset the inactivity clock. Screens call this from any action
        that counts as user activity (viewing, saving, deleting an entry)
        rather than reaching into `last_action_time` directly."""
        self.last_action_time = datetime.now()

    def _check_session_lock(self) -> None:
        if self.password is None:
            return  # already locked - nothing to do (idempotent-safe)
        elapsed = (datetime.now() - self.last_action_time).total_seconds()
        if elapsed >= self.lock_seconds:
            self._wipe_password()

    def lock_now(self) -> None:
        """Manual, on-demand lock (the `l` key): wipe the password and
        return to UnlockScreen, independent of the inactivity timer.

        Uses switch_screen rather than push_screen so repeated lock/unlock
        cycles don't grow the screen stack unboundedly.
        """
        self._wipe_password()
        self.switch_screen(UnlockScreen())

    def on_unmount(self) -> None:
        self._wipe_password()

    def _wipe_password(self) -> None:
        if self.password is not None:
            for i in range(len(self.password)):
                self.password[i] = 0
            self.password = None


if __name__ == "__main__":
    JournalApp().run()
