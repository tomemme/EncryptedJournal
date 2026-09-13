#!/usr/bin/env python3
"""
Encrypted Journal - Textual TUI frontend.

Standalone script, independent of secure_journal.py (the Tkinter GUI).
Must never import tkinter or secure_journal, directly or transitively -
only journal_core plus Textual, so it stays usable headless / over SSH.
"""

import getpass
import logging
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
    TextArea,
    Tree,
)

import journal_core

logger = logging.getLogger("journal_tui")

MAX_FAILED_ATTEMPTS = 5  # matches SecureJournalApp.max_attempts in secure_journal.py


class EntryViewScreen(Screen):
    """Create/view/edit a single journal entry.

    Two modes land on this same screen:
    - "new": empty body, date pre-filled to today.
    - "view": body decrypted from the on-disk entry for `date` and
      populated; date pre-filled to that date. If decryption fails (e.g. a
      stale in-memory app.password), falls back to an in-place password
      re-prompt instead of crashing or showing garbage.

    ctrl+s saves (matching SecureJournalApp.save_journal_entry's exact
    validation/error strings and update-or-append-by-date logic); escape
    discards and returns to EntryListScreen unsaved.
    """

    BINDINGS = [
        Binding("ctrl+s", "save_entry", "Save"),
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, *, mode: str, date: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.mode = mode
        self.date = date
        self._encrypted_entry_text: str | None = None

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
        entry = next(
            (e for e in data if e.get("date") == self.date), None
        )
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
            self._show_password_reprompt(
                "Could not decrypt this entry with the current password. "
                "Enter the correct password to continue."
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
        try:
            plaintext = journal_core.decrypt_message(
                self._encrypted_entry_text, candidate
            )
        except ValueError:
            for i in range(len(candidate)):
                candidate[i] = 0
            self.query_one("#entryview-reprompt-message", Label).update(
                "Incorrect password. Try again."
            )
            self.query_one("#entryview-reprompt-password", Input).value = ""
            return
        # Correct password: adopt it as the app's current session password.
        self.app._wipe_password()
        self.app.password = candidate
        self.query_one("#entryview-body", TextArea).text = plaintext
        self._show_editor()

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
    password BEFORE the Yes/No prompt is shown. If that decryption fails,
    the Yes/No prompt is never shown - only an inline error with a way to
    dismiss, so a password already known to be wrong never reaches the
    confirmation step.

    Dismisses with True only if the entry was actually deleted from disk;
    False for No, Escape, a missing entry, a decrypt failure, or a save
    failure.
    """

    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
    ]

    def __init__(self, *, date: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.date = date

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

    def on_mount(self) -> None:
        data = journal_core.load_json(self.app.journal_path, logger=logger)
        entry = next((e for e in data if e.get("date") == self.date), None)

        if entry is None:
            self._show_error(f"No entry found for {self.date}.")
            return

        try:
            journal_core.decrypt_message(entry.get("entry", ""), self.app.password)
        except ValueError:
            self._show_error(
                "Could not decrypt this entry with the current password. "
                "Delete cancelled."
            )
            return

        self.query_one("#delete-confirm-yes", Button).focus()

    def _show_error(self, message: str) -> None:
        self.query_one("#delete-confirm-prompt", Vertical).add_class("hidden")
        self.query_one("#delete-confirm-error", Vertical).remove_class("hidden")
        self.query_one("#delete-confirm-error-message", Label).update(message)
        self.query_one("#delete-confirm-ok", Button).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "delete-confirm-yes":
            self._do_delete()
        elif event.button.id in ("delete-confirm-no", "delete-confirm-ok"):
            self.dismiss(False)

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


class EntryListScreen(Screen):
    """Main navigation screen: a Tree of journal entries grouped by
    Year-Month, shown after a successful unlock.
    """

    BINDINGS = [
        Binding("n", "new_entry", "New"),
        Binding("v", "view_entry", "View"),
        Binding("d", "delete_entry", "Delete"),
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
        self.app.push_screen(EntryViewScreen(mode="new", date=today))

    def action_view_entry(self) -> None:
        self._view_node(self.query_one("#entrylist-tree", Tree).cursor_node)

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        # Fired by Tree's own "enter" binding (Tree.BINDINGS binds enter to
        # select_cursor before it would reach this screen's own bindings).
        self._view_node(event.node)

    def _view_node(self, node) -> None:
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

    def action_lock(self) -> None:
        # TODO(Task 8): replace with the full timer-based session lock.
        self.app._wipe_password()
        self.app.push_screen(UnlockScreen())

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

        self.app.push_screen(EntryListScreen())


class JournalApp(App):
    """App shell for the Encrypted Journal TUI."""

    CSS_PATH = "journal_tui.tcss"
    TITLE = "Encrypted Journal"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.journal_path = journal_core.resolve_journal_path()

        # In-memory password: only ever a bytearray, never a persisted str.
        self.password: bytearray | None = None

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

    def on_mount(self) -> None:
        self.push_screen(UnlockScreen())

    def on_unmount(self) -> None:
        self._wipe_password()

    def _wipe_password(self) -> None:
        if self.password is not None:
            for i in range(len(self.password)):
                self.password[i] = 0
            self.password = None


if __name__ == "__main__":
    JournalApp().run()
