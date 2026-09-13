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
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Label, Tree

import journal_core

logger = logging.getLogger("journal_tui")

MAX_FAILED_ATTEMPTS = 5  # matches SecureJournalApp.max_attempts in secure_journal.py


class EntryViewPlaceholderScreen(Screen):
    """Placeholder shown when opening a specific entry (new or existing).

    Task 6 replaces this with the real EntryViewScreen. It exists only so
    n/enter/v navigation out of EntryListScreen is observably distinguishable
    ahead of Task 6 building the real editor/viewer.
    """

    BINDINGS = [Binding("escape", "back", "Back")]

    def __init__(self, *, mode: str, date: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self.mode = mode
        self.date = date

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="entryview-placeholder-dialog"):
            yield Label(
                f"Entry view ({self.mode}): {self.date}",
                id="entryview-placeholder-message",
            )
            yield Label(
                "Entry editor/viewer arrives in Task 6.",
                id="entryview-placeholder-submessage",
            )
        yield Footer()

    def action_back(self) -> None:
        self.app.pop_screen()


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
        self.app.push_screen(
            EntryViewPlaceholderScreen(mode="new", date=today)
        )

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
        self.app.push_screen(
            EntryViewPlaceholderScreen(mode="view", date=node.data["date"])
        )

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
        # TODO(Task 7): replace with the real delete-confirmation modal.
        self._set_message(
            f"Delete requested for {node.data['date']} "
            "(confirmation dialog arrives in Task 7)."
        )

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
