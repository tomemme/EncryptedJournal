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

from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Button, Checkbox, Footer, Header, Input, Label

import journal_core

logger = logging.getLogger("journal_tui")

MAX_FAILED_ATTEMPTS = 5  # matches SecureJournalApp.max_attempts in secure_journal.py


class UnlockedPlaceholderScreen(Screen):
    """Placeholder shown after a successful unlock.

    Task 5 replaces this with the real EntryListScreen. It exists only so
    unlock-success is observably distinguishable from unlock-failure (the
    app is no longer on UnlockScreen).
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Vertical(id="unlocked-dialog"):
            yield Label("Journal unlocked.", id="unlocked-message")
            yield Label(
                "Entry list UI arrives in Task 5.", id="unlocked-submessage"
            )
        yield Footer()


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

        self.app.push_screen(UnlockedPlaceholderScreen())


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
