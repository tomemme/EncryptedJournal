#!/usr/bin/env python3
"""
Encrypted Journal - TUI smoke test.

Headless end-to-end smoke test for journal_tui.py, driven via Textual's
App.run_test()/Pilot (no Xvfb or real TTY needed). Exercises the full
unlock -> create -> save -> reload -> delete -> quit flow against a
tempdir journal, and cross-checks on-disk state via journal_core
directly rather than trusting UI state alone.
"""

import asyncio
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


async def _run(journal_path):
    import journal_core
    import journal_tui
    from journal_tui import EntryListScreen, EntryViewScreen, JournalApp, UnlockScreen

    # journal_tui's module-level logger must have a real handler attached
    # (via journal_core.configure_rotating_logger) rather than relying on
    # logging.lastResort's raw-stderr fallback, which would corrupt the
    # live Textual frame.
    _assert(
        len(journal_tui.logger.handlers) > 0,
        "journal_tui.logger should have at least one handler attached.",
    )

    entry_date = "2026-03-14"
    entry_body = "Smoke test entry body, typed via the TUI."

    app = JournalApp()
    async with app.run_test() as pilot:
        # 1. Unlock a brand-new/empty journal - attempt_unlock() succeeds
        # unconditionally when there's no existing data to validate against.
        _assert(
            isinstance(app.screen, UnlockScreen),
            f"Expected UnlockScreen on mount, got {type(app.screen).__name__}.",
        )
        password_input = app.screen.query_one("#password-input")
        password_input.value = "smoke-test-password"
        await pilot.press("enter")
        await pilot.pause()
        _assert(
            isinstance(app.screen, EntryListScreen),
            f"Unlock did not reach EntryListScreen, got {type(app.screen).__name__}.",
        )
        _assert(app.password is not None, "App password should be set after unlock.")

        # 2. Create: press 'n', type a body + date, then ctrl+s to save.
        await pilot.press("n")
        await pilot.pause()
        _assert(
            isinstance(app.screen, EntryViewScreen),
            f"'n' did not open EntryViewScreen, got {type(app.screen).__name__}.",
        )
        view_screen = app.screen
        _assert(view_screen.mode == "new", "Expected 'new' mode EntryViewScreen.")
        view_screen.query_one("#entryview-date-input").value = entry_date
        view_screen.query_one("#entryview-body").text = entry_body

        await pilot.press("ctrl+s")
        await pilot.pause()
        _assert(
            isinstance(app.screen, EntryListScreen),
            "Save (ctrl+s) did not return to EntryListScreen.",
        )

        # 3. Verify on-disk (not just UI state): reload the raw file and
        # decrypt independently of anything journal_tui.py did in-process.
        on_disk_after_save = journal_core.load_json(journal_path)
        saved_entry = next(
            (e for e in on_disk_after_save if e.get("date") == entry_date), None
        )
        _assert(
            saved_entry is not None,
            f"No on-disk entry found for {entry_date} after save.",
        )
        decrypted_after_save = journal_core.decrypt_message(
            saved_entry["entry"], app.password
        )
        _assert(
            decrypted_after_save == entry_body,
            "On-disk decrypted body did not match what was typed: "
            f"expected {entry_body!r}, got {decrypted_after_save!r}.",
        )

        # 4. Reload through the UI: locate the entry's tree node and select
        # it via the Tree's own select_node() (posts a real NodeSelected
        # message through the message pump, same as pressing enter/'v'
        # would), then assert the screen that opens shows the saved body.
        list_screen = app.screen
        tree = list_screen.query_one("#entrylist-tree")
        date_node = None
        for month_node in tree.root.children:
            for leaf in month_node.children:
                if leaf.data and leaf.data.get("date") == entry_date:
                    date_node = leaf
        _assert(date_node is not None, "Saved entry's date node not found in tree.")

        tree.select_node(date_node)
        await pilot.pause()
        _assert(
            isinstance(app.screen, EntryViewScreen),
            "Selecting the entry's tree node did not open EntryViewScreen.",
        )
        _assert(app.screen.mode == "view", "Expected 'view' mode EntryViewScreen.")
        displayed_body = app.screen.query_one("#entryview-body").text
        _assert(
            displayed_body == entry_body,
            "Displayed body after reload did not match what was saved: "
            f"expected {entry_body!r}, got {displayed_body!r}.",
        )

        # Back to the list to drive deletion.
        await pilot.press("escape")
        await pilot.pause()
        _assert(
            isinstance(app.screen, EntryListScreen),
            "Escape did not return to EntryListScreen.",
        )

        # 5. Delete: select the entry again, trigger delete, confirm Yes.
        list_screen = app.screen
        tree = list_screen.query_one("#entrylist-tree")
        date_node = None
        for month_node in tree.root.children:
            for leaf in month_node.children:
                if leaf.data and leaf.data.get("date") == entry_date:
                    date_node = leaf
        _assert(date_node is not None, "Entry's date node not found before delete.")
        # The month node starts collapsed (refresh_entries() adds it with
        # expand=False); move_cursor() resolves via the node's rendered
        # line index, so the parent must be expanded first for cursor_node
        # to actually land on the date leaf rather than the month header.
        date_node.parent.expand()
        await pilot.pause()
        tree.move_cursor(date_node)
        await pilot.pause()

        await pilot.press("d")
        await pilot.pause()
        delete_screen = app.screen
        _assert(
            type(delete_screen).__name__ == "DeleteConfirmScreen",
            f"'d' did not open DeleteConfirmScreen, got {type(delete_screen).__name__}.",
        )

        await pilot.click("#delete-confirm-yes")
        await pilot.pause()

        # 6. Confirm on-disk the entry is gone.
        on_disk_after_delete = journal_core.load_json(journal_path)
        _assert(
            all(e.get("date") != entry_date for e in on_disk_after_delete),
            "Entry still present on-disk after delete.",
        )
        _assert(
            isinstance(app.screen, EntryListScreen),
            "App should be back on EntryListScreen after delete confirmation.",
        )

        # 7. Quit cleanly.
        await pilot.press("q")
        await pilot.pause()
        _assert(not app.is_running, "App should have exited after 'q'.")


async def _run_session_lock_scenario(journal_path):
    """Session-lock reprompt-and-resume scenario (Task 8).

    By the time `_run()` above finishes, the journal at `journal_path` has
    had its one entry deleted again, so it is empty on disk here - a fresh
    JournalApp() unlocks it the same "nothing to validate against yet" way
    UnlockScreen.attempt_unlock() handles any brand-new journal.

    Runs in its own run_test() block (a second JournalApp instance) with
    ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS=1 so the inactivity timer fires
    quickly and deterministically, independent of the default 300s
    threshold `_run()` relies on staying stable throughout its own flow.
    """
    import journal_core
    from journal_tui import EntryListScreen, EntryViewScreen, JournalApp, UnlockScreen

    entry_date = "2026-05-01"
    entry_body = "Session-lock reprompt scenario body."
    password = "smoke-test-password"

    original_lock_seconds = os.environ.get("ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS")
    os.environ["ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS"] = "1"
    try:
        app = JournalApp()
        async with app.run_test() as pilot:
            _assert(
                app.lock_seconds == 1,
                f"Expected lock_seconds == 1 from the env override, got {app.lock_seconds}.",
            )

            # Unlock the (now-empty) journal.
            _assert(
                isinstance(app.screen, UnlockScreen),
                f"Expected UnlockScreen on mount, got {type(app.screen).__name__}.",
            )
            password_input = app.screen.query_one("#password-input")
            password_input.value = password
            await pilot.press("enter")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                f"Unlock did not reach EntryListScreen, got {type(app.screen).__name__}.",
            )

            # Start a new entry and fill it in, but don't save yet.
            await pilot.press("n")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryViewScreen),
                f"'n' did not open EntryViewScreen, got {type(app.screen).__name__}.",
            )
            view_screen = app.screen
            view_screen.query_one("#entryview-date-input").value = entry_date
            view_screen.query_one("#entryview-body").text = entry_body

            # Wait past the 1s inactivity threshold so the session-lock
            # timer fires and wipes app.password before we try to save.
            await asyncio.sleep(1.5)
            _assert(
                app.password is None,
                "Session lock should have wiped app.password once the "
                "inactivity threshold elapsed.",
            )

            # Trigger the save. Since app.password is now None, this must
            # show the in-place password reprompt rather than crash or
            # silently drop the edit.
            await pilot.press("ctrl+s")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryViewScreen),
                "Should still be on EntryViewScreen for the in-place reprompt "
                f"after a locked ctrl+s, got {type(app.screen).__name__}.",
            )
            reprompt = view_screen.query_one("#entryview-reprompt")
            _assert(
                "hidden" not in reprompt.classes,
                "Password reprompt should be visible after a session-lock "
                "expiry on save, but it's still hidden.",
            )

            # Submit the correct password to resume the deferred save.
            reprompt_password = view_screen.query_one(
                "#entryview-reprompt-password"
            )
            reprompt_password.value = password
            await pilot.press("enter")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                "Reprompt-and-resume did not complete the save and return "
                f"to EntryListScreen, got {type(app.screen).__name__}.",
            )

        # Verify on-disk, independent of in-process state: the save that
        # resumed after reprompt must have actually written and be
        # decryptable with the (correct) re-entered password.
        on_disk = journal_core.load_json(journal_path)
        saved_entry = next(
            (e for e in on_disk if e.get("date") == entry_date), None
        )
        _assert(
            saved_entry is not None,
            f"No on-disk entry found for {entry_date} after lock-reprompt save.",
        )
        decrypted = journal_core.decrypt_message(
            saved_entry["entry"], bytearray(password, "utf-8")
        )
        _assert(
            decrypted == entry_body,
            "On-disk decrypted body after lock-reprompt save did not match "
            f"what was typed: expected {entry_body!r}, got {decrypted!r}.",
        )
    finally:
        if original_lock_seconds is not None:
            os.environ["ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS"] = original_lock_seconds
        else:
            os.environ.pop("ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS", None)


async def _run_overwrite_guard_scenario(temp_dir):
    """Overwrite guard: pressing 'n' for a date that already has an entry
    should open that entry for editing (not a blank editor) with a notice,
    ctrl+r should clear just the body text, and saving afterward should
    update (not duplicate) that date's on-disk entry.

    Uses its own journal file (via the ENCRYPTED_JOURNAL_FILE override,
    saved/restored) rather than sharing `journal_path` with `_run`/
    `_run_session_lock_scenario`, since this scenario specifically needs
    control over what's on disk for *today's* date.
    """
    import journal_core
    from journal_tui import EntryListScreen, EntryViewScreen, JournalApp, UnlockScreen

    today = datetime.now().strftime("%Y-%m-%d")
    original_body = "Original entry for today, written first."
    replacement_body = "Replaced after Clear."
    password = "smoke-test-password"
    journal_path = os.path.join(temp_dir, "overwrite-guard-journal.json.gz")

    original_journal_file = os.environ.get("ENCRYPTED_JOURNAL_FILE")
    os.environ["ENCRYPTED_JOURNAL_FILE"] = journal_path
    try:
        app = JournalApp()
        async with app.run_test() as pilot:
            _assert(
                isinstance(app.screen, UnlockScreen),
                f"Expected UnlockScreen on mount, got {type(app.screen).__name__}.",
            )
            password_input = app.screen.query_one("#password-input")
            password_input.value = password
            await pilot.press("enter")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                f"Unlock did not reach EntryListScreen, got {type(app.screen).__name__}.",
            )

            # Save an entry for today via the normal blank 'n' -> ctrl+s path.
            await pilot.press("n")
            await pilot.pause()
            view_screen = app.screen
            _assert(
                isinstance(view_screen, EntryViewScreen) and view_screen.mode == "new",
                "First 'n' press (no existing entry yet) should open a blank new entry.",
            )
            view_screen.query_one("#entryview-body").text = original_body
            await pilot.press("ctrl+s")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                "Save did not return to EntryListScreen.",
            )

            # Press 'n' again: today's entry already exists, so this should
            # open it for editing (mode="view") with a notice, not a blank
            # editor.
            await pilot.press("n")
            await pilot.pause()
            guarded_screen = app.screen
            _assert(
                isinstance(guarded_screen, EntryViewScreen)
                and guarded_screen.mode == "view",
                "'n' with an existing entry for today should open it in "
                f"'view' mode, got mode={getattr(guarded_screen, 'mode', None)!r}.",
            )
            _assert(
                guarded_screen.date == today,
                f"Expected the guarded screen's date to be {today}, "
                f"got {guarded_screen.date}.",
            )
            body_widget = guarded_screen.query_one("#entryview-body")
            _assert(
                body_widget.text == original_body,
                "Overwrite guard should have loaded the existing entry's "
                f"body, got {body_widget.text!r}.",
            )
            message_text = str(guarded_screen.query_one("#entryview-message").content)
            _assert(
                "already exists" in message_text,
                f"Expected an overwrite-guard notice message, got {message_text!r}.",
            )

            # ctrl+r clears the body text only, leaving the date untouched.
            await pilot.press("ctrl+r")
            await pilot.pause()
            _assert(
                body_widget.text == "",
                "ctrl+r (Clear) should empty the entry body.",
            )
            date_widget = guarded_screen.query_one("#entryview-date-input")
            _assert(
                date_widget.value == today,
                "ctrl+r (Clear) should not touch the date field.",
            )

            # Typing fresh content and saving should update (not duplicate)
            # the same date's entry.
            body_widget.text = replacement_body
            await pilot.press("ctrl+s")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                "Save after Clear did not return to EntryListScreen.",
            )

        on_disk = journal_core.load_json(journal_path)
        matching = [e for e in on_disk if e.get("date") == today]
        _assert(
            len(matching) == 1,
            f"Expected exactly one on-disk entry for {today}, got {len(matching)}.",
        )
        decrypted = journal_core.decrypt_message(
            matching[0]["entry"], bytearray(password, "utf-8")
        )
        _assert(
            decrypted == replacement_body,
            "On-disk entry after the guard+clear+save flow did not match "
            f"the replacement body: expected {replacement_body!r}, got {decrypted!r}.",
        )
    finally:
        if original_journal_file is not None:
            os.environ["ENCRYPTED_JOURNAL_FILE"] = original_journal_file
        else:
            os.environ.pop("ENCRYPTED_JOURNAL_FILE", None)


async def _run_backup_restore_scenario(temp_dir):
    """Backup + restore via SettingsScreen (Task: TUI backup/restore).

    Specifically exercises restoring from an arbitrary external path (typed
    into the Input, not selected from the in-folder backup list) - the
    actual gap this feature closes: a backup living anywhere on disk can be
    restored directly, with no manual copy into the journal's own folder
    first.

    Uses its own journal file (like the overwrite-guard scenario) since it
    needs full control over on-disk state and an isolated backup directory.
    """
    import journal_core
    from journal_tui import EntryListScreen, JournalApp, SettingsScreen, UnlockScreen

    password = "smoke-test-password"
    entry_date = "2026-06-01"
    entry_body = "Backup/restore scenario body."
    journal_path = os.path.join(temp_dir, "backup-restore-journal.json.gz")
    external_backup_path = os.path.join(temp_dir, "external", "manual-copy.bak")

    original_journal_file = os.environ.get("ENCRYPTED_JOURNAL_FILE")
    os.environ["ENCRYPTED_JOURNAL_FILE"] = journal_path
    try:
        app = JournalApp()
        async with app.run_test() as pilot:
            password_input = app.screen.query_one("#password-input")
            password_input.value = password
            await pilot.press("enter")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                f"Unlock did not reach EntryListScreen, got {type(app.screen).__name__}.",
            )

            # Seed one entry, then create a backup of it via SettingsScreen.
            await pilot.press("n")
            await pilot.pause()
            app.screen.query_one("#entryview-date-input").value = entry_date
            app.screen.query_one("#entryview-body").text = entry_body
            await pilot.press("ctrl+s")
            await pilot.pause()

            await pilot.press("s")
            await pilot.pause()
            _assert(
                isinstance(app.screen, SettingsScreen),
                f"'s' did not open SettingsScreen, got {type(app.screen).__name__}.",
            )
            settings_screen = app.screen
            await pilot.click("#settings-backup-btn")
            await pilot.pause()
            backup_message = str(settings_screen.query_one("#settings-message").content)
            _assert(
                "Backup created at" in backup_message,
                f"Expected a backup-created message, got {backup_message!r}.",
            )
            backups = journal_core.list_journal_backups(journal_path)
            _assert(len(backups) == 1, f"Expected exactly one backup, found {backups}.")
            backup_path = backups[0]

            # Copy that backup out to an external location and delete it
            # from the journal's own backup folder, so the only way to
            # restore it is via the arbitrary-path Input, not the in-folder
            # OptionList.
            os.makedirs(os.path.dirname(external_backup_path), exist_ok=True)
            with open(backup_path, "rb") as src, open(external_backup_path, "wb") as dst:
                dst.write(src.read())
            os.remove(backup_path)
            _assert(
                journal_core.list_journal_backups(journal_path) == [],
                "Expected no backups left in the journal's own folder.",
            )

            # Delete the entry so restoring it back is observable.
            journal_core.save_json(journal_path, [])
            _assert(
                journal_core.load_json(journal_path) == [],
                "Expected the journal to be empty before restore.",
            )

            await pilot.click("#settings-restore-btn")
            await pilot.pause()
            option_list = settings_screen.query_one("#settings-restore-list")
            _assert(
                option_list.option_count == 1
                and str(option_list.get_option_at_index(0).prompt) == "No backups found.",
                "Expected the in-folder backup list to be empty after the "
                f"backup was moved out, got option_count={option_list.option_count}.",
            )

            # First, confirm an invalid path is rejected with an inline
            # error and does not touch the on-disk journal.
            path_input = settings_screen.query_one("#settings-restore-path-input")
            path_input.value = os.path.join(temp_dir, "does-not-exist.bak")
            await pilot.click("#settings-restore-submit")
            await pilot.pause()
            _assert(
                isinstance(app.screen, SettingsScreen),
                "An invalid restore path should not navigate away from SettingsScreen.",
            )
            restore_message = str(
                settings_screen.query_one("#settings-restore-message").content
            )
            _assert(
                "not a valid journal backup file" in restore_message,
                f"Expected an invalid-backup error message, got {restore_message!r}.",
            )
            _assert(
                journal_core.load_json(journal_path) == [],
                "A failed restore attempt should not have touched the on-disk journal.",
            )

            # Now restore from the real external path (arbitrary location,
            # never placed in the journal's own backup folder). A real-time
            # pause (not just pilot.pause()'s message-queue drain) is needed
            # first: Button.press() applies a 0.2s "-active" class and
            # Button._on_click() ignores a click that lands while it's
            # still set, so clicking the same button twice in quick
            # succession would otherwise silently drop the second click.
            path_input.value = external_backup_path
            await asyncio.sleep(0.25)
            await pilot.click("#settings-restore-submit")
            await pilot.pause()
            _assert(
                isinstance(app.screen, EntryListScreen),
                "A successful restore should return to EntryListScreen, got "
                f"{type(app.screen).__name__}.",
            )
            list_message = str(app.screen.query_one("#entrylist-message").content)
            _assert(
                "restored from" in list_message.lower(),
                f"Expected a restore-complete message, got {list_message!r}.",
            )

        # Verify on-disk: the deleted entry is back, decryptable with the
        # original password, and restoring made its own pre-restore safety
        # backup of the (empty) journal that was in place before restore.
        restored_data = journal_core.load_json(journal_path)
        restored_entry = next(
            (e for e in restored_data if e.get("date") == entry_date), None
        )
        _assert(
            restored_entry is not None,
            f"No on-disk entry found for {entry_date} after restore.",
        )
        decrypted = journal_core.decrypt_message(
            restored_entry["entry"], bytearray(password, "utf-8")
        )
        _assert(
            decrypted == entry_body,
            "On-disk decrypted body after restore did not match the original: "
            f"expected {entry_body!r}, got {decrypted!r}.",
        )
        _assert(
            len(journal_core.list_journal_backups(journal_path)) == 1,
            "Expected one safety backup (of the pre-restore empty journal) "
            "to have been created during restore.",
        )
    finally:
        if original_journal_file is not None:
            os.environ["ENCRYPTED_JOURNAL_FILE"] = original_journal_file
        else:
            os.environ.pop("ENCRYPTED_JOURNAL_FILE", None)


OMARCHY_FIXTURE_COLORS_TOML = """
mode = "dark"
accent = "#509475"
background = "#111c18"
foreground = "#C1C497"
bright_yellow = "#E5C736"
bright_red = "#db9f9c"
bright_green = "#63b07a"
bright_magenta = "#75bbb3"
"""


async def _run_omarchy_theme_scenario(temp_dir):
    """Omarchy theme integration: app.theme reflects a fixture colors.toml
    when the ENCRYPTED_JOURNAL_OMARCHY_*_PATH overrides point at one, and
    falls back to Textual's own default theme when they don't (no Omarchy
    present).
    """
    from journal_tui import JournalApp

    colors_path = os.path.join(temp_dir, "omarchy-colors.toml")
    name_path = os.path.join(temp_dir, "omarchy-theme.name")
    with open(colors_path, "w", encoding="utf-8") as f:
        f.write(OMARCHY_FIXTURE_COLORS_TOML)
    with open(name_path, "w", encoding="utf-8") as f:
        f.write("fixture-theme")

    original_colors_path = os.environ.get("ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH")
    original_name_path = os.environ.get("ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH")
    try:
        # Case 1: fixture present -> app picks it up at startup.
        os.environ["ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH"] = colors_path
        os.environ["ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH"] = name_path

        app = JournalApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            _assert(
                app.theme == "omarchy-fixture-theme",
                f"Expected app.theme == 'omarchy-fixture-theme', got {app.theme!r}.",
            )
            applied = app.get_theme(app.theme)
            _assert(
                applied.primary == "#509475",
                f"Expected applied theme primary #509475, got {applied.primary}.",
            )

        # Case 2: no Omarchy present -> app keeps Textual's own default.
        missing_path = os.path.join(temp_dir, "does-not-exist.toml")
        os.environ["ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH"] = missing_path

        app = JournalApp()
        async with app.run_test() as pilot:
            await pilot.pause()
            _assert(
                not app.theme.startswith("omarchy-"),
                "Expected Textual's own default theme when Omarchy colors.toml "
                f"is missing, got {app.theme!r}.",
            )
    finally:
        if original_colors_path is not None:
            os.environ["ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH"] = original_colors_path
        else:
            os.environ.pop("ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH", None)
        if original_name_path is not None:
            os.environ["ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH"] = original_name_path
        else:
            os.environ.pop("ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH", None)


def main():
    with tempfile.TemporaryDirectory(prefix="tui-smoke-") as temp_dir:
        journal_path = os.path.join(temp_dir, "journal.json.gz")

        original_journal_file = os.environ.get("ENCRYPTED_JOURNAL_FILE")
        original_use_keyring = os.environ.get("ENCRYPTED_JOURNAL_USE_KEYRING")
        original_lock_seconds = os.environ.get("ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS")
        try:
            os.environ["ENCRYPTED_JOURNAL_FILE"] = journal_path
            os.environ.pop("ENCRYPTED_JOURNAL_USE_KEYRING", None)
            os.environ.pop("ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS", None)

            asyncio.run(_run(journal_path))
            asyncio.run(_run_session_lock_scenario(journal_path))
            asyncio.run(_run_overwrite_guard_scenario(temp_dir))
            asyncio.run(_run_backup_restore_scenario(temp_dir))
            asyncio.run(_run_omarchy_theme_scenario(temp_dir))

            print("PASS: TUI smoke test completed successfully.")
            return 0
        except Exception as error:
            print(f"FAIL: TUI smoke test failed: {error}")
            return 1
        finally:
            if original_journal_file is not None:
                os.environ["ENCRYPTED_JOURNAL_FILE"] = original_journal_file
            else:
                os.environ.pop("ENCRYPTED_JOURNAL_FILE", None)
            if original_use_keyring is not None:
                os.environ["ENCRYPTED_JOURNAL_USE_KEYRING"] = original_use_keyring
            else:
                os.environ.pop("ENCRYPTED_JOURNAL_USE_KEYRING", None)
            if original_lock_seconds is not None:
                os.environ["ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS"] = original_lock_seconds
            else:
                os.environ.pop("ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS", None)


if __name__ == "__main__":
    raise SystemExit(main())
