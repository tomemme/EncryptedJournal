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
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


async def _run(journal_path):
    import journal_core
    from journal_tui import EntryListScreen, EntryViewScreen, JournalApp, UnlockScreen

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


def main():
    with tempfile.TemporaryDirectory(prefix="tui-smoke-") as temp_dir:
        journal_path = os.path.join(temp_dir, "journal.json.gz")

        original_journal_file = os.environ.get("ENCRYPTED_JOURNAL_FILE")
        original_use_keyring = os.environ.get("ENCRYPTED_JOURNAL_USE_KEYRING")
        try:
            os.environ["ENCRYPTED_JOURNAL_FILE"] = journal_path
            os.environ.pop("ENCRYPTED_JOURNAL_USE_KEYRING", None)

            asyncio.run(_run(journal_path))

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


if __name__ == "__main__":
    raise SystemExit(main())
