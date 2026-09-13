# EncryptedJournal: Textual TUI (Omarchy 4 "Quattro" concept)

## Context

`EncryptedJournal` (git@github.com:tomemme/EncryptedJournal.git) is a Python/Tkinter encrypted
journal app. Its `omarchy-version` branch is the actively-maintained line — it already carries
Arch/AUR packaging (PKGBUILD, `.desktop`, CI) on top of a hardened core (AES-GCM + Scrypt,
XDG storage paths, keyring support) — but the interface itself is GUI-only.

The goal is to raise the project's profile for Omarchy 4 ("Quattro" — confirmed as the real
release codename via installed package/migration metadata) by adding a terminal-first interface,
which fits Omarchy's terminal-centric conventions and is a prerequisite for either self-publishing
via `omarchy-tui-install` or eventually pitching for bundling into Omarchy itself. This is step one
of that effort: get a working, separate TUI without touching the existing GUI's behavior or taking
on theming/packaging work yet.

Decisions locked in during brainstorming:
1. New branch (`tui-textual`) off `omarchy-version`; TUI is a **separate, coexisting** interface — GUI stays as-is.
2. TUI library: **Textual**.
3. Scope for this pass: **TUI core only** — no Omarchy `colors.toml` theme integration, no
   `omarchy-tui-install`/`.desktop` packaging. Both are explicit follow-ups, not part of this branch.
4. Crypto/storage logic must **not be duplicated** — extract a shared `journal_core.py` module used
   by both frontends, since two independent encryption implementations is a real security risk.

## Grounding (from reading the actual code, not assumptions)

- `SecureJournalApp.__init__` builds the Tkinter window immediately — there's currently no headless
  import path to the crypto/storage logic.
- `self.filename` is a plain attribute mutated directly by tests (`scripts/smoke_test.py` does
  `app.filename = journal_path` post-construction) → `journal_core.py` must be **plain functions
  taking explicit params**, not a stateful class, or GUI/test mutation of `filename` desyncs from it.
- `resource_path()`/`_legacy_journal_path()` resolve relative to `__file__` → `journal_core.py` must
  live at **repo root**, next to `secure_journal.py`, not in a subpackage.
- Three call sites reach into Tkinter and must change from "show a messagebox" to "raise / call an
  injected callback": `encrypt_message` (wrong password), `_load_json_from_path` (corrupt-data
  warning), and `save_json`'s Windows-ACL-permission-failure warning.
- The GUI's "5-minute session timeout" is **aspirational, not implemented** — `last_action_time` is
  set in 8 places but never checked against anything (`TODO_PROD_READY.md` §5 lists it `[ ]`). The
  TUI's session lock is therefore new functionality, not a port of existing behavior.
- Password rotation (`change_journal_password`) is ~180 lines of orchestration (backup, re-encrypt
  all entries with a 90% partial-failure threshold, keyring resync, three outcome dialogs) —
  meaningfully more complex than the rest of v1 combined. **Deferred to v2.**
- No Textual equivalent to `pyenchant` spellcheck exists — **deferred/optional**, not blocking.

## Architecture

### 1. `journal_core.py` (new, repo root)

Module of plain functions (not a class), extracted from `SecureJournalApp` with zero logic changes
beyond parameterizing `self.filename`/`self.logger`/`self.keyring_*` and converting the 3 messagebox
call sites to `warn_callback` params / raised exceptions:

- `derive_key`, `encrypt_message`, `decrypt_message` (drop the `count_attempt`/`failed_attempts`
  coupling — that's session state, not crypto), `secure_password` contextmanager.
- `save_json`, `load_json_from_path` (renamed from `_load_json_from_path`), `load_json`,
  `sanitize_journal_data`, `ensure_parent_dir`, `resource_path`, `default_xdg_journal_path`,
  `legacy_journal_path`, `resolve_journal_path`, `env_bool`.
- `keyring_get_password` / `keyring_set_password` / `keyring_clear_password`.
- `days_since_last_entry` (bonus — already tkinter-free, lets both frontends render identical status text).

`OMARCHY_THEME_PATH` / `load_omarchy_theme()` stay in `secure_journal.py` untouched (out of scope).

### 2. `secure_journal.py` refactor

Keep identically-named/signatured methods on `SecureJournalApp` as **thin delegating wrappers**
around `journal_core`, so none of the ~40 internal call sites need to change:

```python
def encrypt_message(self, message, password):
    try:
        return journal_core.encrypt_message(message, password)
    except Exception:
        messagebox.showerror("Error", "Incorrect password.")
        return None

def save_json(self, data):
    journal_core.save_json(
        self.filename, data, logger=self.logger,
        warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
    )
```

`decrypt_message` keeps its `count_attempt` param and `self.failed_attempts` bookkeeping in the
wrapper, delegating the actual crypto to `journal_core.decrypt_message`.

**Verification this step is behavior-neutral:** `python scripts/smoke_test.py` (unmodified) must
still pass, plus a manual GUI click-through of save/load/delete/settings/rotate-password, plus a
`git diff secure_journal.py` review confirming only relocation, not logic changes.

### 3. `journal_tui.py` + `journal_tui.tcss` (new, repo root)

Single file, matching the repo's existing flat-file convention. Screens:

- **`UnlockScreen`** — password `Input`, keyring-prefill + "remember password" checkbox (mirrors
  GUI's conditional keyring checkbox), validates by attempting a decrypt against an existing entry,
  5-failed-attempts lockout (TUI-local state).
- **`EntryListScreen`** — `Tree` grouped Year-Month → dates (adapted from `update_treeview`'s
  grouping), `days_since_last_entry` status line, keys: `n` new, `enter`/`v` view, `d` delete,
  `l` lock now, `q` quit.
- **`EntryViewScreen`** — `TextArea` body + `Input` date (new entries prefill today's date),
  `ctrl+s` save with the GUI's existing validation error strings, `escape` cancel.
- **Delete confirmation** — `ModalScreen` Yes/No, re-validates decrypt before removing.
- **Session lock** — `set_interval` compares elapsed time to 300s (overridable via
  `ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS` for fast manual testing, following the existing
  `ENCRYPTED_JOURNAL_*` env convention). On expiry, clears the in-memory password; the next action
  needing decryption re-prompts in place rather than discarding an unsaved edit.

**Deferred to v2**: password rotation (needs `journal_core.rotate_password(...)` extracted first,
then wrapped by both frontends' own dialogs — flagged in README as "use the GUI for now").
**Deferred/optional**: spellcheck.

### 4. Entry point & dependencies

Standalone `python journal_tui.py` (own `if __name__ == "__main__":`) — **not** a `--tui` flag on
`secure_journal.py`, because that file imports `tkinter` unconditionally at module load, which would
defeat running the TUI headless over SSH with no display. New `requirements-tui.txt` (just
`textual`) kept separate from `requirements.txt` so GUI-only and TUI-only users aren't forced into
the other's dependencies.

## Testing

1. **Core-extraction regression**: `scripts/smoke_test.py` unmodified must still pass;
   `python -m py_compile secure_journal.py journal_core.py`.
2. **New `scripts/core_smoke_test.py`**: imports `journal_core`, asserts `"tkinter" not in
   sys.modules` (proves headless import works), exercises encrypt/decrypt round-trip, wrong-password
   `ValueError`, save/load round-trip via tempdir, malformed-record sanitization, env-var path overrides.
3. **New `scripts/tui_smoke_test.py`**: Textual's `App.run_test()`/`Pilot` (headless, no Xvfb needed)
   drives unlock → create → save → verify on-disk via `journal_core.load_json`+`decrypt_message`
   (not just UI state) → reload → delete → confirm → quit.
4. **CI** (`.github/workflows/ci.yml`): add a job installing `requirements-tui.txt`, `py_compile`
   the new files, run both new smoke tests alongside the existing Tkinter/Xvfb job.
5. **Manual checklist**: launch `python journal_tui.py` on a fresh journal, create/save/view/delete
   an entry, verify lock behavior with `ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS=10`.

## Sequencing

1. Create `journal_core.py` (extraction + the 3 messagebox→callback/raise conversions).
2. Refactor `secure_journal.py` into thin wrappers; `py_compile` check.
3. Verify zero behavior change (smoke test + manual click-through + diff review).
4. Add `scripts/core_smoke_test.py`; wire into CI.
5. Add `requirements-tui.txt`; scaffold `journal_tui.py`/`journal_tui.tcss` with `App` + `UnlockScreen`.
6. Build `EntryListScreen`.
7. Build `EntryViewScreen` (view/edit/new + save validation).
8. Build delete confirmation flow.
9. Build session lock.
10. Add `scripts/tui_smoke_test.py`; wire into CI.
11. Update `README.md` with a "Textual TUI" section; note deferred items (rotation, spellcheck,
    theming, packaging) in `TODO_PROD_READY.md`.
12. Full diff review of `secure_journal.py` (mechanical-only), both smoke tests + `py_compile` green,
    open PR `tui-textual` → `omarchy-version` (per `MERGE_POLICY.md`'s convention that
    Omarchy/Linux-specific features start there).

## Explicitly out of scope this round

- Omarchy `colors.toml` theme template integration for the TUI.
- `omarchy-tui-install` / `.desktop` launcher wiring, or any change to `packaging/arch/`.
- Password rotation in the TUI.
- Spellcheck in the TUI.
- Pitching for bundling into Omarchy's own menu/repo (a much higher bar — that's Basecamp's repo, not this one).

## Critical files

- `secure_journal.py` — source of all logic being extracted/wrapped.
- `scripts/smoke_test.py` — must keep passing unmodified; pattern to follow for new smoke tests.
- `.github/workflows/ci.yml` — where new test jobs get wired in.
- `requirements.txt` / `README.md` / `TODO_PROD_READY.md` / `MERGE_POLICY.md` — conventions to respect.
