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
  warning, and the separate unexpected-contents warning — two call sites in one method), and
  `save_json`'s Windows-ACL-permission-failure warning.
- The GUI's "5-minute session timeout" is **aspirational, not implemented** — `last_action_time` is
  set in 8 places but never checked against anything (`TODO_PROD_READY.md` §5 lists it `[ ]`). The
  TUI's session lock is therefore new functionality, not a port of existing behavior.
- Password rotation (`change_journal_password`) is ~180 lines of orchestration (backup, re-encrypt
  all entries with a 90% partial-failure threshold, keyring resync, three outcome dialogs) —
  meaningfully more complex than the rest of v1 combined. **Deferred to v2.**
- No Textual equivalent to `pyenchant` spellcheck exists — **deferred/optional**, not blocking.
- `secure_password` (the wipe-on-exit contextmanager) is already a **module-level** function in
  `secure_journal.py` (not a method on `SecureJournalApp`) — it moves into `journal_core.py`
  unchanged, and `secure_journal.py` re-imports it so all its existing `with secure_password(...) as pwd:`
  call sites keep working.
- `_current_date()`/`_current_datetime()` stay on `SecureJournalApp` — they're already tkinter-free
  and used elsewhere (typography scaling, midnight rollover scheduling) beyond just
  `days_since_last_entry`; only `days_since_last_entry` itself gets extracted.

## Global Constraints

Binding across every task below — a reviewer checks these regardless of which task's diff is under review:

- `journal_core.py` is plain functions only — **no class**, **no `import tkinter`** anywhere in the
  file, lives at repo root (not a subpackage).
- `secure_journal.py`'s ~40 call sites that are *not themselves being extracted* (i.e. everything
  outside the ~17 methods listed in Task 1), and every public method name/signature on
  `SecureJournalApp`, must not change — Task 2 wraps, it does not rename or re-shape the class's
  public surface.
- The TUI is a standalone entry point (`journal_tui.py` with its own `if __name__ == "__main__":`),
  never a `--tui` flag bolted onto `secure_journal.py`, and `journal_tui.py` never imports
  `tkinter` or `secure_journal`.
- Crypto/storage logic is never duplicated between the two frontends — both call into `journal_core`.
- `OMARCHY_THEME_PATH` / `load_omarchy_theme()` stay in `secure_journal.py`, untouched, out of scope.
- Password rotation and spellcheck are out of scope for the TUI this round (rotation deferred to
  v2, spellcheck deferred/optional).
- No Omarchy `colors.toml` theming or `omarchy-tui-install`/`.desktop` packaging this round.

  **Update (later):** Omarchy `colors.toml` theming was implemented for the TUI in
  `omarchy_theme.py`, reading `journal_core.py`'s `read_omarchy_colors()`/
  `read_omarchy_theme_name()` — Omarchy's actual current-theme location:
  `~/.local/state/omarchy/current/theme.name` and
  `~/.local/state/omarchy/current/theme/colors.toml`. `omarchy-tui-install`/`.desktop`
  packaging is still deferred (a TUI launcher command was added to the Arch package, but no
  dedicated install script or `.desktop` entry, since the TUI targets terminal/SSH use).

  **Update (later still):** the Tkinter GUI was brought back into this repo (previously
  removed, see `TODO_PROD_READY.md`), so both frontends now coexist and share
  `journal_core.py`. The GUI's own `OMARCHY_THEME_PATH`/inline `load_omarchy_theme()`
  mentioned above no longer exist — the restored GUI was rewired onto the same
  `journal_core` Omarchy-reading functions the TUI uses, so both frontends read the same
  current-theme source instead of the GUI's old, stale `alacritty.toml` path. Backup/
  restore, password rotation, and rotating-file logging (previously GUI-only, inline) also
  moved into `journal_core.py` as shared functions, with the GUI's Settings dialog wired to
  call them. The TUI does not have its own screens for backup/restore/password-rotation
  yet — that remains future work, per the "Explicitly out of scope this round" note below,
  which was true for the TUI's original build and remains true today for those three
  specific TUI screens even though the underlying logic is now shared and ready.
- Every new smoke-test script (`scripts/core_smoke_test.py`, `scripts/tui_smoke_test.py`) follows
  `scripts/smoke_test.py`'s existing conventions: a `main()` returning `0`/`1`, `PASS:`/`FAIL:`
  prefixed stdout, `if __name__ == "__main__": raise SystemExit(main())`.
- Passwords are held as `bytearray`/wrapped via `secure_password`, never left as a bare `str` for
  longer than necessary, consistent with the existing code.
- Do not silently mark a `TODO_PROD_READY.md` item `[x]` for the GUI unless the GUI itself changed.

## Explicitly out of scope this round

- Omarchy `colors.toml` theme template integration for the TUI.
- `omarchy-tui-install` / `.desktop` launcher wiring, or any change to `packaging/arch/`.
- Password rotation in the TUI.
- Spellcheck in the TUI.
- Pitching for bundling into Omarchy's own menu/repo (a much higher bar — that's Basecamp's repo, not this one).

## Critical files

- `secure_journal.py` — source of all logic being extracted/wrapped.
- `scripts/smoke_test.py` — must keep passing unmodified; pattern to follow for new smoke tests.
- `.github/workflows/ci.yml` — where new test jobs/steps get wired in.
- `requirements.txt` / `README.md` / `TODO_PROD_READY.md` / `MERGE_POLICY.md` — conventions to respect.

## Task 1: Extract `journal_core.py`

Create a new module `journal_core.py` at the repo root containing plain, stateless functions (not
a class) covering all crypto/storage logic currently living as methods on `SecureJournalApp`, with
zero logic changes beyond parameterization and converting the 3 Tkinter messagebox call sites (4
individual `messagebox.show*` calls) into raises or injected callbacks. This module must be
importable without pulling in `tkinter` — no `import tkinter`, no `from tkinter import ...`,
directly or transitively.

Do **not** touch `secure_journal.py` in this task — that happens in Task 2. This task only adds
the new file. Do not port `OMARCHY_THEME_PATH` / `load_omarchy_theme()`, `change_journal_password`,
backup/restore, or spellcheck (out of scope / deferred, see Global Constraints).

Functions to extract, one-to-one from their current home in `secure_journal.py` (re-check current
line numbers when implementing — line numbers below are a pointer, the file is unmodified when
this task runs):

1. **`secure_password(password)`** — already a module-level `@contextmanager` function in
   `secure_journal.py` (around line 40), not a method. Move it unchanged into `journal_core.py`:
   same decorator, same `gc` import, same wipe-each-byte-then-`del`-then-`gc.collect()` behavior in
   `finally`.

2. **`derive_key(password, salt)`** — from `SecureJournalApp.derive_key`. Plain function with an
   identical body: `Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)`, accepts
   `memoryview`/`bytes`/`bytearray`/`str` password, raises `TypeError` otherwise.

3. **`encrypt_message(message, password)`** — from `SecureJournalApp.encrypt_message`. **Behavior
   change required by this task**: today it catches the `derive_key` exception, calls
   `messagebox.showerror(...)`, and returns `None`. In `journal_core.py`, let the exception
   propagate unmodified instead — no catching, no new exception type. Everything else (salt/nonce
   generation via `secrets.token_bytes`, AESGCM encrypt, base64 encode) stays identical.

4. **`decrypt_message(encrypted_message, password)`** — from `SecureJournalApp.decrypt_message`.
   Drop the `count_attempt` parameter and the `self.failed_attempts` mutation entirely — that's
   session/UI bookkeeping, not crypto; callers track failed attempts themselves. Keep everything
   else identical: base64-decode, split `salt = data[:16]` / `nonce = data[16:28]` /
   `ciphertext = data[28:]`, derive key, AESGCM decrypt, decode utf-8, and on any exception
   `raise ValueError("Incorrect password or corrupted data.")`.

5. **`env_bool(name, default=False)`** — from `SecureJournalApp._env_bool`. Same body.

6. **`default_xdg_journal_path()`** — from `_default_xdg_journal_path`. Same body (reads
   `XDG_DATA_HOME` env var, falls back to `~/.local/share`, joins `encrypted-journal/journal.json.gz`).

7. **`resource_path(relative_path)`** — from `SecureJournalApp.resource_path`. Same body
   (`sys._MEIPASS` for PyInstaller, else `os.path.dirname(os.path.abspath(__file__))` — `__file__`
   now correctly resolves to `journal_core.py`'s own location since it lives at repo root).

8. **`legacy_journal_path()`** — from `_legacy_journal_path`. Same body, but calls the new plain
   `resource_path("journal.json.gz")` instead of `self.resource_path(...)`.

9. **`resolve_journal_path()`** — from `_resolve_journal_path`. Same body (checks
   `ENCRYPTED_JOURNAL_FILE` env var first, else prefers an existing default XDG path, else an
   existing legacy path, else the default XDG path), calling the new plain
   `default_xdg_journal_path()` / `legacy_journal_path()`.

10. **`keyring_get_password(service, username, *, available=True, logger=None)`**,
    **`keyring_set_password(service, username, password, *, available=True, logger=None)`**,
    **`keyring_clear_password(service, username, *, available=True, logger=None)`** — first add the
    same guarded import `secure_journal.py` already has near its top
    (`try: import keyring / except ImportError: keyring = None`) to `journal_core.py` — `keyring`
    is an optional dependency not in `requirements.txt`, so this must not be an unconditional
    `import keyring`. Then, from
    `_keyring_get_password` / `_keyring_set_password` / `_keyring_clear_password`. If
    `not available`, behave exactly as today's `not self.keyring_available` short-circuit (`get`
    returns `None`; `set`/`clear` no-op). On the `except Exception as error` branches, call
    `logger.warning(...)` **only if `logger` is not `None`** (today it's always available via
    `self.logger`; these plain functions must tolerate `logger=None`). Same
    `keyring.get_password`/`set_password`/`delete_password` calls; `clear` still swallows any
    exception silently, matching today's bare `except Exception: pass`.

11. **`days_since_last_entry(data, *, today=None)`** — from `SecureJournalApp.days_since_last_entry`.
    Today it calls `self.load_json()` internally and `self._current_date()`. Reshape to take the
    already-loaded `data` list as a parameter (caller loads it) and an optional `today` date
    override (default `datetime.now().date()` when `None`) in place of `self._current_date()`. Keep
    the exact same return strings: `"No entries found."`, `"No valid entries found."`,
    `"You have made an entry today."`, `"It has been 1 day since your last entry."`,
    `f"It has been {days_since} days since your last entry."`.

12. **`ensure_parent_dir(path)`** — from `_ensure_parent_dir`. Takes the target file path as a
    parameter instead of reading `self.filename`.

13. **`is_valid_date_string(value)`** — from `_is_valid_date_string`. Same body (`%Y-%m-%d`
    strptime check, `False` for non-`str`).

14. **`sanitize_journal_data(data, *, filename=None, logger=None)`** — from `_sanitize_journal_data`.
    Same filtering (drop non-dict items; drop items where `date` isn't a valid date string per
    `is_valid_date_string` or `entry` isn't a `str`). On the skip-count warning, log only if
    `logger is not None`; use `filename` (may be `None`) in the log message in place of
    `self.filename` — when `filename` is `None`, adjust the message wording so it doesn't claim a
    filename it doesn't have (this only ever reaches a log file, exact wording is not
    user-facing/load-bearing).

15. **`save_json(filename, data, *, logger=None, warn_callback=None)`** — needs the same guarded
    Windows-only import `secure_journal.py` already has near its top
    (`try: import win32security, ntsecuritycon as con / except ImportError: win32security = None; con = None`)
    added to `journal_core.py`, since the Windows ACL branch below depends on it. From `save_json`. This is
    messagebox call site #3 (the Windows-ACL-permission-failure warning). Replace
    `messagebox.showwarning("Warning", f"Failed to set restrictive permissions on Windows: {perm_error}")`
    with: if `warn_callback` is not `None`, call
    `warn_callback(f"Failed to set restrictive permissions on Windows: {perm_error}")`; otherwise do
    nothing (today's code doesn't fail the save over this — it's best-effort). Keep everything else
    byte-identical: temp-file-then-`os.replace` atomic write, `0o600` chmod on POSIX, the Windows
    ACL branch gated on `win32security`, the `PermissionError`/generic-`Exception` re-raise
    wrapping, and the `finally` temp-file cleanup. Uses the new `ensure_parent_dir(filename)` in
    place of `self._ensure_parent_dir()`.

16. **`load_json_from_path(path, *, show_warnings=True, logger=None, warn_callback=None)`** — from
    `_load_json_from_path` (**renamed** per this plan — drop the leading underscore). This is
    messagebox call sites #1 and #2 (corrupt/unreadable file; unexpected-non-list contents). Both
    currently do `if show_warnings: messagebox.showwarning("Warning", "<message>")`. Replace with
    `if show_warnings and warn_callback is not None: warn_callback("<message>")` for both, using
    the exact same two message strings as today. Keep the `logger.warning(...)` calls, guarded by
    `if logger is not None`. Calls the new `sanitize_journal_data(data, filename=path, logger=logger)`
    in place of `self._sanitize_journal_data(data)`.

17. **`load_json(filename, *, logger=None, warn_callback=None)`** — from `load_json`. Same body,
    delegating to `load_json_from_path(filename, logger=logger, warn_callback=warn_callback)` with
    the default `show_warnings=True`, returning `[]` when that returns `None`.

### Verification

- `python -m py_compile journal_core.py` succeeds.
- `python -c "import journal_core, sys; assert 'tkinter' not in sys.modules"` succeeds.
- Exercise (ad-hoc, not committed — Task 3 adds the real committed test): `encrypt_message`/
  `decrypt_message` round-trip on the same password; `decrypt_message` with the wrong password
  raises `ValueError`; `save_json` + `load_json` round-trip through a tempdir; `sanitize_journal_data`
  drops a malformed record and keeps a valid one; `days_since_last_entry([], today=...)` returns
  `"No entries found."`.

## Task 2: Refactor `secure_journal.py` into thin wrappers

Depends on Task 1 (`journal_core.py` must exist with the exact functions listed there).

Make `SecureJournalApp` delegate to `journal_core` for every function extracted in Task 1, as thin
wrappers, changing **zero observable behavior** for the GUI. Every one of the 17 method names stays
on the class with its existing signature, so none of the class's ~40 other internal call sites need
to change — each wrapper just calls the matching `journal_core` function and re-adds the
Tkinter-specific bits (messagebox popups, `self.failed_attempts` bookkeeping) around it.

Add `import journal_core` near the top of `secure_journal.py`, alongside the existing imports.

Wrapper-by-wrapper:

- **`secure_password`**: remove the local `@contextmanager` definition from `secure_journal.py`
  entirely and instead do `from journal_core import secure_password` (or
  `secure_password = journal_core.secure_password`), so every existing
  `with secure_password(password) as pwd:` call site keeps working unchanged. Remove the now-unused
  `gc` import from `secure_journal.py` **only if nothing else in the file still uses it** — check
  before removing.

- **`derive_key(self, password, salt)`**:
  ```python
  def derive_key(self, password, salt):
      return journal_core.derive_key(password, salt)
  ```

- **`encrypt_message(self, message, password)`** — reintroduce the messagebox behavior that Task 1
  deliberately removed from `journal_core.encrypt_message`:
  ```python
  def encrypt_message(self, message, password):
      try:
          return journal_core.encrypt_message(message, password)
      except Exception:
          messagebox.showerror("Error", "Incorrect password.")
          return None
  ```

- **`decrypt_message(self, encrypted_message, password, count_attempt=True)`** — keep the
  `count_attempt` param and `self.failed_attempts` bookkeeping here, delegate crypto to
  `journal_core`:
  ```python
  def decrypt_message(self, encrypted_message, password, count_attempt=True):
      try:
          plaintext = journal_core.decrypt_message(encrypted_message, password)
          if count_attempt:
              self.failed_attempts = 0
          return plaintext
      except Exception:
          if count_attempt:
              self.failed_attempts += 1
          raise ValueError("Incorrect password or corrupted data.")
  ```

- **`_env_bool(self, name, default=False)`**: `return journal_core.env_bool(name, default)`.

- **`_default_xdg_journal_path(self)`**: `return journal_core.default_xdg_journal_path()`.

- **`resource_path(self, relative_path)`**: `return journal_core.resource_path(relative_path)`.

- **`_legacy_journal_path(self)`**: `return journal_core.legacy_journal_path()`.

- **`_resolve_journal_path(self)`**: `return journal_core.resolve_journal_path()`.

- **`_keyring_get_password(self)`** (and the analogous `_keyring_set_password(self, password)` /
  `_keyring_clear_password(self)`):
  ```python
  def _keyring_get_password(self):
      return journal_core.keyring_get_password(
          self.keyring_service, self.keyring_username,
          available=self.keyring_available, logger=self.logger,
      )
  ```

- **`days_since_last_entry(self)`**:
  ```python
  def days_since_last_entry(self):
      return journal_core.days_since_last_entry(self.load_json())
  ```
  No `today` override needed — the GUI always wants "now". `_current_date()`/`_current_datetime()`
  stay on the class untouched (see Grounding).

- **`_ensure_parent_dir(self)`**: `journal_core.ensure_parent_dir(self.filename)`.

- **`_is_valid_date_string(self, value)`**: `return journal_core.is_valid_date_string(value)`.

- **`_sanitize_journal_data(self, data)`**:
  ```python
  def _sanitize_journal_data(self, data):
      return journal_core.sanitize_journal_data(data, filename=self.filename, logger=self.logger)
  ```

- **`save_json(self, data)`**:
  ```python
  def save_json(self, data):
      journal_core.save_json(
          self.filename, data, logger=self.logger,
          warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
      )
  ```

- **`_load_json_from_path(self, path, show_warnings=True)`**:
  ```python
  def _load_json_from_path(self, path, show_warnings=True):
      return journal_core.load_json_from_path(
          path, show_warnings=show_warnings, logger=self.logger,
          warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
      )
  ```

- **`load_json(self)`**:
  ```python
  def load_json(self):
      return journal_core.load_json(
          self.filename, logger=self.logger,
          warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
      )
  ```

### Verification

1. `python -m py_compile secure_journal.py journal_core.py` succeeds.
2. `python scripts/smoke_test.py` still passes **unmodified** (do not edit this file). If no
   display is available it prints `SKIP:` and exits `0` — acceptable in a headless environment —
   but if a display **is** available it must print `PASS:`.
3. `git diff secure_journal.py` review: confirm the diff touches only (a) the new
   `import journal_core` line, (b) removal of the `secure_password` contextmanager plus its
   replacement import, (c) the bodies of the 17 methods listed above. No renamed methods, no
   changed signatures, no changed call sites elsewhere in the file, no unrelated reformatting.
4. Manual GUI click-through (record what you did and observed in the report): launch
   `python secure_journal.py` with `ENCRYPTED_JOURNAL_FILE` pointed at a scratch tempdir path, and
   exercise save → load → delete → open the settings dialog → (if practical) rotate password. **If
   no display is available in this environment, say so explicitly in the report** rather than
   claiming this step passed.

## Task 3: `scripts/core_smoke_test.py` + CI wiring

Depends on Task 1 (imports `journal_core` directly; does not need Task 2).

New file `scripts/core_smoke_test.py`, modeled on `scripts/smoke_test.py`'s pattern (`REPO_ROOT`
`sys.path` insert, an `_assert`-style helper, `main()` returning `0`/`1`,
`if __name__ == "__main__": raise SystemExit(main())`), importing `journal_core` directly — no
tkinter, no display check needed, must run everywhere including plain CI with no `Xvfb`. It must:

1. Assert `"tkinter" not in sys.modules` **immediately after** `import journal_core` — the literal
   proof of headless import.
2. Encrypt/decrypt round-trip: `journal_core.decrypt_message(journal_core.encrypt_message("hello", "pw"), "pw") == "hello"`.
3. Wrong password: decrypting a message encrypted with `"pw"` using `"wrong-pw"` raises `ValueError`.
4. Save/load round-trip via `tempfile.TemporaryDirectory()`: `journal_core.save_json(path, [{"date": "2026-01-01", "entry": "x"}])`
   then `journal_core.load_json(path)` returns that same list.
5. Malformed-record sanitization:
   `journal_core.sanitize_journal_data([{"date": "2026-01-01", "entry": "ok"}, {"date": "not-a-date", "entry": "bad"}, "not-a-dict"])`
   returns only the first record.
6. Env-var path override: set `ENCRYPTED_JOURNAL_FILE` to a tempdir path, assert
   `journal_core.resolve_journal_path()` returns `os.path.abspath(os.path.expanduser(<that path>))`;
   restore/clear the env var afterward (manual save/restore — this is a plain script, not pytest).

Print `PASS: core smoke test completed successfully.` on success, or `FAIL: <reason>` and return
`1` on failure — matching `smoke_test.py`'s message style.

CI wiring — edit `.github/workflows/ci.yml`, extending the existing single `test` job (do not
create a second job; `journal_core.py` needs no `xvfb`/`tkinter`, but the existing job installing
those does no harm to a step that doesn't need them):
- Extend the `Compile check` step's `py_compile` invocation to also compile `journal_core.py` and
  `scripts/core_smoke_test.py`.
- Add a new step, e.g. `- name: Core smoke test (headless)` running `python scripts/core_smoke_test.py`,
  placed **before** the existing `Smoke test (Tkinter under Xvfb)` step.

### Verification

- `python -m py_compile journal_core.py scripts/core_smoke_test.py`.
- `python scripts/core_smoke_test.py` prints `PASS:` and exits `0`.
- `python scripts/smoke_test.py` still passes/skips as before (untouched by this task).
- Read the edited `ci.yml` back and confirm it's well-formed YAML with correct indentation.

## Task 4: `requirements-tui.txt` + scaffold `journal_tui.py`/`journal_tui.tcss` — App + UnlockScreen

Depends on Task 1 (`journal_core.py` must exist and expose the functions listed there).

New file `requirements-tui.txt` at repo root, containing just:
```
textual
```
Kept separate from `requirements.txt` — GUI-only installs must not pull in Textual, TUI-only
installs must not pull in `pyenchant`.

New files `journal_tui.py` and `journal_tui.tcss` at repo root (flat-file convention, matching
`secure_journal.py`/`azure.tcl`). `journal_tui.py` is a standalone script with its own
`if __name__ == "__main__":` — **not** a `--tui` flag on `secure_journal.py` (that file imports
`tkinter` unconditionally at module load, which would break headless/SSH use). `journal_tui.py`
must **not** import `secure_journal` or `tkinter` at all — only `journal_core` plus Textual.

App shell (e.g. `class JournalApp(textual.app.App)`):
- `CSS_PATH = "journal_tui.tcss"`.
- Resolves the journal path the same way the GUI does: `journal_core.resolve_journal_path()`
  (respects `ENCRYPTED_JOURNAL_FILE`, XDG default, legacy fallback — same convention as the GUI, so
  a user pointing `ENCRYPTED_JOURNAL_FILE` at a journal gets identical behavior in both frontends).
- Holds app-level state: the resolved journal path; the in-memory password (only ever held via
  `bytearray`/`secure_password`, never a plain `str` for longer than necessary); and keyring
  settings mirroring the GUI's `ENCRYPTED_JOURNAL_USE_KEYRING` / `ENCRYPTED_JOURNAL_KEYRING_USER`
  env vars — reuse `journal_core.env_bool("ENCRYPTED_JOURNAL_USE_KEYRING", False)` and
  `os.environ.get("ENCRYPTED_JOURNAL_KEYRING_USER", getpass.getuser() or "default")`, matching
  `SecureJournalApp.__init__`'s exact logic (`self.keyring_service = "encrypted-journal"`).
- On mount, pushes `UnlockScreen` as the initial screen.

`UnlockScreen` (Textual `Screen`):
- A password `Input` (`password=True`).
- If keyring is available/enabled and has a stored password for
  `(service="encrypted-journal", username=<resolved username>)` (via
  `journal_core.keyring_get_password`), prefill the `Input` with it (mirrors the GUI's
  keyring-prefill behavior) — only render this prefill/checkbox when keyring is actually available
  (mirrors the GUI's conditional keyring checkbox).
- A "remember password" `Checkbox`, shown only when keyring is available.
- On submit: load the journal via `journal_core.load_json(journal_path)`.
  - If empty (brand-new journal), accept whatever was typed as the new password (nothing to
    validate against yet) — store it and proceed.
  - If non-empty, validate by attempting `journal_core.decrypt_message(<first entry's "entry">, <typed password>)`;
    on success, store the password and proceed. Where it proceeds to (`EntryListScreen`) doesn't
    exist until Task 5 — a placeholder push/transition is fine for this task as long as
    unlock-success is observably distinguishable from unlock-failure in a headless `Pilot` test.
- On failure (wrong password against an existing entry): increment a **TUI-local** failed-attempt
  counter (do not touch `SecureJournalApp.failed_attempts` — no shared state between GUI and TUI
  processes) and show an inline error. After **5** failed attempts (matching the GUI's
  `self.max_attempts = 5`), lock out further attempts for this run (exact lockout presentation is
  implementer's judgment — only the count, 5, is fixed).
- If "remember password" is checked and keyring is available, call `journal_core.keyring_set_password(...)`
  with the validated password on successful unlock.

### Verification

- `python -m py_compile journal_tui.py`.
- `pip install -r requirements-tui.txt` succeeds in a clean venv (or at minimum
  `python -c "import textual"` succeeds after installing it).
- A headless `App.run_test()`/`Pilot` check (this is the first Textual test in the repo — no
  existing pattern to copy) that: creates a fresh empty journal in a tempdir, types a password into
  `UnlockScreen`, submits, and asserts the app is no longer on `UnlockScreen`. This can be an ad-hoc
  local check for this task — Task 9 adds the full committed `scripts/tui_smoke_test.py`.
- Note in the report whether `python journal_tui.py` was verified interactively against a scratch
  journal path, or only via headless `Pilot` (depends on terminal availability in this environment).

## Task 5: Build `EntryListScreen`

Depends on Task 4 (`UnlockScreen` must exist and successfully transition somewhere on unlock).

`EntryListScreen` (Textual `Screen`, pushed by `UnlockScreen` on successful unlock):
- A `Tree` widget grouped **Year-Month → dates**, adapted directly from `update_treeview`'s grouping
  logic: group entries by `date_str[:7]` (`YYYY-MM`), sort year-month groups descending via
  `datetime.strptime(ym, "%Y-%m")`, sort dates within each group descending via
  `datetime.strptime(date, "%Y-%m-%d")`. Month nodes collapsed by default, date nodes are leaves.
- Data source: `journal_core.load_json(journal_path)`, re-loaded on mount and whenever the screen
  needs to refresh (after returning from create/delete).
- A status line showing `journal_core.days_since_last_entry(data)`'s return string verbatim.
- Key bindings (Textual `BINDINGS`):
  - `n` → push `EntryViewScreen` (Task 6) in "new" mode: empty body, date pre-filled to today
    (`datetime.now().strftime("%Y-%m-%d")`, matching `save_journal_entry`'s own default-date logic).
  - `enter` / `v` → if the current selection is a date leaf (not a month-group node — mirror the
    GUI's month-vs-date distinction), push `EntryViewScreen` in "view/edit" mode for that date,
    decrypting via the app's stored password.
  - `d` → trigger the delete-confirmation flow (Task 7) for the selected date leaf; if a month node
    is selected, show guidance instead of deleting (mirrors the GUI's
    `"Please select a date to delete, not a month."`).
  - `l` → manually trigger the session lock (Task 8): clears the in-memory password and returns to
    `UnlockScreen` immediately, regardless of the elapsed-time timer.
  - `q` → quit the app.
- Selecting a month node for view/enter should give guidance (mirrors the GUI's
  `"Select a dated journal entry, not a month heading."`) rather than silently doing nothing or
  crashing — an inline status message is sufficient (no messagebox equivalent required).

### Verification

- `python -m py_compile journal_tui.py`.
- Headless `Pilot` check: seed a tempdir journal with entries across at least two different
  year-months (write directly via `journal_core.save_json`/`encrypt_message` in test setup, not
  through the UI), unlock, assert the `Tree` has the expected month-group node count and the most
  recent month-group sorts first.
- Note in the report whether `n`/`enter`/`v`/`d`/`l`/`q` were exercised via `Pilot.press(...)` here,
  or left for Task 9's end-to-end test to cover.

## Task 6: Build `EntryViewScreen`

Depends on Task 5 (`EntryListScreen` pushes this screen in both "new" and "view/edit" modes).

`EntryViewScreen` (Textual `Screen`):
- A `TextArea` for the entry body, an `Input` for the date (`YYYY-MM-DD`).
- Two modes landing on this same screen: **new** (via `n` — empty body, date pre-filled to today)
  and **view/edit** (via `enter`/`v` — body decrypted and populated, date pre-filled to the
  selected date).
- View/edit mode: decrypt via `journal_core.decrypt_message(<entry>, <app's stored password>)` on
  screen entry. If decryption fails (e.g. a stale in-memory password after a lock — see Task 8), do
  not crash — fall back to re-prompting for the password in place rather than showing garbage or
  raising uncaught.
- `ctrl+s` → save, matching `save_journal_entry`'s exact validation and **exact error strings**:
  - Empty body (after `.strip()`) → reject with `"Journal entry cannot be empty."` (no save, no
    screen change).
  - Empty date → default to `datetime.now().strftime("%Y-%m-%d")` (not an error — silently
    defaulted, same as the GUI).
  - Non-empty but malformed date (fails `datetime.strptime(date_str, "%Y-%m-%d")`) → reject with
    `"Invalid date format. Use YYYY-MM-DD"`.
  - On valid input: `journal_core.encrypt_message(<body>, <stored password>)`, load current data
    via `journal_core.load_json(journal_path)`, update-in-place if an entry with that exact date
    already exists (else append) — same update-or-append logic as the GUI — then
    `journal_core.save_json(journal_path, data)`.
  - On success: show a brief success indication (no modal required — the GUI's `messagebox.showinfo`
    has no TUI equivalent requirement), clear/reset screen state, return to `EntryListScreen`, which
    must **refresh** its `Tree` and days-since status line (re-run Task 5's load/group/sort logic,
    don't pop back to stale state).
- `escape` → cancel: discard in-progress edits, return to `EntryListScreen` without saving. No
  confirm-discard dialog required.

### Verification

- `python -m py_compile journal_tui.py`.
- Headless `Pilot` check: from `EntryListScreen`, press `n`, type a body, `ctrl+s`, then verify
  **on-disk** (via `journal_core.load_json` + `journal_core.decrypt_message`, not just TUI widget
  state) that the entry round-trips correctly for the exact typed text and today's pre-filled date.
- A second check exercising all three validation paths (empty body, empty date defaults, malformed
  date rejected) and confirming the exact error strings above appear.

## Task 7: Build delete confirmation flow

Depends on Task 5 (triggered by `d` on `EntryListScreen`).

A `ModalScreen` with Yes/No, matching `delete_journal_entry`'s flow:
- Reachable only for a selected **date** leaf (month nodes rejected at the `EntryListScreen` level
  per Task 5 — this modal should never be reachable for a month node).
- Before any data is removed: re-validate the app's stored in-memory password by attempting
  `journal_core.decrypt_message(<selected entry's "entry">, <stored password>)`. If this raises
  `ValueError`, abort the delete with an inline error — do not show the Yes/No prompt with a
  password already known to be wrong (mirrors the GUI's decrypt-then-confirm order).
- On explicit "Yes": load current data via `journal_core.load_json`, filter out the entry matching
  the selected date, `journal_core.save_json(...)` the filtered list, return to `EntryListScreen`
  and **refresh** its `Tree` and days-since status line (same refresh requirement as Task 6).
- On "No"/cancel: no data changes, return to `EntryListScreen` unchanged.

### Verification

- `python -m py_compile journal_tui.py`.
- Headless `Pilot` check: seed a journal with one entry, unlock, select it, press `d`, confirm Yes,
  assert on-disk (via `journal_core.load_json`) the entry is gone and the `Tree` no longer shows
  that date.
- A second check confirming "No" leaves the on-disk entry untouched.

## Task 8: Build session lock

Depends on Task 4 (app-level stored password) and Task 5 (`l` key wiring exists there); sequence
this after Task 7.

New functionality — the GUI's "5-minute session timeout" is aspirational and never actually checks
elapsed time anywhere (see Grounding), so this is not a port.

- A `set_interval` timer at the app level comparing elapsed time since `last_action_time` (tracked
  the same way the GUI tracks `self.last_action_time = datetime.now()`, reset on user actions —
  follow the GUI's own pattern of resetting it at the top of its save/load/delete-equivalent
  actions) against a threshold.
- **Threshold: 300 seconds (5 minutes) by default**, overridable via the
  `ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS` environment variable (parsed as `int`) — a new env var this
  task introduces, following the existing `ENCRYPTED_JOURNAL_*` naming convention, so a manual
  tester can set it small (e.g. `10`) for fast verification.
- On expiry: clear the in-memory stored password (wipe the `bytearray` byte-by-byte before dropping
  the reference, same pattern as `secure_password`'s `finally` block). **Do not discard unsaved
  edits** — if the lock fires mid-edit on `EntryViewScreen`, the next action needing decryption
  (viewing a different entry, or `ctrl+s` needing to re-encrypt) re-prompts for the password **in
  place** rather than kicking the user back to `UnlockScreen` and losing their typed body. This
  means `EntryViewScreen`'s save path (Task 6) and the delete-confirmation's decrypt-revalidation
  (Task 7) must both handle "no password currently held" by prompting inline and resuming.
- The `l` key on `EntryListScreen` (wired in Task 5) triggers this same clear-and-return-to-`UnlockScreen`
  path manually, on demand, independent of the timer.

### Verification

- `python -m py_compile journal_tui.py`.
- Headless check with `ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS=1` (or similarly short) set before app
  startup: unlock, wait past the threshold (a real sleep, or manipulating the app's
  clock/timer if Textual's `Pilot` supports time control), then assert the in-memory password is
  cleared and an action needing decryption re-prompts rather than crashing.
- A check for the manual `l` lock-now path, independent of the timer.

## Task 9: `scripts/tui_smoke_test.py` + CI wiring

Depends on Tasks 4-8 (exercises the full app).

New file `scripts/tui_smoke_test.py`, following `scripts/smoke_test.py`'s and Task 3's
`scripts/core_smoke_test.py`'s conventions (`REPO_ROOT` `sys.path` insert, an assert-style helper,
`main()`/`async def main()` returning `0`/`1`, `if __name__ == "__main__":` entry). Uses Textual's
`App.run_test()`/`Pilot` (headless, no `Xvfb` needed). Drives, against a tempdir journal:

1. **Unlock**: submit a password on `UnlockScreen` for a brand-new (empty) journal.
2. **Create**: press `n`, type an entry body, `ctrl+s`.
3. **Verify on-disk** (not just UI state): reload via `journal_core.load_json` +
   `journal_core.decrypt_message`, assert it matches what was typed.
4. **Reload**: navigate to the entry through the UI and assert the displayed body matches.
5. **Delete**: trigger delete, confirm.
6. **Confirm**: assert on-disk (via `journal_core.load_json`) the entry is gone.
7. **Quit**: assert the app exits cleanly.

Print `PASS: TUI smoke test completed successfully.` / `FAIL: <reason>`, matching the other two
smoke scripts' conventions.

CI wiring — edit `.github/workflows/ci.yml` again: add a step installing `requirements-tui.txt`
(`pip install -r requirements-tui.txt`), extend the `Compile check` step to also
`py_compile journal_tui.py scripts/tui_smoke_test.py`, and add a `TUI smoke test (headless)` step
running `python scripts/tui_smoke_test.py`, alongside (not replacing) the existing steps.

### Verification

- `python -m py_compile journal_tui.py scripts/tui_smoke_test.py`.
- `python scripts/tui_smoke_test.py` prints `PASS:` and exits `0`.
- `scripts/smoke_test.py` and `scripts/core_smoke_test.py` still pass/skip as before.
- Read `ci.yml` back and confirm it's well-formed YAML with all four checks present: compile check,
  Tkinter smoke test (Xvfb), core smoke test, TUI smoke test.

## Task 10: Update `README.md` and `TODO_PROD_READY.md`

Depends on all prior tasks (documents the finished feature).

`README.md`: add a "Textual TUI" section (match the existing document's structure/tone; read it
before writing). Cover: what it is (a terminal-first alternative, coexisting with the GUI, not a
replacement); installing the extra dependency (`pip install -r requirements-tui.txt`); launching it
(`python journal_tui.py`); that it shares the same journal file/format/crypto as the GUI (via
`journal_core.py`), so entries created in one are visible in the other; the key bindings
(`n`/`enter`/`v`/`d`/`l`/`q`/`ctrl+s`/`escape`); the `ENCRYPTED_JOURNAL_TUI_LOCK_SECONDS` env var;
and a short note that password rotation and spellcheck are GUI-only for now.

`TODO_PROD_READY.md` §5 "Session Lock Features": do **not** mark `[ ]` "Add optional inactivity
auto-lock" or `[ ]` "Add a manual `Lock now` action" as `[x]` — the GUI still doesn't implement
them, and that remains true. Instead add a note clarifying the **TUI** now has both (Tasks 5 & 8),
while the **GUI** still does not — keep the existing `[ ]` markers honest about GUI state. Also add
new `[ ]` entries (or a new "TUI (v1)" subsection) listing what's explicitly deferred from this
effort: password rotation, spellcheck, Omarchy `colors.toml` theming, `omarchy-tui-install`/`.desktop`
packaging — cross-reference this plan's "Explicitly out of scope this round" list so nothing is
missed.

### Verification

- Read the edited `README.md` and `TODO_PROD_READY.md` back and confirm the new content reads
  coherently in context and that no existing `[x]`/`[ ]` marker for an unrelated, already-shipped
  item was accidentally changed.
- `git diff README.md TODO_PROD_READY.md` — confirm the diff is additive/targeted, not a wholesale
  reformat.
