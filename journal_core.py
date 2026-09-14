"""
Core cryptographic and storage logic for the Encrypted Journal.
Shared between GUI and TUI implementations.
"""

import os
import sys
import gzip
import json
import secrets
import gc
import shutil
import tempfile
import tomllib
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
from contextlib import contextmanager
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

# Guarded optional imports
try:
    import keyring
except ImportError:
    keyring = None

try:
    import win32security
    import ntsecuritycon as con
except ImportError:
    win32security = None
    con = None


@contextmanager
def secure_password(password):
    """Provide a mutable buffer for a password and wipe it afterwards."""

    secret = None
    try:
        if isinstance(password, bytearray):
            secret = password
        elif isinstance(password, (bytes, memoryview)):
            secret = bytearray(password)
        elif isinstance(password, str):
            secret = bytearray(password, "utf-8")
        else:
            raise TypeError("Password must be bytes-like or str")

        yield secret
    finally:
        if secret is not None:
            for i in range(len(secret)):
                secret[i] = 0
        del secret
        gc.collect()


def derive_key(password, salt):
    """Derive a 32-byte key from a password and salt using Scrypt."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    if isinstance(password, memoryview):
        password_bytes = password.tobytes()
    elif isinstance(password, (bytes, bytearray)):
        password_bytes = password
    elif isinstance(password, str):
        password_bytes = password.encode()
    else:
        raise TypeError("Password must be bytes-like or str")

    return kdf.derive(password_bytes)


def encrypt_message(message, password):
    """Encrypt a message with a password using AES-GCM.

    Raises TypeError if password is invalid type.
    Propagates any exception from derive_key.
    """
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
    return base64.urlsafe_b64encode(salt + nonce + ciphertext).decode("utf-8")


def decrypt_message(encrypted_message, password):
    """Decrypt a message with a password using AES-GCM.

    Raises ValueError with message "Incorrect password or corrupted data."
    on any decryption error.
    """
    try:
        encrypted_data = base64.urlsafe_b64decode(encrypted_message)
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")
    except Exception:
        raise ValueError("Incorrect password or corrupted data.")


def env_bool(name, default=False):
    """Parse an environment variable as a boolean."""
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_int(name, default=0):
    """Parse an environment variable as an int, falling back to `default`
    if it's unset or not a valid integer."""
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def default_xdg_journal_path():
    """Get the default XDG Data Home path for the journal."""
    xdg_data_home = os.environ.get(
        "XDG_DATA_HOME", os.path.expanduser("~/.local/share")
    )
    return os.path.join(
        os.path.expanduser(xdg_data_home), "encrypted-journal", "journal.json.gz"
    )


def resource_path(relative_path):
    """Resolve a resource path, using PyInstaller's bundled resources if available."""
    try:
        base_path = sys._MEIPASS  # PyInstaller
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)


def legacy_journal_path():
    """Get the legacy journal path (bundled with the app binary)."""
    return resource_path("journal.json.gz")


def resolve_journal_path():
    """Resolve the journal file path according to precedence rules.

    1. ENCRYPTED_JOURNAL_FILE env var if set
    2. Default XDG path if it exists
    3. Legacy path if it exists
    4. Default to XDG path
    """
    custom_path = os.environ.get("ENCRYPTED_JOURNAL_FILE")
    if custom_path:
        return os.path.abspath(os.path.expanduser(custom_path))

    default_path = default_xdg_journal_path()
    legacy_path = legacy_journal_path()

    if os.path.exists(default_path):
        return default_path
    if os.path.exists(legacy_path):
        return legacy_path
    return default_path


def keyring_get_password(service, username, *, available=True, logger=None):
    """Get a password from the system keyring.

    Returns None if keyring is not available or if retrieval fails.
    """
    if not available:
        return None
    if keyring is None:
        return None
    try:
        return keyring.get_password(service, username)
    except Exception as error:
        if logger is not None:
            logger.warning("Keyring read failed: %s", error)
        return None


def keyring_set_password(service, username, password, *, available=True, logger=None):
    """Set a password in the system keyring.

    No-op if keyring is not available or if password is falsy.
    """
    if not available or keyring is None or not password:
        return
    try:
        keyring.set_password(service, username, password)
    except Exception as error:
        if logger is not None:
            logger.warning("Keyring write failed: %s", error)


def keyring_clear_password(service, username, *, available=True, logger=None):
    """Clear a password from the system keyring.

    No-op if keyring is not available. Silently ignores any exceptions.
    """
    if not available or keyring is None:
        return
    try:
        keyring.delete_password(service, username)
    except Exception:
        pass


def days_since_last_entry(data, *, today=None):
    """Return a human-readable string about days since the last journal entry.

    Args:
        data: List of journal entry dicts (already loaded from JSON)
        today: Optional date override (defaults to datetime.now().date())

    Returns one of:
    - "No entries found."
    - "No valid entries found."
    - "You have made an entry today."
    - "It has been 1 day since your last entry."
    - "It has been {days_since} days since your last entry."
    """
    if today is None:
        today = datetime.now().date()

    if not data:
        return "No entries found."

    dates = []
    for entry in data:
        date_str = entry.get("date")
        if date_str:
            try:
                date = datetime.strptime(date_str, "%Y-%m-%d").date()
                dates.append(date)
            except ValueError:
                pass

    if not dates:
        return "No valid entries found."

    most_recent_date = max(dates)
    days_since = (today - most_recent_date).days

    if days_since == 0:
        return "You have made an entry today."
    elif days_since == 1:
        return "It has been 1 day since your last entry."
    else:
        return f"It has been {days_since} days since your last entry."


def ensure_parent_dir(path):
    """Ensure the parent directory of a file path exists."""
    parent = os.path.dirname(path)
    if parent and not os.path.exists(parent):
        os.makedirs(parent, exist_ok=True)


def is_valid_date_string(value):
    """Check if a value is a valid date string in YYYY-MM-DD format."""
    if not isinstance(value, str):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def sanitize_journal_data(data, *, filename=None, logger=None):
    """Filter a list of journal entries to remove invalid records.

    Removes non-dict items and items with invalid date or missing entry.
    Logs a warning if any records were skipped (only if logger is not None).
    """
    sanitized = []
    skipped = 0
    for item in data:
        if not isinstance(item, dict):
            skipped += 1
            continue

        date_value = item.get("date")
        entry_value = item.get("entry")
        if not is_valid_date_string(date_value) or not isinstance(
            entry_value, str
        ):
            skipped += 1
            continue

        sanitized.append(item)

    if skipped and logger is not None:
        if filename:
            logger.warning(
                f"Skipped {skipped} invalid journal record(s) while loading "
                f"'{filename}'."
            )
        else:
            logger.warning(
                f"Skipped {skipped} invalid journal record(s) while loading."
            )
    return sanitized


def save_json(filename, data, *, logger=None, warn_callback=None):
    """Save journal data to a compressed JSON file atomically.

    Writes to a temp file first, then replaces the target atomically.
    On POSIX: sets 0o600 permissions.
    On Windows with win32security: sets ACL to restrict to current user.

    If warn_callback is provided and Windows ACL setup fails, calls it with
    the error message. Otherwise, silently continues (best-effort).

    Raises PermissionError or Exception on write failures.
    """
    temp_path = None
    try:
        ensure_parent_dir(filename)

        parent_dir = os.path.dirname(filename) or "."
        with tempfile.NamedTemporaryFile(
            mode="wb",
            delete=False,
            dir=parent_dir,
            prefix=".journal_tmp_",
            suffix=".gz",
        ) as tmp_file:
            temp_path = tmp_file.name

        with gzip.open(temp_path, "wt", encoding="utf-8") as file:
            json.dump(data, file, indent=4)

        if os.name != "nt":
            os.chmod(temp_path, 0o600)  # lock down temp file on Unix

        os.replace(temp_path, filename)
        temp_path = None

        if os.name == "nt" and win32security:
            try:
                user, domain, type = win32security.LookupAccountName(
                    "", os.getlogin()
                )
                sd = win32security.GetFileSecurity(
                    filename, win32security.DACL_SECURITY_INFORMATION
                )
                dacl = win32security.ACL()
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION,
                    con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                    user,
                )
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    filename, win32security.DACL_SECURITY_INFORMATION, sd
                )
            except Exception as perm_error:
                if warn_callback is not None:
                    warn_callback(f"Failed to set restrictive permissions on Windows: {perm_error}")
        else:
            os.chmod(filename, 0o600)  # lock down on Unix

    except PermissionError as e:
        raise PermissionError(
            f"Permission denied when accessing {filename}: {e}"
        )
    except Exception as e:
        raise Exception(f"Failed to save JSON data: {e}")
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def load_json_from_path(path, *, show_warnings=True, logger=None, warn_callback=None):
    """Load journal data from a file path.

    Returns a sanitized list of journal entries, or None if the file is
    corrupted or contains unexpected data.

    If show_warnings is True and warn_callback is not None, calls warn_callback
    with error messages when encountering corruption or invalid data.

    If logger is not None, logs warnings about load failures and corruption.
    """
    if not os.path.exists(path):
        return []

    try:
        with gzip.open(path, "rt", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        if show_warnings and warn_callback is not None:
            warn_callback(
                "The journal file appears to be corrupted or unreadable. "
                "It will be ignored until it is replaced with a valid backup."
            )
        if logger is not None:
            logger.warning("Failed to read journal file '%s': %s", path, e)
        return None

    if isinstance(data, list):
        return sanitize_journal_data(data, filename=path, logger=logger)

    if show_warnings and warn_callback is not None:
        warn_callback(
            "The journal file contains unexpected data and will be ignored."
        )
    if logger is not None:
        logger.warning(
            "Unexpected journal file contents. Expected a list of entries, got %s.",
            type(data).__name__,
        )
    return None


def load_json(filename, *, logger=None, warn_callback=None):
    """Load journal data from a file.

    Returns an empty list if the file doesn't exist or is invalid.
    """
    data = load_json_from_path(
        filename, logger=logger, warn_callback=warn_callback
    )
    if data is None:
        return []
    return data


def find_entry_by_date(data, date_str):
    """Return the entry dict in `data` whose 'date' matches date_str, or
    None if there isn't one. Shared by both frontends' overwrite guards:
    creating/saving a "new" entry for a date that already has one should
    open the existing entry for editing instead of silently overwriting it.
    """
    return next((entry for entry in data if entry.get("date") == date_str), None)


DEFAULT_MAX_BACKUPS = 10


def create_journal_backup(journal_path, *, max_backups=DEFAULT_MAX_BACKUPS, now=None):
    """Copy journal_path to '<dir>/<basename>.bak-<YYYYMMDD-HHMMSS-ffffff>',
    then prune to the newest `max_backups` (best-effort - a prune failure on
    one old backup doesn't stop the others). Returns the new backup's path.
    Propagates any exception from the copy itself.

    Includes microseconds in the timestamp so two backups created within
    the same wall-clock second (e.g. two quick clicks, or a fast automated
    test) get distinct filenames instead of the second one silently
    overwriting the first via shutil.copy2.
    """
    ensure_parent_dir(journal_path)
    timestamp = (now or datetime.now()).strftime("%Y%m%d-%H%M%S-%f")
    base_name = os.path.basename(journal_path)
    backup_dir = os.path.dirname(journal_path) or "."
    backup_path = os.path.join(backup_dir, f"{base_name}.bak-{timestamp}")
    shutil.copy2(journal_path, backup_path)

    backup_prefix = f"{base_name}.bak-"
    backups = sorted(
        (
            os.path.join(backup_dir, file_name)
            for file_name in os.listdir(backup_dir)
            if file_name.startswith(backup_prefix)
        ),
        reverse=True,
    )
    for old_backup in backups[max_backups:]:
        try:
            os.remove(old_backup)
        except OSError:
            pass

    return backup_path


def list_journal_backups(journal_path):
    """Return '<basename>.bak-*' paths beside journal_path, newest-first.
    Empty list if the containing directory doesn't exist."""
    base_name = os.path.basename(journal_path)
    backup_prefix = f"{base_name}.bak-"
    backup_dir = os.path.dirname(journal_path) or "."
    if not os.path.isdir(backup_dir):
        return []
    return sorted(
        (
            os.path.join(backup_dir, file_name)
            for file_name in os.listdir(backup_dir)
            if file_name.startswith(backup_prefix)
        ),
        reverse=True,
    )


def validate_backup_file(path):
    """Load and sanitize a candidate backup file for restore. Raises
    ValueError if the path doesn't exist or doesn't parse as valid journal
    data.

    Deliberately does not delegate path-existence handling to
    load_json_from_path: that function treats a missing path as "new empty
    journal" ([]), which is correct for the main journal file but wrong
    here - a restore candidate that doesn't exist (e.g. a mistyped path)
    must fail, not silently "restore" an empty journal.
    """
    if not os.path.exists(path):
        raise ValueError(f"'{path}' is not a valid journal backup file.")
    data = load_json_from_path(path, show_warnings=False)
    if data is None:
        raise ValueError(f"'{path}' is not a valid journal backup file.")
    return data


PASSWORD_ROTATION_SUCCESS_THRESHOLD = 0.9


def rotate_journal_password(data, old_password, new_password):
    """Re-encrypt every entry's 'entry' field from old_password to
    new_password. Per-entry failures are collected rather than aborting the
    whole rotation. Does not write or back up anything itself - the caller
    backs up first, checks success_ratio against
    PASSWORD_ROTATION_SUCCESS_THRESHOLD, and calls save_json.

    Returns (updated_data, failed_entries, success_ratio), where
    failed_entries is a list of {"date": ..., "reason": ...} dicts and
    success_ratio is successful_re-encryptions / total_encrypted_entries
    (1.0 if there were none).
    """
    updated_data = []
    failed_entries = []
    total_encrypted_entries = 0
    successful_updates = 0

    for entry in data:
        encrypted_entry = entry.get("entry")
        if not encrypted_entry:
            updated_data.append(entry)
            continue

        total_encrypted_entries += 1
        identifier = (
            entry.get("date")
            or entry.get("timestamp")
            or entry.get("created_at")
            or "Unknown entry"
        )
        try:
            plaintext = decrypt_message(encrypted_entry, old_password)
        except Exception as error:
            failed_entries.append({"date": identifier, "reason": str(error)})
            updated_data.append(entry)
            continue

        try:
            new_encrypted = encrypt_message(plaintext, new_password)
        except Exception as error:
            failed_entries.append({"date": identifier, "reason": str(error)})
            updated_data.append(entry)
            continue

        updated_entry = dict(entry)
        updated_entry["entry"] = new_encrypted
        updated_data.append(updated_entry)
        successful_updates += 1

    success_ratio = (
        successful_updates / total_encrypted_entries
        if total_encrypted_entries
        else 1.0
    )
    return updated_data, failed_entries, success_ratio


def log_password_rotation_failures(journal_path, failed_entries, *, now=None):
    """Append timestamped failure lines to
    '<dir>/password_rotation_failures.log' beside journal_path. Returns the
    log path, or None if failed_entries is empty."""
    if not failed_entries:
        return None
    log_path = os.path.join(
        os.path.dirname(journal_path) or ".", "password_rotation_failures.log"
    )
    timestamp = (now or datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"[{timestamp}] {failure['date']} - {failure['reason']}"
        for failure in failed_entries
    ]
    with open(log_path, "a", encoding="utf-8") as log_file:
        log_file.write("\n".join(lines) + "\n")
    return log_path


def configure_rotating_logger(
    journal_path,
    *,
    logger_name="encrypted_journal",
    env_file_var="ENCRYPTED_JOURNAL_LOG_FILE",
    env_level_var="ENCRYPTED_JOURNAL_LOG_LEVEL",
    default_level=logging.INFO,
    max_bytes=512 * 1024,
    backup_count=5,
):
    """Configure (idempotently - safe to call more than once) a named
    logger with a RotatingFileHandler. Log path: env_file_var if set, else
    '<dirname(journal_path)>/encrypted-journal.log'. Log level: env_level_var
    if set to a valid logging level name, else default_level. Falls back to
    a StreamHandler if the file handler can't be created (e.g. permission
    error), so the logger always has some handler attached - this is what
    keeps an unhandled record from ever falling through to
    logging.lastResort's raw stderr write.
    """
    logger = logging.getLogger(logger_name)
    logger.propagate = False

    level_name = os.environ.get(env_level_var)
    level = getattr(logging, level_name.upper(), default_level) if level_name else default_level
    logger.setLevel(level)

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    custom_path = os.environ.get(env_file_var)
    if custom_path:
        log_path = os.path.abspath(os.path.expanduser(custom_path))
    else:
        log_dir = os.path.dirname(journal_path) or "."
        log_path = os.path.join(log_dir, "encrypted-journal.log")

    try:
        log_dir = os.path.dirname(log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        handler = RotatingFileHandler(
            log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info("Logger initialized at %s", log_path)
    except Exception:
        fallback = logging.StreamHandler()
        fallback.setFormatter(formatter)
        logger.addHandler(fallback)
        logger.exception("Failed to initialize file logger at %s", log_path)

    return logger


def seconds_until_next_midnight(now=None):
    """Seconds from `now` (default datetime.now()) until the next local
    midnight, floored at a small positive minimum so a caller's timer API
    never sees a zero/negative delay."""
    current = now or datetime.now()
    next_midnight = datetime.combine(
        current.date() + timedelta(days=1), datetime.min.time()
    )
    return max(0.001, (next_midnight - current).total_seconds())


OMARCHY_STATE_DIR = os.path.expanduser("~/.local/state/omarchy")
DEFAULT_THEME_NAME_PATH = os.path.join(OMARCHY_STATE_DIR, "current", "theme.name")
DEFAULT_COLORS_TOML_PATH = os.path.join(
    OMARCHY_STATE_DIR, "current", "theme", "colors.toml"
)


def resolve_theme_name_path():
    """Resolve the path to Omarchy's current theme-name file, honoring the
    ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH override (used by tests)."""
    return os.environ.get(
        "ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH", DEFAULT_THEME_NAME_PATH
    )


def resolve_colors_toml_path():
    """Resolve the path to Omarchy's current colors.toml, honoring the
    ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH override (used by tests)."""
    return os.environ.get(
        "ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH", DEFAULT_COLORS_TOML_PATH
    )


def read_omarchy_colors(path=None):
    """Parse Omarchy's colors.toml. Returns None on any error (missing
    file, bad TOML, permission error, etc.) rather than raising."""
    if path is None:
        path = resolve_colors_toml_path()
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return None


def read_omarchy_theme_name(path=None):
    """Read Omarchy's theme.name file. Returns None on any error."""
    if path is None:
        path = resolve_theme_name_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            name = f.read().strip()
        return name or None
    except Exception:
        return None
