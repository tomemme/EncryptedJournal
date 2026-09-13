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
import tempfile
import logging
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
