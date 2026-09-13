#!/usr/bin/env python3
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import journal_core


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    try:
        # Check 1: tkinter not in sys.modules immediately after import
        _assert(
            "tkinter" not in sys.modules,
            "tkinter should not be in sys.modules after importing journal_core",
        )

        # Check 2: Encrypt/decrypt round-trip
        encrypted = journal_core.encrypt_message("hello", "pw")
        decrypted = journal_core.decrypt_message(encrypted, "pw")
        _assert(
            decrypted == "hello",
            f"Encrypt/decrypt round-trip failed: expected 'hello', got '{decrypted}'",
        )

        # Check 3: Wrong password raises ValueError
        encrypted_with_pw = journal_core.encrypt_message("hello", "pw")
        try:
            journal_core.decrypt_message(encrypted_with_pw, "wrong-pw")
            raise AssertionError(
                "decrypt_message should raise ValueError for wrong password"
            )
        except ValueError:
            pass  # Expected

        # Check 4: Save/load round-trip
        with tempfile.TemporaryDirectory(prefix="core-smoke-") as temp_dir:
            temp_path = os.path.join(temp_dir, "test_journal.json.gz")
            test_data = [{"date": "2026-01-01", "entry": "x"}]
            journal_core.save_json(temp_path, test_data)
            loaded_data = journal_core.load_json(temp_path)
            _assert(
                loaded_data == test_data,
                f"Save/load round-trip failed: expected {test_data}, got {loaded_data}",
            )

        # Check 5: Malformed-record sanitization
        raw_data = [
            {"date": "2026-01-01", "entry": "ok"},
            {"date": "not-a-date", "entry": "bad"},
            "not-a-dict",
        ]
        sanitized = journal_core.sanitize_journal_data(raw_data)
        _assert(
            len(sanitized) == 1,
            f"Sanitization should keep only 1 valid record, got {len(sanitized)}",
        )
        _assert(
            sanitized[0] == {"date": "2026-01-01", "entry": "ok"},
            f"Sanitization should preserve the first valid record, got {sanitized[0]}",
        )

        # Check 6: Env-var path override
        with tempfile.TemporaryDirectory(prefix="core-smoke-env-") as temp_dir:
            custom_path = os.path.join(temp_dir, "custom_journal.json.gz")
            original_env = os.environ.get("ENCRYPTED_JOURNAL_FILE")
            try:
                os.environ["ENCRYPTED_JOURNAL_FILE"] = custom_path
                resolved = journal_core.resolve_journal_path()
                expected = os.path.abspath(os.path.expanduser(custom_path))
                _assert(
                    resolved == expected,
                    f"resolve_journal_path should return {expected}, got {resolved}",
                )
            finally:
                if original_env is not None:
                    os.environ["ENCRYPTED_JOURNAL_FILE"] = original_env
                else:
                    os.environ.pop("ENCRYPTED_JOURNAL_FILE", None)

        print("PASS: core smoke test completed successfully.")
        return 0
    except Exception as error:
        print(f"FAIL: core smoke test failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
