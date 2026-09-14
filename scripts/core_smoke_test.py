#!/usr/bin/env python3
import gzip
import json
import logging
import os
import sys
import tempfile
from datetime import datetime
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

        # Check 7: Backup creation + retention at DEFAULT_MAX_BACKUPS
        with tempfile.TemporaryDirectory(prefix="core-smoke-backup-") as temp_dir:
            journal_path = os.path.join(temp_dir, "journal.json.gz")
            with gzip.open(journal_path, "wt", encoding="utf-8") as f:
                json.dump([{"date": "2026-01-01", "entry": "x"}], f)

            backup_paths = []
            for i in range(12):
                backup_paths.append(
                    journal_core.create_journal_backup(
                        journal_path,
                        max_backups=10,
                        now=datetime(2026, 1, 1, 0, 0, i),
                    )
                )
            remaining = journal_core.list_journal_backups(journal_path)
            _assert(
                len(remaining) == 10,
                f"Expected 10 backups retained, got {len(remaining)}",
            )
            _assert(
                remaining == sorted(remaining, reverse=True),
                "list_journal_backups should return newest-first",
            )
            _assert(
                backup_paths[-1] in remaining and backup_paths[0] not in remaining,
                "Retention should keep the newest backups and prune the oldest",
            )

            # Check 8: validate_backup_file (valid + corrupt)
            valid_data = journal_core.validate_backup_file(remaining[0])
            _assert(
                valid_data == [{"date": "2026-01-01", "entry": "x"}],
                f"validate_backup_file should load valid backup content, got {valid_data}",
            )
            corrupt_path = os.path.join(temp_dir, "not-a-backup.gz")
            with open(corrupt_path, "wb") as f:
                f.write(b"not a gzip file at all")
            try:
                journal_core.validate_backup_file(corrupt_path)
                raise AssertionError(
                    "validate_backup_file should raise ValueError for a corrupt file"
                )
            except ValueError:
                pass  # Expected

        # Check 9: rotate_journal_password (full success + partial failure)
        entry_a = journal_core.encrypt_message("first entry", "old-pw")
        entry_b = journal_core.encrypt_message("second entry", "old-pw")
        data = [
            {"date": "2026-01-01", "entry": entry_a},
            {"date": "2026-01-02", "entry": entry_b},
        ]
        updated_data, failed_entries, success_ratio = journal_core.rotate_journal_password(
            data, "old-pw", "new-pw"
        )
        _assert(
            not failed_entries and success_ratio == 1.0,
            f"Expected full success, got failed={failed_entries} ratio={success_ratio}",
        )
        for original, updated in zip(data, updated_data):
            decrypted = journal_core.decrypt_message(updated["entry"], "new-pw")
            _assert(
                decrypted in ("first entry", "second entry"),
                f"Expected re-encrypted entry to decrypt under new password, got {decrypted!r}",
            )

        corrupted_data = [
            {"date": "2026-01-01", "entry": entry_a},
            {"date": "2026-01-02", "entry": "not-valid-ciphertext"},
        ]
        updated_data, failed_entries, success_ratio = journal_core.rotate_journal_password(
            corrupted_data, "old-pw", "new-pw"
        )
        _assert(
            len(failed_entries) == 1 and failed_entries[0]["date"] == "2026-01-02",
            f"Expected exactly one failure for the corrupted entry, got {failed_entries}",
        )
        _assert(
            success_ratio == 0.5,
            f"Expected a 0.5 success ratio for one success/one failure, got {success_ratio}",
        )
        _assert(
            updated_data[1]["entry"] == "not-valid-ciphertext",
            "A failed rotation should leave the original entry unchanged",
        )

        # Check 10: log_password_rotation_failures
        with tempfile.TemporaryDirectory(prefix="core-smoke-rotatelog-") as temp_dir:
            journal_path = os.path.join(temp_dir, "journal.json.gz")
            _assert(
                journal_core.log_password_rotation_failures(journal_path, []) is None,
                "log_password_rotation_failures should return None for an empty list",
            )
            log_path = journal_core.log_password_rotation_failures(
                journal_path,
                [{"date": "2026-01-02", "reason": "Incorrect password or corrupted data."}],
                now=datetime(2026, 1, 3, 12, 0, 0),
            )
            _assert(
                log_path == os.path.join(temp_dir, "password_rotation_failures.log"),
                f"Unexpected log path: {log_path}",
            )
            with open(log_path, encoding="utf-8") as f:
                content = f.read()
            _assert(
                "2026-01-02" in content and "Incorrect password" in content,
                f"Expected failure details in log file, got: {content!r}",
            )

        # Check 11: configure_rotating_logger (idempotent, writes to file)
        with tempfile.TemporaryDirectory(prefix="core-smoke-logger-") as temp_dir:
            journal_path = os.path.join(temp_dir, "journal.json.gz")
            logger_name = "core-smoke-test-logger"
            logger = journal_core.configure_rotating_logger(
                journal_path, logger_name=logger_name
            )
            logger = journal_core.configure_rotating_logger(
                journal_path, logger_name=logger_name
            )
            _assert(
                len(logger.handlers) == 1,
                f"configure_rotating_logger should be idempotent (1 handler), "
                f"got {len(logger.handlers)}",
            )
            logger.warning("smoke test warning line")
            for handler in logger.handlers:
                handler.flush()
            log_path = os.path.join(temp_dir, "encrypted-journal.log")
            _assert(os.path.exists(log_path), f"Expected log file at {log_path}")
            with open(log_path, encoding="utf-8") as f:
                log_content = f.read()
            _assert(
                "smoke test warning line" in log_content,
                f"Expected the warning to be written to the log file, got: {log_content!r}",
            )
            logging.getLogger(logger_name).handlers.clear()

        # Check 12: seconds_until_next_midnight
        near_midnight = journal_core.seconds_until_next_midnight(
            now=datetime(2026, 1, 1, 23, 59, 59)
        )
        _assert(
            0 < near_midnight <= 1,
            f"Expected ~1s until midnight, got {near_midnight}",
        )
        start_of_day = journal_core.seconds_until_next_midnight(
            now=datetime(2026, 1, 1, 0, 0, 0)
        )
        _assert(
            86399 < start_of_day <= 86400,
            f"Expected ~86400s until next midnight, got {start_of_day}",
        )

        print("PASS: core smoke test completed successfully.")
        return 0
    except Exception as error:
        print(f"FAIL: core smoke test failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
