#!/usr/bin/env python3
"""
Encrypted Journal - Omarchy theme integration smoke test.

Headless checks for omarchy_theme.py's parsing/mapping logic, fully
self-contained via the ENCRYPTED_JOURNAL_OMARCHY_*_PATH env overrides so it
runs the same in CI (no real Omarchy present) as on an Omarchy machine.
"""

import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

OSAKA_JADE_TOML = """
mode = "dark"

accent = "#509475"
selection = "#32473B"
muted = "#53685B"

background = "#111c18"
dark_background = "#0c1512"
darker_background = "#090f0d"
lighter_background = "#23372B"

foreground = "#C1C497"
dark_foreground = "#81B8A8"
light_foreground = "#D6D5BC"
bright_foreground = "#F7E8B2"

red = "#FF5345"
yellow = "#459451"
orange = "#a2734b"
green = "#549e6a"
cyan = "#2DD5B7"
blue = "#509475"
magenta = "#D2689C"
brown = "#513925"

bright_red = "#db9f9c"
bright_yellow = "#E5C736"
bright_green = "#63b07a"
bright_cyan = "#8CD3CB"
bright_blue = "#ACD4CF"
bright_magenta = "#75bbb3"
"""

MINIMAL_TOML = """
background = "#101010"
accent = "#abcdef"
"""


def _assert(condition, message):
    if not condition:
        raise AssertionError(message)


def _write(path, content):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def main():
    import omarchy_theme

    try:
        with tempfile.TemporaryDirectory(prefix="omarchy-theme-smoke-") as temp_dir:
            colors_path = os.path.join(temp_dir, "colors.toml")
            name_path = os.path.join(temp_dir, "theme.name")
            missing_path = os.path.join(temp_dir, "does-not-exist.toml")

            # Check 1: missing file -> None, no exception.
            _assert(
                omarchy_theme.read_omarchy_colors(missing_path) is None,
                "read_omarchy_colors should return None for a missing file.",
            )
            # Calling with the real default paths must never raise, whether
            # or not Omarchy is actually installed on this machine.
            omarchy_theme.load_omarchy_theme()

            # Check 2: malformed TOML -> None, no exception.
            _write(colors_path, "this is not [valid toml")
            _assert(
                omarchy_theme.read_omarchy_colors(colors_path) is None,
                "read_omarchy_colors should return None for malformed TOML.",
            )

            # Check 3: real osaka-jade fixture -> correct Theme field values.
            _write(colors_path, OSAKA_JADE_TOML)
            _write(name_path, "osaka-jade")
            colors = omarchy_theme.read_omarchy_colors(colors_path)
            _assert(colors is not None, "Expected osaka-jade colors.toml to parse.")
            theme = omarchy_theme.build_textual_theme(colors, "osaka-jade")
            _assert(
                theme.primary == "#509475",
                f"Expected primary #509475, got {theme.primary}",
            )
            _assert(theme.dark is True, "Expected dark mode for osaka-jade.")
            _assert(
                theme.background == "#111c18",
                f"Expected background #111c18, got {theme.background}",
            )
            _assert(
                theme.name == "omarchy-osaka-jade",
                f"Expected theme name 'omarchy-osaka-jade', got {theme.name!r}",
            )

            # Check 4: missing optional keys still builds via fallbacks.
            minimal_colors = {"background": "#101010", "accent": "#abcdef"}
            minimal_theme = omarchy_theme.build_textual_theme(minimal_colors, None)
            _assert(
                minimal_theme.primary == "#abcdef",
                "Expected primary fallback to accent for minimal colors.",
            )
            _assert(
                minimal_theme.warning is None,
                "warning should stay None (Textual's own default applies) "
                "when no yellow/bright_yellow key is present.",
            )

            # Check 5: theme-name stability/discrimination.
            same_again = omarchy_theme.build_textual_theme(colors, "osaka-jade")
            _assert(
                same_again.name == theme.name,
                "Rebuilding from identical content should yield the same name.",
            )
            other_theme = omarchy_theme.build_textual_theme(
                minimal_colors, "some-other-theme"
            )
            _assert(
                other_theme.name != theme.name,
                "Different themes must get different registered names.",
            )

            # Check 6: end-to-end load_omarchy_theme() via env overrides.
            original_colors_env = os.environ.get("ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH")
            original_name_env = os.environ.get(
                "ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH"
            )
            try:
                os.environ["ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH"] = colors_path
                os.environ["ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH"] = name_path
                loaded = omarchy_theme.load_omarchy_theme()
                _assert(
                    loaded is not None and loaded.name == "omarchy-osaka-jade",
                    "load_omarchy_theme should build the osaka-jade theme via "
                    f"env overrides, got {loaded}.",
                )

                os.environ["ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH"] = missing_path
                _assert(
                    omarchy_theme.load_omarchy_theme() is None,
                    "load_omarchy_theme should return None when colors.toml "
                    "is missing.",
                )
            finally:
                if original_colors_env is not None:
                    os.environ["ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH"] = (
                        original_colors_env
                    )
                else:
                    os.environ.pop("ENCRYPTED_JOURNAL_OMARCHY_COLORS_PATH", None)
                if original_name_env is not None:
                    os.environ["ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH"] = (
                        original_name_env
                    )
                else:
                    os.environ.pop(
                        "ENCRYPTED_JOURNAL_OMARCHY_THEME_NAME_PATH", None
                    )

        print("PASS: Omarchy theme smoke test completed successfully.")
        return 0
    except Exception as error:
        print(f"FAIL: Omarchy theme smoke test failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
