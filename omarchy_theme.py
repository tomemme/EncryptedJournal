"""
Builds a Textual Theme from the current Omarchy desktop theme.

Omarchy (a Hyprland-based Arch desktop distro) exposes its active theme at
~/.local/state/omarchy/current/: theme.name (plain text, e.g. "osaka-jade")
and theme/colors.toml (the canonical, hand-authored palette - present for
every theme, unlike the per-app files templated from it such as
alacritty.toml). The raw file-reading lives in journal_core.py (shared with
secure_journal.py's own Omarchy integration); this module is the thin
Textual-specific layer on top of it. It never raises: any
missing/unreadable/malformed file results in load_omarchy_theme() returning
None, so journal_tui.py can call it unconditionally and fall back to
Textual's own default theme.
"""

import hashlib
import re

from textual.theme import Theme

from journal_core import (
    read_omarchy_colors,
    read_omarchy_theme_name,
    resolve_colors_toml_path,
    resolve_theme_name_path,
)

THEME_NAME_PREFIX = "omarchy"


def _pick(colors, *keys, fallback=None):
    """Return the first truthy value among colors[key] for key in keys."""
    for key in keys:
        value = colors.get(key)
        if value:
            return value
    return fallback


def _theme_slug(colors, name_hint):
    """Derive a content-stable slug identifying this theme: a sanitized
    version of the Omarchy theme name if available, else a short hash of
    the color values. Two different themes always get different slugs; the
    same theme (same name, or same colors) always gets the same slug - this
    is what lets JournalApp detect an actual theme change vs. a no-op poll.
    """
    if name_hint:
        slug = re.sub(r"[^a-z0-9-]+", "-", name_hint.strip().lower()).strip("-")
        if slug:
            return slug
    digest = hashlib.sha1(repr(sorted(colors.items())).encode()).hexdigest()[:8]
    return f"unnamed-{digest}"


def build_textual_theme(colors, name_hint=None):
    """Map a parsed Omarchy colors.toml dict to a textual.theme.Theme.

    Raises if `colors` doesn't even have a usable `accent`/`background`
    fallback chain result (i.e. is essentially empty) - callers that want
    the "never raises" guarantee should go through load_omarchy_theme().
    """
    slug = _theme_slug(colors, name_hint)
    mode = str(colors.get("mode", "dark")).strip().lower()

    return Theme(
        name=f"{THEME_NAME_PREFIX}-{slug}",
        primary=_pick(colors, "accent", fallback="#4e9a06"),
        secondary=_pick(colors, "muted", "dark_foreground"),
        warning=_pick(colors, "bright_yellow", "yellow"),
        error=_pick(colors, "bright_red", "red"),
        success=_pick(colors, "bright_green", "green"),
        accent=_pick(colors, "bright_magenta", "magenta", "bright_cyan", "cyan"),
        foreground=_pick(colors, "foreground", fallback="#e0e0e0"),
        background=_pick(colors, "background", fallback="#1e1e1e"),
        surface=_pick(
            colors, "dark_background", "darker_background", "background"
        ),
        panel=_pick(colors, "lighter_background", "selection", "background"),
        boost=_pick(colors, "selection"),
        dark=mode != "light",
    )


def load_omarchy_theme():
    """Load the current Omarchy theme as a Textual Theme, or None if
    Omarchy isn't present/readable/parseable on this machine. Never raises.
    """
    colors = read_omarchy_colors()
    if not colors:
        return None
    try:
        name_hint = read_omarchy_theme_name()
        return build_textual_theme(colors, name_hint)
    except Exception:
        return None
