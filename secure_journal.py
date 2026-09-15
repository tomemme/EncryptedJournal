import tkinter as tk
from tkinter import ttk, messagebox, font, filedialog
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import sys
import gzip
import json
from datetime import datetime
import getpass
try:
    import enchant
except ImportError:
    enchant = None
try:
    import keyring
except ImportError:
    keyring = None
import re
import string
import secrets
import tempfile
import logging
from contextlib import contextmanager
import journal_core
from journal_core import secure_password

# Windows-specific imports for file permissions
try:
    import win32security
    import ntsecuritycon as con
except ImportError:
    win32security = None
    con = None


def load_omarchy_theme():
    """Load the current Omarchy theme colors via the shared journal_core
    reader (the same current-theme source journal_tui.py's omarchy_theme.py
    uses: ~/.local/state/omarchy/current/theme.name + .../theme/colors.toml,
    not the old, stale ~/.config/omarchy/current/theme/alacritty.toml path),
    mapped to this GUI's {bg, fg, accent, cursor} shape. Falls back silently
    (returns None) if Omarchy isn't present or the file is unreadable.
    """
    colors = journal_core.read_omarchy_colors()
    if not colors:
        return None
    return {
        "bg": colors.get("background", "#1e1e2e"),
        "fg": colors.get("foreground", "#cdd6f4"),
        "accent": colors.get("accent", "#509475"),
        # The current colors.toml schema has no dedicated cursor entry;
        # foreground is the same effective fallback the old alacritty.toml
        # parsing used when no [colors.cursor] table was present.
        "cursor": colors.get("foreground", "#cdd6f4"),
    }

class SecureJournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encrypted Journal")
        self.set_app_icon()
        self.last_action_time = datetime.now()
        self.keyring_service = "encrypted-journal"
        self.keyring_username = os.environ.get(
            "ENCRYPTED_JOURNAL_KEYRING_USER", getpass.getuser() or "default"
        )
        self.keyring_enabled = self._env_bool("ENCRYPTED_JOURNAL_USE_KEYRING", False)
        self.keyring_available = keyring is not None and self.keyring_enabled
        self.filename = self._resolve_journal_path()
        self.logger = journal_core.configure_rotating_logger(self.filename)
        self.is_modified = False
        self.entry_loaded = False
        # Date of whichever entry is currently loaded into the editor (via
        # load_journal_entry or the overwrite guard in save_journal_entry),
        # or None. Lets save_journal_entry tell "resaving the entry the
        # user just loaded/was shown" apart from "about to silently
        # overwrite a different existing entry".
        self.loaded_entry_date = None
        self.failed_attempts = 0
        self.max_attempts = journal_core.DEFAULT_MAX_PASSWORD_ATTEMPTS
        self.dictionary = None
        self.spellcheck_enabled = False
        self.help_overlay = None
        self.help_overlay_content = None
        self.help_content_label = None
        self.help_overlay_title_label = None
        self.help_overlay_close_button = None
        self.settings_dialog = None
        self.password_remember_var = None
        self._init_spellchecker()
        self.current_theme = "dark"
        self.current_layout = None
        self._resize_after_id = None
        self._pending_geometry = None
        self._days_since_refresh_after_id = None
        self.base_text_size = 12
        self.base_tree_font_size = 11
        self.base_heading_font_size = 11
        self.base_tree_row_height = 24
        self.tree_row_height = self.base_tree_row_height
        self.text_font = font.Font(family="Verdana", size=self.base_text_size)
        self.tree_font = font.Font(family="Verdana", size=self.base_tree_font_size)
        self.tree_heading_font = font.Font(
            family="Verdana", size=self.base_heading_font_size, weight="bold"
        )
        self.last_typography_scale = None

        self.setup_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)
        self.refresh_days_since_label()
        self._schedule_days_since_refresh()
        self._bind_shortcuts()
        self.load_theme_file()  # strict: raise if missing
        self.apply_theme()
        self.omarchy_colors = load_omarchy_theme()
        if self.omarchy_colors:
            self.apply_omarchy_colors()
        self.apply_responsive_typography()
        self.update_theme_toggle_visibility()
        self.last_omarchy_theme_mtime = self._get_omarchy_theme_mtime()
        self._schedule_omarchy_theme_check()

    def _env_bool(self, name, default=False):
        return journal_core.env_bool(name, default)

    def _default_xdg_journal_path(self):
        return journal_core.default_xdg_journal_path()

    def _legacy_journal_path(self):
        return journal_core.legacy_journal_path()

    def _resolve_journal_path(self):
        return journal_core.resolve_journal_path()

    def _keyring_get_password(self):
        return journal_core.keyring_get_password(
            self.keyring_service, self.keyring_username,
            available=self.keyring_available, logger=self.logger,
        )

    def _keyring_set_password(self, password):
        journal_core.keyring_set_password(
            self.keyring_service, self.keyring_username, password,
            available=self.keyring_available, logger=self.logger,
        )

    def _keyring_clear_password(self):
        journal_core.keyring_clear_password(
            self.keyring_service, self.keyring_username,
            available=self.keyring_available, logger=self.logger,
        )

    def _init_spellchecker(self):
        if enchant is None:
            self.logger.info("Spellcheck disabled: pyenchant is not installed.")
            return
        try:
            self.dictionary = enchant.Dict("en_US")
            self.spellcheck_enabled = True
        except Exception as error:
            self.dictionary = None
            self.spellcheck_enabled = False
            self.logger.warning("Spellcheck disabled: %s", error)

    def _get_help_palette(self):
        if getattr(self, "omarchy_colors", None):
            return {
                "bg": self.omarchy_colors["bg"],
                "fg": self.omarchy_colors["fg"],
                "accent": self.omarchy_colors["accent"],
            }
        if self.current_theme == "light":
            return {"bg": "#f5f6fa", "fg": "#1f2937", "accent": "#3b82f6"}
        return {"bg": "#0f111a", "fg": "#e5e7eb", "accent": "#7c93f6"}

    def _blend_hex(self, color, target, factor):
        color = color.lstrip("#")
        target = target.lstrip("#")
        if len(color) != 6 or len(target) != 6:
            return f"#{color}"
        try:
            r = int(color[0:2], 16)
            g = int(color[2:4], 16)
            b = int(color[4:6], 16)
            rt = int(target[0:2], 16)
            gt = int(target[2:4], 16)
            bt = int(target[4:6], 16)
        except ValueError:
            return f"#{color}"

        nr = min(255, max(0, int(r + (rt - r) * factor)))
        ng = min(255, max(0, int(g + (gt - g) * factor)))
        nb = min(255, max(0, int(b + (bt - b) * factor)))
        return f"#{nr:02x}{ng:02x}{nb:02x}"

    def _best_text_color(self, background_hex):
        hex_color = background_hex.lstrip("#")
        if len(hex_color) != 6:
            return "#ffffff"
        try:
            r = int(hex_color[0:2], 16)
            g = int(hex_color[2:4], 16)
            b = int(hex_color[4:6], 16)
        except ValueError:
            return "#ffffff"

        # Perceived luminance heuristic for readable foreground selection.
        luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255.0
        return "#111111" if luminance > 0.62 else "#f8fafc"

    def _get_selection_colors(self):
        if getattr(self, "omarchy_colors", None):
            bg = self.omarchy_colors["accent"]
            fg = self._best_text_color(bg)
            return bg, fg
        if self.current_theme == "light":
            bg = "#3b82f6"
            fg = self._best_text_color(bg)
            return bg, fg
        bg = "#7c93f6"
        fg = self._best_text_color(bg)
        return bg, fg

    def _apply_text_selection_style(self):
        select_bg, select_fg = self._get_selection_colors()
        widgets = []
        if hasattr(self, "text_entry"):
            widgets.append(self.text_entry)
        if hasattr(self, "date_entry"):
            widgets.append(self.date_entry)

        for widget in widgets:
            try:
                widget.configure(
                    selectbackground=select_bg,
                    selectforeground=select_fg,
                    inactiveselectbackground=select_bg,
                )
            except tk.TclError:
                pass

    def _apply_help_button_style(self):
        if not hasattr(self, "help_button"):
            return
        colors = self._get_help_palette()
        button_fg = self._best_text_color(colors["accent"])
        try:
            self.help_button.configure(
                bg=colors["accent"],
                fg=button_fg,
                activebackground=colors["accent"],
                activeforeground=button_fg,
                highlightbackground=colors["bg"],
                highlightcolor=colors["accent"],
            )
        except tk.TclError:
            pass

    def _style_help_overlay(self):
        if not self.help_overlay or not self.help_overlay.winfo_exists():
            return

        colors = self._get_help_palette()
        button_fg = self._best_text_color(colors["accent"])
        try:
            self.help_overlay.configure(bg=colors["bg"])
            if hasattr(self, "help_overlay_content"):
                self.help_overlay_content.configure(bg=colors["bg"])
            if self.help_overlay_title_label:
                self.help_overlay_title_label.configure(
                    bg=colors["bg"], fg=colors["fg"]
                )
            if self.help_content_label:
                self.help_content_label.configure(bg=colors["bg"], fg=colors["fg"])
            if self.help_overlay_close_button:
                self.help_overlay_close_button.configure(
                    bg=colors["accent"],
                    fg=button_fg,
                    activebackground=colors["accent"],
                    activeforeground=button_fg,
                    highlightbackground=colors["bg"],
                )
        except tk.TclError:
            pass

    def _position_help_overlay(self):
        if not self.help_overlay or not self.help_overlay.winfo_exists():
            return

        self.root.update_idletasks()
        root_width = max(1, self.root.winfo_width())
        root_height = max(1, self.root.winfo_height())

        # Keep the overlay ~10% smaller than the parent journal window.
        width = max(320, min(root_width - 20, int(root_width * 0.9)))
        height = max(260, min(root_height - 20, int(root_height * 0.9)))

        root_x = self.root.winfo_rootx()
        root_y = self.root.winfo_rooty()
        x = root_x + max(0, (root_width - width) // 2)
        y = root_y + max(0, (root_height - height) // 2)

        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = max(0, min(x, max(0, screen_w - width)))
        y = max(0, min(y, max(0, screen_h - height)))
        self.help_overlay.geometry(f"{width}x{height}+{x}+{y}")

    def _sync_help_overlay_geometry(self):
        if not self.help_overlay or not self.help_overlay.winfo_exists():
            return
        self._position_help_overlay()
        if self.help_content_label and self.help_content_label.winfo_exists():
            wrap = max(220, self.help_overlay.winfo_width() - 80)
            self.help_content_label.configure(wraplength=wrap)
        self.help_overlay.after(140, self._sync_help_overlay_geometry)

    def close_help_overlay(self, event=None):
        if self.help_overlay and self.help_overlay.winfo_exists():
            self.help_overlay.destroy()
        self.help_overlay = None
        self.help_overlay_content = None
        self.help_content_label = None
        self.help_overlay_title_label = None
        self.help_overlay_close_button = None

    def close_settings_dialog(self, event=None):
        if self.settings_dialog and self.settings_dialog.winfo_exists():
            self.settings_dialog.destroy()
        self.settings_dialog = None

    def _open_settings_action(self, action):
        self.close_settings_dialog()
        action()

    def show_help_overlay(self):
        if self.help_overlay and self.help_overlay.winfo_exists():
            try:
                self.help_overlay.lift()
                self.help_overlay.focus_force()
            except tk.TclError:
                pass
            return

        overlay = tk.Toplevel(self.root)
        self.help_overlay = overlay
        overlay.title("Journal Help")
        overlay.transient(self.root)
        overlay.grab_set()
        overlay.resizable(True, True)
        overlay.protocol("WM_DELETE_WINDOW", self.close_help_overlay)
        overlay.bind("<Escape>", self.close_help_overlay)

        self._position_help_overlay()

        self.help_overlay_content = tk.Frame(overlay, padx=28, pady=24)
        self.help_overlay_content.pack(fill=tk.BOTH, expand=True)

        header = tk.Frame(self.help_overlay_content)
        header.pack(fill=tk.X, pady=(0, 14))

        self.help_overlay_title_label = tk.Label(
            header, text="How To Use Encrypted Journal", font=("Verdana", 15, "bold")
        )
        self.help_overlay_title_label.pack(side=tk.LEFT)

        self.help_overlay_close_button = tk.Button(
            header,
            text="Close",
            command=self.close_help_overlay,
            bd=0,
            padx=12,
            pady=6,
            cursor="hand2",
        )
        self.help_overlay_close_button.pack(side=tk.RIGHT)

        help_text = (
            "1. Enter a date (YYYY-MM-DD), or leave it blank to use today.\n\n"
            "2. Write your journal entry in the text area.\n\n"
            "3. Click Save and enter your password.\n\n"
            "4. To read an entry, select a date on the right and click Load.\n\n"
            "5. To remove an entry, select a date and click Delete.\n\n"
            "6. Use Settings for backups and password rotation.\n\n"
            "Shortcuts:\n"
            "- Ctrl/Cmd+S: Save\n"
            "- Ctrl/Cmd+L: Load selected entry\n"
            "- Ctrl/Cmd+D: Delete selected entry\n"
            "- Ctrl/Cmd+H: Open Help\n\n"
            "Tips:\n"
            "- Keep your password in a safe place (Your Mind). Lost passwords cannot be recovered.\n"
            "- Settings lets you create a backup, restore a backup, or rotate the journal password.\n"
            "- Password changes create timestamped backups beside your journal file."
        )

        self.help_content_label = tk.Label(
            self.help_overlay_content,
            text=help_text,
            justify=tk.LEFT,
            anchor="nw",
            font=("Verdana", 11),
            wraplength=max(220, int(self.root.winfo_width() * 0.9) - 80),
        )
        self.help_content_label.pack(fill=tk.BOTH, expand=True)

        self._style_help_overlay()
        overlay.lift()
        overlay.focus_force()
        self._sync_help_overlay_geometry()

    def show_settings_dialog(self):
        if self.settings_dialog and self.settings_dialog.winfo_exists():
            try:
                self.settings_dialog.lift()
                self.settings_dialog.focus_force()
            except tk.TclError:
                pass
            return

        dialog = tk.Toplevel(self.root)
        self.settings_dialog = dialog
        dialog.title("Journal Settings")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.protocol("WM_DELETE_WINDOW", self.close_settings_dialog)
        dialog.bind("<Escape>", self.close_settings_dialog)

        body = ttk.Frame(dialog, padding=22, style="Omarchy.TFrame")
        body.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            body,
            text="Journal Settings",
            style="Omarchy.TLabel",
            font=("Verdana", 14, "bold"),
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(
            body,
            text="Select a maintenance action.",
            style="Omarchy.TLabel",
        ).pack(anchor="w", pady=(0, 16))

        actions = ttk.Frame(body, style="Omarchy.TFrame")
        actions.pack(fill=tk.X)
        actions.columnconfigure(0, weight=1)

        button_options = [
            ("Create Backup Now", self.create_manual_backup),
            ("Restore From Backup", self.restore_journal_backup),
            ("Rotate Password", self.change_journal_password),
        ]
        for row_index, (label, command) in enumerate(button_options):
            ttk.Button(
                actions,
                text=label,
                command=lambda action=command: self._open_settings_action(action),
                style="Omarchy.TButton",
            ).grid(row=row_index, column=0, sticky="ew", pady=4)

        ttk.Button(
            body,
            text="Close",
            command=self.close_settings_dialog,
            style="Omarchy.TButton",
        ).pack(anchor="e", pady=(16, 0))

        self._show_modal_dialog(dialog)
        dialog.wait_window()

    def _tk_major_version(self):
        """Cached major version of the running Tcl/Tk (e.g. 9 for 9.0.4)."""
        if not hasattr(self, "_tk_major_version_cache"):
            try:
                patchlevel = self.root.tk.call("info", "patchlevel")
                self._tk_major_version_cache = int(str(patchlevel).split(".")[0])
            except Exception:
                # Unknown/unparseable version: assume the newer, stricter
                # Tk 9 behavior rather than risk treating it as safe.
                self._tk_major_version_cache = 9
        return self._tk_major_version_cache

    def _tk_supports_image_style_overrides(self):
        """Whether it's safe to override Button/Scrollbar ttk layouts with
        custom flat-color image elements (see
        apply_omarchy_colors below).

        Azure's own layouts for these already use baked PNG images, so
        recoloring them requires swapping in our own image elements via a
        custom ttk::style layout. This works correctly under Tcl/Tk 8.6,
        but under Tk 9.0.4 the exact same calls have been observed to hang
        the app's event loop entirely (unresponsive, unclosable window) -
        likely a Tk 9 regression in image-element/layout handling. Until
        that's root-caused, only enable this on Tk 8.
        """
        return self._tk_major_version() < 9

    def _fix_tk9_treeview_disclosure_indicator(self):
        """Work around a Tk 9 regression where Azure's own baked-image
        Treeitem.indicator ignores the 'leaf'/'open' ttk states entirely -
        every row (including leaf/dated entries with no children) renders
        the same static disclosure triangle, regardless of whether it has
        children or is expanded/collapsed. Confirmed Azure-specific: the
        stock 'clam' theme's own (non-image, vector-drawn) indicator
        responds to both states correctly under the same Tk 9 build.

        Fix: borrow clam's indicator element under a new name (ttk's
        documented "element create <name> from <theme> <sourceElement>"
        idiom - reusing an existing, working element, not defining a new
        custom image element, which is the operation already confirmed to
        hang the event loop under Tk 9 - see
        _tk_supports_image_style_overrides), then point the azure theme's
        own Treeview.Item layout at it instead of Azure's broken element.
        Only the indicator changes; Treeitem.image/text/padding stay
        Azure's.

        Azure's Treeview.Item layout (and the Treeitem.indicator element
        itself) is defined per-theme (inside each azure-dark/azure-light
        theme's own `ttk::style theme settings` block in theme/dark.tcl
        and theme/light.tcl), so both element creation and the layout
        override apply to whichever azure-* theme is currently active -
        this must be (and is, via apply_theme) called again after every
        theme switch. Re-creating the borrowed element for a theme it was
        already created under raises a "Duplicate element" TclError - one
        is expected and ignored on every toggle back to a previously-seen
        theme; the layout override itself is safely re-appliable every
        time.
        """
        if self._tk_major_version() < 9:
            return  # Azure's own indicator already works correctly here.

        try:
            self.root.tk.call(
                "ttk::style", "element", "create", "Fixed.Treeitem.indicator",
                "from", "clam", "Treeitem.indicator",
            )
        except tk.TclError:
            pass  # Already created for this theme on an earlier toggle.

        item_layout = (
            "Treeitem.padding", "-sticky", "nswe", "-children", (
                "Fixed.Treeitem.indicator", "-side", "left", "-sticky", "",
                "Treeitem.image", "-side", "left", "-sticky", "",
                "Treeitem.text", "-side", "left", "-sticky", "",
            ),
        )
        try:
            self.root.tk.call("ttk::style", "layout", "Treeview.Item", item_layout)
        except tk.TclError as e:
            self.logger.warning(
                "Could not apply the Tk 9 treeview indicator fix: %s", e
            )

    def apply_omarchy_colors(self):
        """
        Inject Omarchy colors into the azure theme before applying it.
        """
        colors = self.omarchy_colors
        if not colors:
            return

        try:
            # dynamically update tk palette
            self.root.tk_setPalette(
                background=colors["bg"],
                foreground=colors["fg"],
                activeBackground=colors["accent"],
                activeForeground=colors["fg"],
                highlightColor=colors["accent"]
            )

            # text widget background + fg
            self.text_entry.config(
                bg=colors["bg"],
                fg=colors["fg"],
                insertbackground=colors["cursor"]
            )
            self._apply_text_selection_style()

            # --- ttk widget styling (buttons + treeview) ---
            style = ttk.Style()

            accent_hover = self._blend_hex(colors["accent"], "ffffff", 0.18)
            accent_pressed = self._blend_hex(colors["accent"], "000000", 0.22)
            accent_disabled = self._blend_hex(colors["accent"], colors["bg"], 0.55)
            button_fg = self._best_text_color(colors["accent"])
            text_disabled = self._blend_hex(button_fg, colors["bg"], 0.65)

            style.configure(
                "Omarchy.TButton",
                background=colors["accent"],
                foreground=button_fg,
                # bordercolor/lightcolor/darkcolor/relief only matter to the
                # Tk-9 borrowed-clam button element below (clam's
                # Button.border fills using these, not "background") - set
                # unconditionally since they're harmless no-ops for the Tk-8
                # image element, which ignores them entirely.
                bordercolor=colors["accent"],
                lightcolor=colors["accent"],
                darkcolor=colors["accent"],
                relief="flat",
                borderwidth=0,
                focusthickness=1,
                focuscolor=colors["accent"],
                padding=(12, 6)
            )
            style.map(
                "Omarchy.TButton",
                background=[
                    ("!disabled", colors["accent"]),
                    ("active", accent_hover),
                    ("pressed", accent_pressed),
                    ("disabled", accent_disabled),
                ],
                bordercolor=[
                    ("!disabled", colors["accent"]),
                    ("active", accent_hover),
                    ("pressed", accent_pressed),
                    ("disabled", accent_disabled),
                ],
                lightcolor=[
                    ("!disabled", colors["accent"]),
                    ("active", accent_hover),
                    ("pressed", accent_pressed),
                    ("disabled", accent_disabled),
                ],
                darkcolor=[
                    ("!disabled", colors["accent"]),
                    ("active", accent_hover),
                    ("pressed", accent_pressed),
                    ("disabled", accent_disabled),
                ],
                foreground=[
                    ("!disabled", button_fg),
                    ("disabled", text_disabled)
                ]
            )

            button_element_name = "Omarchy.Button.button"
            if self._tk_supports_image_style_overrides():
                # Azure's TButton layout draws a baked PNG image
                # (Button.button) for the button body, which ignores the
                # plain "background"/"foreground" options configured
                # above - same root cause, same fix as the Treeview field
                # background below: swap in a flat-color image element via
                # a custom layout, keeping Azure's own Button.padding/
                # Button.label children so text placement/padding still
                # behaves normally.
                if not hasattr(self, "_omarchy_button_image"):
                    self._omarchy_button_image = tk.PhotoImage(width=2, height=2)
                self._omarchy_button_image.put(colors["accent"], to=(0, 0, 2, 2))

                try:
                    if button_element_name not in style.element_names():
                        style.element_create(
                            button_element_name,
                            "image",
                            self._omarchy_button_image,
                            border=0,
                            sticky="nswe",
                        )
                except tk.TclError:
                    pass
            else:
                # Tk 9: defining a brand-new custom image element (the
                # branch above) is the exact operation confirmed to hang
                # the event loop under Tk 9 - see
                # _tk_supports_image_style_overrides. Instead, borrow
                # clam's own Button.border element under a new name (ttk's
                # documented "element create <name> from <theme>
                # <sourceElement>" idiom, reusing an existing, working
                # element rather than defining a new image one - the same
                # fix pattern already used for the Tk-9 treeview disclosure
                # indicator). Unlike Azure's baked image, clam's
                # Button.border actually honors the bordercolor/lightcolor/
                # darkcolor configured above, giving a real flat accent
                # fill. This element is per-theme scoped, so a "Duplicate
                # element" on re-entering a previously-seen theme (e.g. a
                # light/dark toggle back) is expected and harmless.
                try:
                    style.element_create(
                        button_element_name, "from", "clam", "Button.border"
                    )
                except tk.TclError:
                    pass

            style.layout(
                "Omarchy.TButton",
                [
                    (
                        button_element_name,
                        {
                            "sticky": "nswe",
                            "children": [
                                (
                                    "Button.padding",
                                    {
                                        "sticky": "nswe",
                                        "children": [
                                            ("Button.label", {"sticky": "nswe"})
                                        ],
                                    },
                                )
                            ],
                        },
                    )
                ],
            )

            style.configure(
                "Omarchy.TFrame",
                background=colors["bg"]
            )
            style.configure(
                "Omarchy.TLabel",
                background=colors["bg"],
                foreground=colors["fg"]
            )

            # Treeview styling
            if not hasattr(self, "_omarchy_tree_field_image"):
                self._omarchy_tree_field_image = tk.PhotoImage(width=2, height=2)
            self._omarchy_tree_field_image.put(colors["bg"], to=(0, 0, 2, 2))

            element_name = "Omarchy.Treeview.field"
            try:
                if element_name not in style.element_names():
                    style.element_create(
                        element_name,
                        "image",
                        self._omarchy_tree_field_image,
                        border=0,
                        sticky="nswe",
                    )
            except tk.TclError:
                pass

            style.layout(
                "Omarchy.Treeview",
                [
                    (
                        element_name,
                        {
                            "sticky": "nswe",
                            "children": [
                                (
                                    "Treeview.padding",
                                    {
                                        "sticky": "nswe",
                                        "children": [
                                            ("Treeview.treearea", {"sticky": "nswe"})
                                        ],
                                    },
                                )
                            ],
                        },
                    )
                ],
            )

            style.configure(
                "Omarchy.Treeview",
                background=colors["bg"],
                foreground=colors["fg"],
                fieldbackground=colors["bg"],
                borderwidth=0,
                rowheight=self.tree_row_height,
                relief="flat",
                bordercolor=colors["bg"],
                lightcolor=colors["bg"],
                darkcolor=colors["bg"],
            )
            style.map(
                "Omarchy.Treeview",
                background=[
                    ("selected", colors["accent"]),
                    ("!selected", colors["bg"]),
                ],
                foreground=[
                    ("selected", colors["bg"]),
                    ("!selected", colors["fg"]),
                ],
                fieldbackground=[("!selected", colors["bg"])],
                bordercolor=[("!selected", colors["bg"])],
                lightcolor=[("!selected", colors["bg"])],
                darkcolor=[("!selected", colors["bg"])],
            )

            style.configure(
                "Treeview",
                background=colors["bg"],
                foreground=colors["fg"],
                fieldbackground=colors["bg"],
                borderwidth=0,
                rowheight=self.tree_row_height,
                relief="flat",
                bordercolor=colors["bg"],
                lightcolor=colors["bg"],
                darkcolor=colors["bg"]
            )
            style.map(
                "Treeview",
                background=[
                    ("selected", colors["accent"]),
                    ("!selected", colors["bg"]),
                ],
                foreground=[
                    ("selected", colors["bg"]),
                    ("!selected", colors["fg"]),
                ],
                fieldbackground=[("!selected", colors["bg"])],
                bordercolor=[("!selected", colors["bg"])],
                lightcolor=[("!selected", colors["bg"])],
                darkcolor=[("!selected", colors["bg"])],
            )

            # No Treeview.Heading styling: the journal tree has no columns
            # and no clickable/sortable heading (see the static
            # tree_header_accent separator set below instead, which needs
            # none of Azure's/Tk 9's Heading-element quirks since it's a
            # plain tk.Frame, not a ttk style).
            if hasattr(self, "tree_header_accent"):
                self.tree_header_accent.config(background=colors["accent"])

            # Scrollbar styling. background (thumb) is the accent color at
            # rest, same as buttons/selection - not just on hover: on Tk 8,
            # the thumb has always been a solid-accent baked image
            # regardless of state (the "background"/"map" values below were
            # only ever read by the trough, not the ignore-everything image
            # thumb), so a bg-colored resting thumb here would be a Tk-9-only
            # regression relative to how this has always actually looked.
            style.configure(
                "Vertical.TScrollbar",
                background=colors["accent"],
                troughcolor=colors["bg"],
                arrowcolor=colors["fg"],
                bordercolor=colors["bg"],
                relief="flat"
            )
            style.map(
                "Vertical.TScrollbar",
                background=[
                    ("active", accent_hover),
                    ("pressed", accent_pressed),
                    ("!disabled", colors["accent"]),
                ]
            )

            style.configure(
                "Horizontal.TScrollbar",
                background=colors["accent"],
                troughcolor=colors["bg"],
                arrowcolor=colors["fg"],
                bordercolor=colors["bg"],
                relief="flat"
            )
            style.map(
                "Horizontal.TScrollbar",
                background=[
                    ("active", accent_hover),
                    ("pressed", accent_pressed),
                    ("!disabled", colors["accent"]),
                ]
            )

            if self._tk_supports_image_style_overrides():
                # Azure's scrollbar trough/thumb are image-based too (same
                # root cause again): swap in flat-colored images for both,
                # so the scrollbar actually reflects the theme instead of
                # staying Azure's default gray.
                if not hasattr(self, "_omarchy_scrollbar_trough_image"):
                    self._omarchy_scrollbar_trough_image = tk.PhotoImage(
                        width=2, height=2
                    )
                self._omarchy_scrollbar_trough_image.put(colors["bg"], to=(0, 0, 2, 2))
                if not hasattr(self, "_omarchy_scrollbar_thumb_image"):
                    self._omarchy_scrollbar_thumb_image = tk.PhotoImage(
                        width=2, height=2
                    )
                self._omarchy_scrollbar_thumb_image.put(
                    colors["accent"], to=(0, 0, 2, 2)
                )

                trough_element_name = "Omarchy.Scrollbar.trough"
                thumb_element_name = "Omarchy.Scrollbar.thumb"
                try:
                    if trough_element_name not in style.element_names():
                        style.element_create(
                            trough_element_name,
                            "image",
                            self._omarchy_scrollbar_trough_image,
                            border=0,
                            sticky="nswe",
                        )
                    if thumb_element_name not in style.element_names():
                        style.element_create(
                            thumb_element_name,
                            "image",
                            self._omarchy_scrollbar_thumb_image,
                            border=0,
                            sticky="nswe",
                        )
                except tk.TclError:
                    pass

                for orientation, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
                    style.layout(
                        f"{orientation}.TScrollbar",
                        [
                            (
                                trough_element_name,
                                {
                                    "sticky": sticky,
                                    "children": [
                                        (
                                            thumb_element_name,
                                            {"expand": "1", "sticky": "nswe"},
                                        )
                                    ],
                                },
                            )
                        ],
                    )
            else:
                # Tk 9: borrow-from-clam idiom again, per orientation (clam
                # keeps separate Vertical.*/Horizontal.* trough+thumb
                # elements, unlike the single shared pair the Tk-8 image
                # branch above uses - a flat solid-color image doesn't
                # care about orientation, but the borrowed elements are
                # theme-native ones that do). Deliberately keeps Azure's
                # own minimal trough+thumb-only layout shape (no separate
                # up/down or left/right arrow elements, unlike clam's own
                # native layout) so the flat, arrow-less look this app
                # already has doesn't change - only the color
                # configurability does.
                for orientation, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
                    trough_element_name = f"Fixed.{orientation}.Scrollbar.trough"
                    thumb_element_name = f"Fixed.{orientation}.Scrollbar.thumb"
                    try:
                        style.element_create(
                            trough_element_name, "from", "clam",
                            f"{orientation}.Scrollbar.trough",
                        )
                        style.element_create(
                            thumb_element_name, "from", "clam",
                            f"{orientation}.Scrollbar.thumb",
                        )
                    except tk.TclError:
                        pass

                    style.layout(
                        f"{orientation}.TScrollbar",
                        [
                            (
                                trough_element_name,
                                {
                                    "sticky": sticky,
                                    "children": [
                                        (
                                            thumb_element_name,
                                            {"expand": "1", "sticky": "nswe"},
                                        )
                                    ],
                                },
                            )
                        ],
                    )

            # Make ttk default background match theme
            style.configure(
                ".",  # default ttk style root
                background=colors["bg"],
                foreground=colors["fg"]
            )

            # Style entry widgets (date input field)
            try:
                self.date_entry.config(
                    bg=colors["bg"],
                    fg=colors["fg"],
                    insertbackground=colors["cursor"],
                    highlightbackground=colors["accent"],
                    highlightcolor=colors["accent"]
                )
            except:
                pass

            try:
                self.date_label.config(bg=colors["bg"], fg=colors["fg"])
                self.date_frame.config(bg=colors["bg"])
                self.date_inner.config(bg=colors["bg"])
            except tk.TclError:
                pass

            try:
                self.days_since_label.configure(style="Omarchy.TLabel")
            except tk.TclError:
                pass

            for frame in (
                self.editor_container,
                self.controls_frame,
                self.tree_container,
                self.button_frame,
                self.tree_frame,
            ):
                try:
                    frame.configure(style="Omarchy.TFrame")
                except tk.TclError:
                    pass

            try:
                self.treeview.configure(style="Omarchy.Treeview")
            except tk.TclError:
                pass

            # Remove harsh frame borders (make them inherit bg)
            for frame in (self.button_frame, self.tree_frame, self.date_frame):
                try:
                    frame.config(bg=colors["bg"], highlightbackground=colors["bg"])
                except Exception:
                    pass

            self._apply_help_button_style()
            self._style_help_overlay()

        except Exception as e:
            self.logger.exception("Failed to apply Omarchy theme: %s", e)
        finally:
            # Re-apply responsive fonts in case the theme reset them
            self.apply_responsive_typography()

    def apply_responsive_typography(self):
        scale = self._compute_display_scale()
        self.last_typography_scale = scale

        text_size = max(self.base_text_size, int(round(self.base_text_size * scale)))
        tree_size = max(
            self.base_tree_font_size, int(round(self.base_tree_font_size * scale))
        )
        heading_size = max(
            self.base_heading_font_size, int(round(self.base_heading_font_size * scale))
        )
        row_height = max(
            self.base_tree_row_height, int(round(self.base_tree_row_height * scale))
        )

        self.text_font.configure(size=text_size)
        self.tree_font.configure(size=tree_size)
        self.tree_heading_font.configure(size=heading_size)
        self.tree_row_height = row_height

        try:
            default_font = font.nametofont("TkDefaultFont")
            default_font.configure(size=max(11, int(round(11 * scale))))
        except tk.TclError:
            pass

        style = ttk.Style()
        style.configure("Treeview", font=self.tree_font, rowheight=row_height)
        style.configure("Treeview.Heading", font=self.tree_heading_font)
        style.configure("Omarchy.Treeview", font=self.tree_font, rowheight=row_height)
        style.configure("Omarchy.Treeview.Heading", font=self.tree_heading_font)
        style.configure("Omarchy.TButton", font=self.tree_font)
        style.configure("TButton", font=self.tree_font)
        style.configure("Omarchy.TLabel", font=self.tree_font)
        style.configure("TLabel", font=self.tree_font)

        try:
            self.text_entry.configure(font=self.text_font)
        except tk.TclError:
            pass

    def _compute_display_scale(self):
        screen_width, screen_height = self._get_screen_size()

        dpi_scale = 1.0
        try:
            dpi = float(self.root.winfo_fpixels("1i"))
            if dpi > 0:
                dpi_scale = dpi / 96.0
        except Exception:
            dpi_scale = 1.0

        tk_scaling = self._get_tk_scaling()

        geometry_scale = 1.0
        try:
            width = self.root.winfo_width()
            height = self.root.winfo_height()
            if width <= 1 or height <= 1:
                self.root.update_idletasks()
                width = self.root.winfo_width()
                height = self.root.winfo_height()
            if width > 1 and height > 1:
                geometry_scale = min(
                    1.35, max(1.0, min(width / 1280, height / 720))
                )
        except Exception:
            geometry_scale = 1.0

        screen_scale = _screen_resolution_scale(screen_width, screen_height)

        base_scale = max(1.0, dpi_scale, geometry_scale, screen_scale)
        scale = self._platform_scale_adjust(
            base_scale,
            dpi_scale,
            tk_scaling,
            screen_width,
            screen_height,
        )
        return max(1.0, scale)

    def _get_screen_size(self):
        try:
            width = max(1, int(self.root.winfo_screenwidth()))
            height = max(1, int(self.root.winfo_screenheight()))
            return width, height
        except Exception:
            return 1920, 1080

    def _get_tk_scaling(self):
        try:
            scaling = float(self.root.tk.call("tk", "scaling"))
            if scaling <= 0:
                return 1.0
            return scaling
        except Exception:
            return 1.0

    def _platform_scale_adjust(
        self, base_scale, dpi_scale, tk_scaling, screen_width, screen_height
    ):
        scale = max(1.0, base_scale)
        hidpi_resolution = _looks_like_hidpi_laptop(screen_width, screen_height)
        hidpi_signal = dpi_scale >= 1.42 or tk_scaling >= 1.42 or hidpi_resolution
        try:
            if sys.platform == "darwin":
                # Older mac hardware often reports ~72 DPI with tk scaling near 1.0.
                # Push those panels to a noticeably larger baseline so text climbs
                # roughly two points while still respecting explicit tk scaling.
                if hidpi_resolution:
                    scale = max(scale, 1.34)
                elif dpi_scale < 1.3:
                    scale = max(scale, 1.22)
                else:
                    scale = max(scale, min(dpi_scale, 1.32))
                if tk_scaling > scale:
                    scale = tk_scaling
                return min(scale, 1.46)
            else:
                if hidpi_signal:
                    boosted = max(base_scale, dpi_scale, tk_scaling, 1.24)
                    return min(boosted, 1.38)

                # Temper automatic scaling so Windows/Linux builds that already looked
                # correct stay close to their original size while still honoring user
                # adjustments and slight DPI inflation.
                tempered = 1.0 + max(0.0, base_scale - 1.0) * 0.5
                scale = max(1.0, min(tempered, 1.12))
                if tk_scaling > 1.0:
                    scale = max(scale, min(1.0 + (tk_scaling - 1.0) * 0.4, 1.15))
                return min(scale, 1.18)
        except Exception:
            pass
        return min(scale, 1.3)

    def _get_omarchy_theme_mtime(self):
        mtimes = []
        for path in (
            journal_core.resolve_theme_name_path(),
            journal_core.resolve_colors_toml_path(),
        ):
            try:
                mtimes.append(os.path.getmtime(path))
            except OSError:
                mtimes.append(None)
        return tuple(mtimes)

    def _check_for_omarchy_theme_update(self):
        current_mtime = self._get_omarchy_theme_mtime()
        if current_mtime != self.last_omarchy_theme_mtime:
            colors = load_omarchy_theme()
            self.omarchy_colors = colors
            if colors:
                self.apply_omarchy_colors()
            self.update_theme_toggle_visibility()
            self.last_omarchy_theme_mtime = current_mtime
        self._schedule_omarchy_theme_check()

    def _schedule_omarchy_theme_check(self):
        try:
            self.root.after(5000, self._check_for_omarchy_theme_update)
        except Exception:
            pass

    def update_theme_toggle_visibility(self):
        if not hasattr(self, "theme_toggle_button"):
            return

        try:
            if getattr(self, "omarchy_colors", None):
                self.theme_toggle_button.grid_remove()
            else:
                if not self.theme_toggle_button.winfo_ismapped():
                    self.theme_toggle_button.grid()
        except tk.TclError:
            pass

    def _current_datetime(self):
        return datetime.now()

    def _current_date(self):
        return self._current_datetime().date()

    def refresh_days_since_label(self):
        if not hasattr(self, "days_since_label"):
            return
        try:
            self.days_since_label.config(text=self.days_since_last_entry())
        except tk.TclError:
            pass

    def _schedule_days_since_refresh(self):
        if self._days_since_refresh_after_id is not None:
            try:
                self.root.after_cancel(self._days_since_refresh_after_id)
            except Exception:
                pass
            self._days_since_refresh_after_id = None

        try:
            delay_ms = int(
                journal_core.seconds_until_next_midnight(self._current_datetime())
                * 1000
            )
            self._days_since_refresh_after_id = self.root.after(
                delay_ms, self._handle_day_rollover
            )
        except Exception:
            self._days_since_refresh_after_id = None

    def _handle_day_rollover(self):
        self._days_since_refresh_after_id = None
        self.refresh_days_since_label()
        self._schedule_days_since_refresh()

    def _bind_shortcuts(self):
        bindings = {
            "<Control-s>": self._shortcut_save,
            "<Control-l>": self._shortcut_load,
            "<Control-d>": self._shortcut_delete,
            "<Control-h>": self._shortcut_help,
            "<Command-s>": self._shortcut_save,
            "<Command-l>": self._shortcut_load,
            "<Command-d>": self._shortcut_delete,
            "<Command-h>": self._shortcut_help,
        }
        for sequence, handler in bindings.items():
            self.root.bind(sequence, handler)

    def _shortcut_save(self, event=None):
        self.save_journal_entry()
        return "break"

    def _shortcut_load(self, event=None):
        self.load_journal_entry()
        return "break"

    def _shortcut_delete(self, event=None):
        self.delete_journal_entry()
        return "break"

    def _shortcut_help(self, event=None):
        self.show_help_overlay()
        return "break"


    def setup_ui(self):
        # Allow normal window resizing + keep UI visible at small sizes
        self.root.resizable(True, True)
        self.root.minsize(600, 460)

        # Frame for the date selection
        self.date_frame = tk.Frame(self.root, padx=5, pady=5)
        self.date_frame.pack(padx=5, pady=5, fill=tk.X)

        # Center the date input within its own container so it stays aligned
        self.date_inner = tk.Frame(self.date_frame)
        self.date_inner.pack()

        # Entry widget for date input
        self.date_label = tk.Label(self.date_inner, text="Enter Date (YYYY-MM-DD):")
        self.date_label.pack(side=tk.LEFT, padx=(0, 8))
        self.date_entry = tk.Entry(self.date_inner, width=12)
        self.date_entry.pack(side=tk.LEFT)
        self._apply_text_selection_style()

        self.help_button = tk.Button(
            self.date_frame,
            text="?",
            command=self.show_help_overlay,
            bd=0,
            padx=8,
            pady=4,
            font=("Verdana", 10, "bold"),
            cursor="hand2",
        )
        self.help_button.place(relx=1.0, x=-8, y=4, anchor="ne")
        self._apply_help_button_style()

        # --- Responsive split container
        self.split = tk.PanedWindow(
            self.root, orient=tk.VERTICAL
        )  # tk PanedWindow = stable cross-platform
        self.split.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # Editor container holds the text widget + controls so we can reposition together
        self.editor_container = ttk.Frame(self.split, padding=5, style="Omarchy.TFrame")
        self.editor_container.rowconfigure(0, weight=1)
        # Reserve space for the controls that live under the editor even when
        # the window height becomes constrained (e.g. half-screen vertical
        # tiling). Without a minimum size the text widget would consume the
        # entire pane and hide the action buttons until the user adjusted the
        # sash manually.
        self.editor_container.rowconfigure(1, weight=0, minsize=120)
        self.editor_container.columnconfigure(0, weight=1)
        self.editor_container.columnconfigure(1, weight=0)
        self.split.add(self.editor_container)

        self.text_entry = tk.Text(
            self.editor_container, wrap=tk.WORD, width=65, height=20
        )
        self.text_entry.grid(row=0, column=0, sticky="nsew", padx=(0, 5))

        text_scrollbar = ttk.Scrollbar(
            self.editor_container, orient=tk.VERTICAL, command=self.text_entry.yview
        )
        text_scrollbar.grid(row=0, column=1, sticky="ns")
        self.text_entry.configure(yscrollcommand=text_scrollbar.set)

        self.text_entry.configure(font=self.text_font)
        self.text_entry.focus_set()
        self.text_entry.config(insertwidth=5, insertbackground="black")
        self._apply_text_selection_style()

        # spell check tagging
        self.text_entry.tag_config("misspelled", foreground="red", underline=True)
        self.text_entry.bind("<KeyRelease>", lambda event: self.check_spelling())
        self.text_entry.bind("<Button-3>", self.show_suggestions)  # Linux/Windows
        self.text_entry.bind("<Button-2>", self.show_suggestions)  # macOS fallback

        # Container for status + action buttons (lives under the editor in all layouts)
        self.controls_frame = ttk.Frame(self.editor_container, style="Omarchy.TFrame")
        self.controls_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.controls_frame.columnconfigure(0, weight=1)

        self.days_since_label = ttk.Label(
            self.controls_frame, text=self.days_since_last_entry(), style="Omarchy.TLabel"
        )
        self.days_since_label.pack(pady=(0, 5))

        self.button_frame = ttk.Frame(self.controls_frame, style="Omarchy.TFrame")
        self.button_frame.pack(padx=10, pady=5)

        action_button_padding = (6, 4)

        ttk.Button(
            self.button_frame,
            text="Save",
            command=self.save_journal_entry,
            style="Omarchy.TButton",
            padding=action_button_padding,
        ).grid(row=1, column=0, padx=5)

        ttk.Button(
            self.button_frame,
            text="Load",
            command=self.load_journal_entry,
            style="Omarchy.TButton",
            padding=action_button_padding,
        ).grid(row=1, column=1, padx=5)

        ttk.Button(
            self.button_frame,
            text="Delete",
            command=self.delete_journal_entry,
            style="Omarchy.TButton",
            padding=action_button_padding,
        ).grid(row=1, column=2, padx=5)

        ttk.Button(
            self.button_frame,
            text="Clear",
            command=self.clear_entry_text,
            style="Omarchy.TButton",
            padding=action_button_padding,
        ).grid(row=1, column=3, padx=5)

        ttk.Button(
            self.button_frame,
            text="Settings",
            command=self.show_settings_dialog,
            style="Omarchy.TButton",
            padding=action_button_padding,
        ).grid(row=1, column=4, padx=5)

        self.theme_toggle_button = ttk.Button(
            self.button_frame, text="light/dark", command=self.toggle_theme, style="Omarchy.TButton"
        )
        self.theme_toggle_button.grid(row=1, column=5, padx=5)

        # Separate container for the treeview so we can move it below or beside the editor
        self.tree_container = ttk.Frame(self.split, style="Omarchy.TFrame")
        self.tree_container.rowconfigure(0, weight=1)
        self.tree_container.columnconfigure(0, weight=1)
        self.split.add(self.tree_container)

        self.tree_frame = ttk.Frame(self.tree_container, style="Omarchy.TFrame")
        self.tree_frame.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)

        # A plain, static accent-colored line in place of the tree's ttk
        # Heading row - the tree has no columns and no clickable/sortable
        # heading (see update_treeview: heading("#0", text="") is the only
        # thing ever done with it), so a real Heading was just an empty
        # strip that (before this fix) also depended on Azure/Tk-9-specific
        # style plumbing for no functional benefit. Its color is kept in
        # sync by apply_omarchy_colors, same as text_entry/date_entry.
        self.tree_header_accent = tk.Frame(self.tree_frame, height=2, bd=0, highlightthickness=0)
        self.tree_header_accent.pack(side=tk.TOP, fill=tk.X)

        scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.treeview = ttk.Treeview(
            self.tree_frame, yscrollcommand=scrollbar.set, show="tree"
        )
        self.treeview.pack(padx=5, pady=5, fill=tk.BOTH, expand=True)
        self.treeview.bind("<<TreeviewSelect>>", self.on_treeview_select)
        scrollbar.config(command=self.treeview.yview)

        self.root.bind("<Configure>", self.on_root_resize)
        self.root.after(200, self._initialize_layout)

        # Initial update of treeview
        self.update_treeview()

    def _initialize_layout(self):
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        if width <= 1 or height <= 1:
            self.root.after(100, self._initialize_layout)
            return
        self.update_layout(width, height)
        self.apply_responsive_typography()

    def on_root_resize(self, event):
        if event.widget is not self.root:
            return
        if event.width <= 0 or event.height <= 0:
            return
        self._pending_geometry = (event.width, event.height)
        if self._resize_after_id is not None:
            self.root.after_cancel(self._resize_after_id)
        self._resize_after_id = self.root.after(120, self._apply_pending_layout)

    def _apply_pending_layout(self):
        self._resize_after_id = None
        if not self._pending_geometry:
            return
        width, height = self._pending_geometry
        self.update_layout(width, height)
        self.apply_responsive_typography()

    def update_layout(self, width, height):
        if width <= 1 or height <= 1:
            return
        desired_layout = "horizontal" if width >= height else "vertical"
        if desired_layout == self.current_layout:
            return

        self.current_layout = desired_layout
        orient = tk.HORIZONTAL if desired_layout == "horizontal" else tk.VERTICAL
        self.split.configure(orient=orient)

        # ensure panes are re-added in the proper order
        try:
            self.split.forget(self.editor_container)
        except tk.TclError:
            pass
        try:
            self.split.forget(self.tree_container)
        except tk.TclError:
            pass

        self.split.add(self.editor_container)
        self.split.add(self.tree_container)

        self.root.after(50, self._position_sash)

    def _position_sash(self):
        if not self.current_layout:
            return
        try:
            self.root.update_idletasks()
            if self.current_layout == "vertical":
                total = self.split.winfo_height() or self.root.winfo_height()
                pos = max(220, int(total * 0.58))
                self.split.sash_place(0, 0, pos)
            else:
                total = self.split.winfo_width() or self.root.winfo_width()
                pos = max(360, int(total * 0.62))
                self.split.sash_place(0, pos, 0)
        except Exception:
            pass

    def set_app_icon(self):
        try:
            if sys.platform.startswith("win"):
                ico_path = self.resource_path("./theme/journal.ico")
                if os.path.exists(ico_path):
                    self.root.iconbitmap(ico_path)
                    return
                # Fallback to PNG if no ICO present
                png_path = self.resource_path("./theme/journal.png")
                if os.path.exists(png_path):
                    self.root.iconphoto(True, tk.PhotoImage(file=png_path))
            else:
                png_path = self.resource_path("./theme/journal.png")
                if os.path.exists(png_path):
                    # You can pass multiple sizes for best results
                    self.root.iconphoto(True, tk.PhotoImage(file=png_path))
        except Exception as e:
            # Don't crash if the icon can't be loaded; just log it.
            if hasattr(self, "logger"):
                self.logger.warning("Icon not applied: %s", e)

    def days_since_last_entry(self):
        return journal_core.days_since_last_entry(
            self.load_json(), today=self._current_date()
        )

    def resource_path(self, relative_path):
        return journal_core.resource_path(relative_path)

    def apply_theme(self):
        try:
            self.root.tk.call("set_theme", self.current_theme)
            self._fix_tk9_treeview_disclosure_indicator()
            self._apply_text_selection_style()
            self._apply_help_button_style()
            self._style_help_overlay()
        except tk.TclError as e:
            self.logger.exception("Error applying theme: %s", e)
            messagebox.showerror(
                "Error",
                "Unable to apply theme. Ensure that the theme is loaded correctly.",
            )

    def load_theme_file(self):
        try:
            azure_tcl_path = self.resource_path("azure.tcl")
            self.root.tk.call("source", azure_tcl_path)
        except tk.TclError as e:
            self.logger.exception("Error loading theme file: %s", e)
            messagebox.showerror(
                "Error",
                "Unable to load theme file. Make sure the azure.tcl file is in the correct directory.",
            )
            raise

    def toggle_theme(self):
        current_geometry = self.root.geometry()
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
        self.root.geometry(current_geometry)
        self.root.update_idletasks()
        self.apply_responsive_typography()

    def check_spelling(self):
        if not self.spellcheck_enabled or self.dictionary is None:
            try:
                self.text_entry.tag_remove("misspelled", "1.0", tk.END)
            except tk.TclError:
                pass
            return
        try:
            text_content = self.text_entry.get("1.0", tk.END)
            self.text_entry.tag_remove("misspelled", "1.0", tk.END)
            words_positions = self.get_words_positions(text_content)
            for word, start_idx, end_idx in words_positions:
                stripped_word = word.strip(string.punctuation)
                if stripped_word and not self.dictionary.check(stripped_word):
                    self.text_entry.tag_add("misspelled", start_idx, end_idx)
        except Exception as e:
            self.spellcheck_enabled = False
            self.logger.exception("Spellcheck disabled due to runtime error: %s", e)

    def get_words_positions(self, text):
        words_positions = []
        pattern = re.compile(r"\b[\w']+\b")
        for match in pattern.finditer(text):
            word = match.group()
            start_index = f"1.0 + {match.start()} chars"
            end_index = f"1.0 + {match.end()} chars"
            words_positions.append((word, start_index, end_index))
        return words_positions

    def show_suggestions(self, event):
        if not self.spellcheck_enabled or self.dictionary is None:
            return
        try:
            index = self.text_entry.index(f"@{event.x},{event.y}")
            tags = self.text_entry.tag_names(index)
            if "misspelled" in tags:
                ranges = self.text_entry.tag_prevrange("misspelled", index)
                if ranges:
                    word_start, word_end = ranges
                    misspelled_word = self.text_entry.get(word_start, word_end)
                    stripped_word = misspelled_word.strip(string.punctuation)
                    suggestions = self.dictionary.suggest(stripped_word)
                    menu = tk.Menu(self.root, tearoff=0)
                    if suggestions:
                        for suggestion in suggestions[:5]:
                            menu.add_command(
                                label=suggestion,
                                command=lambda s=suggestion: self.replace_word(
                                    word_start, word_end, s
                                ),
                            )
                    else:
                        menu.add_command(label="No suggestions available")
                    menu.post(event.x_root, event.y_root)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def replace_word(self, start, end, replacement):
        self.text_entry.delete(start, end)
        self.text_entry.insert(start, replacement)
        self.check_spelling()

    def on_treeview_select(self, event):
        self.last_action_time = datetime.now()

    def focus_treeview_for_selection(self, message=None):
        try:
            first_month = self.treeview.get_children("")
            if first_month:
                first_child = self.treeview.get_children(first_month[0])
                target = first_child[0] if first_child else first_month[0]
                self.treeview.focus(target)
                self.treeview.selection_set(target)
                self.treeview.see(target)
            self.treeview.focus_set()
        except tk.TclError:
            pass

        if message:
            messagebox.showinfo("Select Entry", message)

    def prompt_for_password(self):
        if self.failed_attempts >= self.max_attempts:
            messagebox.showerror(
                "Error", "Too many failed attempts. Application will exit."
            )
            self.close_app()
            return None

        dialog = tk.Toplevel(self.root)
        dialog.title("Password Required")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        # Match the journal tile aesthetics when possible
        try:
            dialog.configure(bg=self.text_entry.cget("bg"))
        except tk.TclError:
            pass

        prompt = ttk.Label(
            dialog, text="Enter your journal password:", style="Omarchy.TLabel"
        )
        prompt.pack(padx=20, pady=(20, 10))

        password_var = tk.StringVar()
        stored_password = self._keyring_get_password()
        if stored_password:
            password_var.set(stored_password)
        entry = ttk.Entry(dialog, textvariable=password_var, show="*")
        entry.pack(padx=20, pady=(0, 15))
        entry.focus_set()

        self.password_remember_var = tk.IntVar(value=1 if stored_password else 0)
        if self.keyring_available:
            remember_checkbox = tk.Checkbutton(
                dialog,
                text="Remember password on this machine",
                variable=self.password_remember_var,
                anchor="w",
                padx=16,
                pady=2,
            )
            remember_checkbox.pack(fill=tk.X, padx=4, pady=(0, 8))

        button_row = ttk.Frame(dialog, style="Omarchy.TFrame")
        button_row.pack(padx=20, pady=(0, 20))

        result = {"value": None}

        def submit(event=None):
            password_value = password_var.get()
            if self.keyring_available:
                if self.password_remember_var.get():
                    self._keyring_set_password(password_value)
                else:
                    self._keyring_clear_password()
            result["value"] = password_value
            dialog.destroy()

        def cancel(event=None):
            result["value"] = None
            dialog.destroy()

        ttk.Button(
            button_row, text="OK", command=submit, style="Omarchy.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            button_row, text="Cancel", command=cancel, style="Omarchy.TButton"
        ).pack(side=tk.LEFT)

        dialog.bind("<Return>", submit)
        dialog.bind("<Escape>", cancel)
        dialog.protocol("WM_DELETE_WINDOW", cancel)

        self._show_modal_dialog(dialog, focus_widget=entry)

        dialog.wait_window()

        password = result["value"]
        password_var.set("")
        return password

    def prompt_for_new_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Set New Password")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        try:
            dialog.configure(bg=self.text_entry.cget("bg"))
        except tk.TclError:
            pass

        prompt = ttk.Label(
            dialog, text="Enter and confirm the new password:", style="Omarchy.TLabel"
        )
        prompt.pack(padx=20, pady=(20, 10))

        new_password_var = tk.StringVar()
        confirm_password_var = tk.StringVar()

        new_entry = ttk.Entry(dialog, textvariable=new_password_var, show="*")
        new_entry.pack(padx=20, pady=(0, 10))
        new_entry.focus_set()

        confirm_entry = ttk.Entry(dialog, textvariable=confirm_password_var, show="*")
        confirm_entry.pack(padx=20, pady=(0, 15))

        button_row = ttk.Frame(dialog, style="Omarchy.TFrame")
        button_row.pack(padx=20, pady=(0, 20))

        result = {"value": None}

        def submit(event=None):
            new_password = new_password_var.get()
            confirm_password = confirm_password_var.get()
            if not new_password:
                messagebox.showerror(
                    "Error", "New password cannot be empty.", parent=dialog
                )
                return
            if new_password != confirm_password:
                messagebox.showerror(
                    "Error", "Passwords do not match.", parent=dialog
                )
                return
            result_value = new_password
            new_password_var.set("")
            confirm_password_var.set("")
            result["value"] = result_value
            dialog.destroy()

        def cancel(event=None):
            new_password_var.set("")
            confirm_password_var.set("")
            result["value"] = None
            dialog.destroy()

        ttk.Button(
            button_row, text="OK", command=submit, style="Omarchy.TButton"
        ).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(
            button_row, text="Cancel", command=cancel, style="Omarchy.TButton"
        ).pack(side=tk.LEFT)

        dialog.bind("<Return>", submit)
        dialog.bind("<Escape>", cancel)
        dialog.protocol("WM_DELETE_WINDOW", cancel)

        self._show_modal_dialog(dialog, focus_widget=new_entry)

        dialog.wait_window()
        return result["value"]

    def _show_modal_dialog(self, dialog, focus_widget=None):
        def center_dialog():
            if not dialog.winfo_exists():
                return
            self.root.update_idletasks()
            dialog.update_idletasks()

            target = self.editor_container
            try:
                if not target.winfo_ismapped():
                    target = self.root
            except tk.TclError:
                target = self.root

            parent_x = target.winfo_rootx()
            parent_y = target.winfo_rooty()
            parent_width = target.winfo_width()
            parent_height = target.winfo_height()
            dialog_width = dialog.winfo_width()
            dialog_height = dialog.winfo_height()

            pos_x = parent_x + (parent_width - dialog_width) // 2
            pos_y = parent_y + (parent_height - dialog_height) // 2
            max_x = max(0, dialog.winfo_screenwidth() - dialog_width)
            max_y = max(0, dialog.winfo_screenheight() - dialog_height)
            pos_x = max(0, min(pos_x, max_x))
            pos_y = max(0, min(pos_y, max_y))
            dialog.geometry(f"+{pos_x}+{pos_y}")

        # Pre-position before mapping, then re-center after map because some
        # Wayland/tiling WMs report stale coordinates on first render.
        dialog.withdraw()
        center_dialog()
        dialog.deiconify()
        try:
            dialog.wait_visibility()
        except tk.TclError:
            pass
        center_dialog()
        for delay in (40, 100, 180, 300):
            dialog.after(delay, center_dialog)

        try:
            dialog.lift()
            dialog.attributes("-topmost", True)
            dialog.after(50, lambda: dialog.attributes("-topmost", False))
        except tk.TclError:
            pass

        if focus_widget is not None:
            try:
                focus_widget.focus_force()
            except tk.TclError:
                pass

    def derive_key(self, password, salt):
        return journal_core.derive_key(password, salt)

    def encrypt_message(self, message, password):
        try:
            return journal_core.encrypt_message(message, password)
        except Exception:
            messagebox.showerror("Error", "Incorrect password.")
            return None

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

    def change_journal_password(self):
        self.last_action_time = datetime.now()
        backup_path = None
        if os.path.exists(self.filename):
            try:
                backup_path = journal_core.create_journal_backup(self.filename)
            except Exception as backup_error:
                messagebox.showwarning(
                    "Backup Failed",
                    "The journal could not be backed up before attempting the password change. "
                    "The process will continue without a backup.\n\n"
                    f"Details: {backup_error}",
                )

        data = self.load_json()

        if not data:
            messagebox.showinfo(
                "No Entries",
                "There are no journal entries to re-encrypt. Add an entry first before changing the password.",
            )
            return

        current_password = self.prompt_for_password()
        if current_password is None:
            return

        new_password = self.prompt_for_new_password()
        if not new_password:
            return
        remember_password_in_keyring = (
            self.keyring_available and self._keyring_get_password() is not None
        )
        keyring_new_password = new_password

        encrypted_entries = [entry.get("entry") for entry in data if entry.get("entry")]
        if encrypted_entries:
            try:
                with secure_password(current_password) as old_pwd:
                    self.decrypt_message(encrypted_entries[0], old_pwd, count_attempt=True)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                return

        with secure_password(current_password) as old_pwd:
            with secure_password(new_password) as new_pwd:
                updated_data, failed_entries, success_ratio = (
                    journal_core.rotate_journal_password(data, old_pwd, new_pwd)
                )
        total_encrypted_entries = len(encrypted_entries)

        current_password = None
        new_password = None

        log_path = None
        if failed_entries:
            try:
                log_path = journal_core.log_password_rotation_failures(
                    self.filename, failed_entries
                )
            except Exception as log_error:
                messagebox.showwarning(
                    "Logging Failed",
                    "Unable to record failed entry details for the password change.\n\n"
                    f"Details: {log_error}",
                )

        if (
            total_encrypted_entries
            and success_ratio < journal_core.PASSWORD_ROTATION_SUCCESS_THRESHOLD
        ):
            details = ""
            if failed_entries:
                failed_dates = ", ".join(
                    sorted({failure["date"] for failure in failed_entries})
                )
                details = (
                    "\n\nEntries that could not be re-encrypted: "
                    f"{failed_dates}."
                )
            log_note = (
                f"\n\nDetailed information has been saved to: {log_path}"
                if log_path
                else ""
            )
            backup_note = (
                f"\n\nA backup of your journal is stored at: {backup_path}"
                if backup_path
                else ""
            )
            messagebox.showerror(
                "Password Change Incomplete",
                "Fewer than 90% of your journal entries could be updated with the new password. "
                "Your journal has not been modified." + details + log_note + backup_note,
            )
            return

        try:
            self.save_json(updated_data)
        except Exception as e:
            messagebox.showerror(
                "Error", f"Failed to save the re-encrypted journal entries: {e}"
            )
            return

        if remember_password_in_keyring:
            self._keyring_set_password(keyring_new_password)

        if failed_entries:
            failed_details = "\n".join(
                f"• {failure['date']}: {failure['reason']}" for failure in failed_entries
            )
            log_message = (
                f"\nA record of the affected entries has been written to: {log_path}"
                if log_path
                else ""
            )
            backup_note = (
                f"\nYour pre-change journal is backed up at: {backup_path}"
                if backup_path
                else ""
            )
            messagebox.showwarning(
                "Password Change Completed with Warnings",
                "Most entries were updated with the new password, "
                "but some entries could not be re-encrypted.\n\n"
                f"{failed_details}{log_message}{backup_note}",
            )
        else:
            messagebox.showinfo(
                "Success", "All journal entries have been re-encrypted with the new password."
            )

    def create_manual_backup(self):
        self.last_action_time = datetime.now()
        if not os.path.exists(self.filename):
            messagebox.showinfo(
                "No Journal Found",
                "There is no journal file to back up yet.",
            )
            return

        try:
            backup_path = journal_core.create_journal_backup(self.filename)
        except Exception as error:
            messagebox.showerror(
                "Backup Failed",
                f"Unable to create a backup: {error}",
            )
            return

        messagebox.showinfo(
            "Backup Created",
            f"A backup was created at:\n{backup_path}",
        )

    def restore_journal_backup(self):
        self.last_action_time = datetime.now()

        backups = journal_core.list_journal_backups(self.filename)
        if not backups:
            messagebox.showinfo(
                "No Backups Found",
                "No journal backups were found yet. A backup is created automatically before password rotation.",
            )
            return

        backup_dir = os.path.dirname(self.filename) or "."
        selected_backup = filedialog.askopenfilename(
            parent=self.root,
            title="Select Journal Backup",
            initialdir=backup_dir,
            initialfile=os.path.basename(backups[0]),
            filetypes=[
                ("Journal backups", "*.bak-*"),
                ("Compressed journal files", "*.gz"),
                ("All files", "*"),
            ],
        )
        if not selected_backup:
            return

        try:
            data = journal_core.validate_backup_file(selected_backup)
        except ValueError:
            messagebox.showerror(
                "Restore Failed",
                "The selected backup is not a valid journal file.",
            )
            return

        safety_backup = None
        if os.path.exists(self.filename):
            try:
                safety_backup = journal_core.create_journal_backup(self.filename)
            except Exception as error:
                proceed = messagebox.askyesno(
                    "Backup Failed",
                    "The current journal could not be backed up before restore.\n\n"
                    f"Details: {error}\n\n"
                    "Continue restoring anyway?",
                )
                if not proceed:
                    return

        try:
            self.save_json(data)
        except Exception as error:
            messagebox.showerror(
                "Restore Failed",
                f"Unable to restore the selected backup: {error}",
            )
            return

        self.clear_journal_entry()
        self.update_treeview()
        self.refresh_days_since_label()

        safety_note = (
            f"\n\nYour previous journal was backed up to:\n{safety_backup}"
            if safety_backup
            else ""
        )
        messagebox.showinfo(
            "Restore Complete",
            f"Journal restored from:\n{selected_backup}{safety_note}",
        )

    def _ensure_parent_dir(self):
        journal_core.ensure_parent_dir(self.filename)

    def _is_valid_date_string(self, value):
        return journal_core.is_valid_date_string(value)

    def _sanitize_journal_data(self, data):
        return journal_core.sanitize_journal_data(data, filename=self.filename, logger=self.logger)

    def save_json(self, data):
        journal_core.save_json(
            self.filename, data, logger=self.logger,
            warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
        )

    def _load_json_from_path(self, path, show_warnings=True):
        return journal_core.load_json_from_path(
            path, show_warnings=show_warnings, logger=self.logger,
            warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
        )

    def load_json(self):
        return journal_core.load_json(
            self.filename, logger=self.logger,
            warn_callback=lambda msg: messagebox.showwarning("Warning", msg),
        )

    def save_journal_entry(self):
        self.last_action_time = datetime.now()

        password = self.prompt_for_password()
        if password is None:
            return

        with secure_password(password) as pwd:
            password = None
            try:
                journal_entry = self.text_entry.get("1.0", tk.END).strip()
                date_str = self.date_entry.get().strip()

                if not journal_entry:
                    messagebox.showwarning("Warning", "Journal entry cannot be empty.")
                    return

                if not date_str:
                    date_str = datetime.now().strftime("%Y-%m-%d")
                else:
                    try:
                        datetime.strptime(date_str, "%Y-%m-%d")
                    except ValueError:
                        messagebox.showerror(
                            "Error", "Invalid date format. Use YYYY-MM-DD"
                        )
                        return

                data = self.load_json()

                # Overwrite guard: if an entry already exists for date_str
                # and the user didn't get there by explicitly loading that
                # same entry first (entry_loaded/loaded_entry_date), don't
                # silently clobber it - load it into the editor instead and
                # let them Clear it if they really want to start blank.
                existing_entry = journal_core.find_entry_by_date(data, date_str)
                already_editing_this_entry = (
                    self.entry_loaded and self.loaded_entry_date == date_str
                )
                if existing_entry is not None and not already_editing_this_entry:
                    try:
                        decrypted_entry = self.decrypt_message(
                            existing_entry["entry"], pwd
                        )
                    except ValueError as error:
                        messagebox.showerror("Error", str(error))
                        return
                    self._populate_editor_from_entry(date_str, decrypted_entry)
                    messagebox.showwarning(
                        "Entry Already Exists",
                        f"An entry already exists for {date_str}. It has "
                        "been loaded into the editor instead of being "
                        "overwritten - use Clear if you want to start "
                        "blank, then Save again.",
                    )
                    return

                encrypted_entry = self.encrypt_message(journal_entry, pwd)
                if encrypted_entry is None:
                    return

                entry = {"date": date_str, "entry": encrypted_entry}

                # Update or append entry
                for existing in data:
                    if existing.get("date") == date_str:
                        existing["entry"] = encrypted_entry
                        break
                else:
                    data.append(entry)

                self.save_json(data)
                messagebox.showinfo(
                    "Success", "Your journal entry has been encrypted and saved."
                )

                self.clear_journal_entry()
                self.update_treeview()
                self.refresh_days_since_label()

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save entry: {str(e)}")

    def _populate_editor_from_entry(self, date_str, decrypted_text):
        self.text_entry.delete("1.0", tk.END)
        self.text_entry.insert(tk.END, decrypted_text)
        self.date_entry.delete(0, tk.END)
        self.date_entry.insert(0, date_str)
        self.entry_loaded = True
        self.loaded_entry_date = date_str

    def load_journal_entry(self):
        self.last_action_time = datetime.now()

        try:
            selected_item = self.treeview.selection()[0]
        except IndexError:
            self.focus_treeview_for_selection(
                "Select a journal entry from the list, then press Load again."
            )
            return

        try:
            selected_date = self.treeview.item(selected_item, "text")
            if not self.treeview.parent(selected_item):
                self.focus_treeview_for_selection(
                    "Select a dated journal entry, not a month heading."
                )
                return

            password = self.prompt_for_password()
            if password is None:
                return

            data = self.load_json()
            for entry in data:
                if entry.get("date") == selected_date:
                    with secure_password(password) as pwd:
                        password = None
                        decrypted_entry = self.decrypt_message(
                            entry["entry"], pwd
                        )
                    self._populate_editor_from_entry(selected_date, decrypted_entry)
                    break
            else:
                messagebox.showwarning(
                    "Warning", "No entry found for the selected date."
                )
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load entry: {e}")
        finally:
            password = None

    def delete_journal_entry(self):
        self.last_action_time = datetime.now()

        try:
            selected_item = self.treeview.selection()[0]
            selected_date = self.treeview.item(selected_item, "text")
            if self.treeview.parent(selected_item):
                password = self.prompt_for_password()
                if password is None:
                    return

                confirm = messagebox.askyesno(
                    "Confirm Delete",
                    f"Are you sure you want to delete the entry for {selected_date}?",
                )
                if not confirm:
                    return

                data = self.load_json()
                selected_entry = next(
                    (entry for entry in data if entry.get("date") == selected_date),
                    None,
                )
                if not selected_entry:
                    messagebox.showwarning(
                        "Warning", "No entry found for the selected date."
                    )
                    return

                encrypted_entry = selected_entry.get("entry")
                if encrypted_entry:
                    try:
                        with secure_password(password) as pwd:
                            self.decrypt_message(encrypted_entry, pwd)
                    except ValueError as e:
                        messagebox.showerror("Error", str(e))
                        return

                new_data = [
                    entry for entry in data if entry.get("date") != selected_date
                ]
                self.save_json(new_data)

                messagebox.showinfo("Success", "Journal entry deleted successfully.")
                self.clear_journal_entry()
                self.update_treeview()
                self.refresh_days_since_label()
            else:
                messagebox.showinfo(
                    "Information", "Please select a date to delete, not a month."
                )
        except IndexError:
            messagebox.showwarning("Warning", "Please select a date from the list.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {e}")
        finally:
            password = None

    def clear_journal_entry(self):
        self.text_entry.delete("1.0", tk.END)
        self.date_entry.delete(0, tk.END)
        self.entry_loaded = False
        self.loaded_entry_date = None

    def clear_entry_text(self):
        """Clear button handler: blanks just the entry body, leaving the
        date field and entry_loaded/loaded_entry_date untouched - unlike
        clear_journal_entry() (used internally after a successful save, a
        full reset for the next unrelated action). If the overwrite guard
        in save_journal_entry just loaded an existing entry here, the user
        clicking Clear to blank it and typing fresh content should still
        be able to Save that same date immediately afterward without the
        guard re-triggering and reloading the old content over their new
        text - which is what a full reset here would otherwise cause.
        """
        self.text_entry.delete("1.0", tk.END)

    def close_app(self):
        if self._days_since_refresh_after_id is not None:
            try:
                self.root.after_cancel(self._days_since_refresh_after_id)
            except Exception:
                pass
            self._days_since_refresh_after_id = None
        self.root.destroy()

    def update_treeview(self):
        data = self.load_json()
        self.treeview.delete(*self.treeview.get_children())
        grouped_data = {}
        for entry in data:
            date_str = entry.get("date")
            if not date_str:
                continue
            year_month = date_str[:7]  # Extract YYYY-MM
            if year_month not in grouped_data:
                grouped_data[year_month] = []
            grouped_data[year_month].append(date_str)

        sorted_year_months = sorted(
            grouped_data.keys(),
            key=lambda ym: datetime.strptime(ym, "%Y-%m"),
            reverse=True,
        )

        for year_month in sorted_year_months:
            dates = sorted(
                grouped_data[year_month],
                key=lambda date: datetime.strptime(date, "%Y-%m-%d"),
                reverse=True,
            )
            parent = self.treeview.insert("", "end", text=year_month, open=False)
            for date in dates:
                self.treeview.insert(parent, "end", text=date)

def _clamp(value, minimum, maximum):
    return max(minimum, min(maximum, value))


def _screen_resolution_scale(screen_width, screen_height):
    try:
        resolution_ratio = (screen_width * screen_height) / float(1920 * 1080)
        return resolution_ratio**0.08
    except Exception:
        return 1.0


def _looks_like_hidpi_laptop(screen_width, screen_height):
    # Retina-era 13" MacBook Pro often runs around 2560x1600 points/pixels
    # in Linux/macOS setups where Tk reports conservative DPI values.
    return (
        screen_width >= 2200
        and screen_height >= 1300
        and screen_width <= 3200
        and screen_height <= 2000
    )


def _resolve_startup_scaling(root):
    # Optional override for troubleshooting and per-device tuning.
    override = os.environ.get("ENCRYPTED_JOURNAL_UI_SCALE")
    if override:
        try:
            return _clamp(float(override), 0.9, 2.2)
        except ValueError:
            pass

    dpi_scale = 1.0
    try:
        dpi = float(root.winfo_fpixels("1i"))
        if dpi > 0:
            dpi_scale = dpi / 96.0
    except Exception:
        dpi_scale = 1.0

    try:
        screen_width = max(1, int(root.winfo_screenwidth()))
        screen_height = max(1, int(root.winfo_screenheight()))
    except Exception:
        screen_width, screen_height = 1920, 1080

    resolution_scale = _screen_resolution_scale(screen_width, screen_height)
    startup_scale = dpi_scale * resolution_scale

    if _looks_like_hidpi_laptop(screen_width, screen_height):
        startup_scale = max(startup_scale, 1.28)

    return _clamp(startup_scale, 0.95, 1.52)


def _set_startup_geometry(root):
    try:
        screen_width = max(1, int(root.winfo_screenwidth()))
        screen_height = max(1, int(root.winfo_screenheight()))
        width = _clamp(int(screen_width * 0.72), 900, 1360)
        height = _clamp(int(screen_height * 0.78), 620, 940)
        pos_x = max(0, (screen_width - width) // 2)
        pos_y = max(20, (screen_height - height) // 3)
        root.geometry(f"{width}x{height}+{pos_x}+{pos_y}")
    except Exception:
        root.geometry("1100x760+120+80")


if __name__ == "__main__":
    root = tk.Tk(className="JournalApp")
    root.title("Secure Encrypted Journal")
    _set_startup_geometry(root)
    root.tk.call("tk", "scaling", _resolve_startup_scaling(root))
    app = SecureJournalApp(root)
    root.mainloop()
