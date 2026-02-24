import tkinter as tk
from tkinter import ttk, messagebox, font
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tomllib
import base64
import os
import shutil
import sys
import gzip
import json
from datetime import datetime
try:
    import enchant
except ImportError:
    enchant = None
import re
import string
import secrets
import gc
import tempfile
from contextlib import contextmanager

# Windows-specific imports for file permissions
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


OMARCHY_THEME_PATH = os.path.expanduser("~/.config/omarchy/current/theme/alacritty.toml")


def load_omarchy_theme():
    """
    Loads current omarchy theme colors, falls back silently if theme not found
    """
    theme_toml = OMARCHY_THEME_PATH

    if not os.path.exists(theme_toml):
        return None

    try:
        with open(theme_toml, "rb") as f:
            data = tomllib.load(f)

        primary = data.get("colors", {}).get("primary", {})
        normal = data.get("colors", {}).get("normal", {})
        cursor = data.get("colors", {}).get("cursor", {})

        bg = primary.get("background", "#1e1e2e")
        fg = primary.get("foreground", "#cdd6f4")

        # A = subtle jade accent = colors.normal.blue
        accent = normal.get("blue", "#509475")

        # Optional: get cursor color
        cur = cursor.get("cursor", fg)

        return {
            "bg": bg,
            "fg": fg,
            "accent": accent,
            "cursor": cur,
        }
    except Exception:
        return None

class SecureJournalApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Encrypted Journal")
        self.set_app_icon()
        self.last_action_time = datetime.now()
        # Use a unified, script-relative path for the journal file
        self.filename = self.resource_path("journal.json.gz")
        self.is_modified = False
        self.entry_loaded = False
        self.failed_attempts = 0
        self.max_attempts = 5
        self.dictionary = None
        self.spellcheck_enabled = False
        self._init_spellchecker()
        self.current_theme = "dark"
        self.current_layout = None
        self._resize_after_id = None
        self._pending_geometry = None
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
        self.load_theme_file()  # strict: raise if missing
        self.apply_theme()
        self.omarchy_theme_path = OMARCHY_THEME_PATH
        self.omarchy_colors = load_omarchy_theme()
        if self.omarchy_colors:
            self.apply_omarchy_colors()
        self.apply_responsive_typography()
        self.update_theme_toggle_visibility()
        self.last_omarchy_theme_mtime = self._get_omarchy_theme_mtime()
        self._schedule_omarchy_theme_check()

    def _init_spellchecker(self):
        if enchant is None:
            print("Spellcheck disabled: pyenchant is not installed.")
            return
        try:
            self.dictionary = enchant.Dict("en_US")
            self.spellcheck_enabled = True
        except Exception as error:
            self.dictionary = None
            self.spellcheck_enabled = False
            print(f"Spellcheck disabled: {error}")

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

            # --- ttk widget styling (buttons + treeview) ---
            style = ttk.Style()

            def blend(color, target, factor):
                """Blend a hex color toward a target color by a factor (0-1)."""
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

            accent_hover = blend(colors["accent"], "ffffff", 0.18)
            accent_pressed = blend(colors["accent"], "000000", 0.22)
            accent_disabled = blend(colors["accent"], colors["bg"], 0.55)
            text_disabled = blend(colors["fg"], colors["bg"], 0.65)

            style.configure(
                "Omarchy.TButton",
                background=colors["accent"],
                foreground=colors["fg"],
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
                foreground=[
                    ("!disabled", colors["fg"]),
                    ("disabled", text_disabled)
                ]
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

            # Treeview heading (column headers)
            style.configure(
                "Omarchy.Treeview.Heading",
                background=colors["bg"],
                foreground=colors["fg"],
                relief="flat"
            )
            style.map(
                "Omarchy.Treeview.Heading",
                background=[("active", accent_hover)],
                foreground=[("active", colors["bg"])]
            )

            style.configure(
                "Treeview.Heading",
                background=colors["bg"],
                foreground=colors["fg"],
                relief="flat"
            )
            style.map(
                "Treeview.Heading",
                background=[("active", accent_hover)],
                foreground=[("active", colors["bg"])]
            )

            # Scrollbar styling
            style.configure(
                "Vertical.TScrollbar",
                background=colors["bg"],
                troughcolor=colors["bg"],
                arrowcolor=colors["fg"],
                bordercolor=colors["bg"],
                relief="flat"
            )
            style.map(
                "Vertical.TScrollbar",
                background=[("active", colors["accent"])]
            )

            style.configure(
                "Horizontal.TScrollbar",
                background=colors["bg"],
                troughcolor=colors["bg"],
                arrowcolor=colors["fg"],
                bordercolor=colors["bg"],
                relief="flat"
            )
            style.map(
                "Horizontal.TScrollbar",
                background=[("active", colors["accent"])]
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
                self.treeview.heading("#0", text="")
            except tk.TclError:
                pass

            # Remove harsh frame borders (make them inherit bg)
            for frame in (self.button_frame, self.tree_frame, self.date_frame):
                try:
                    frame.config(bg=colors["bg"], highlightbackground=colors["bg"])
                except Exception:
                    pass

        except Exception as e:
            print("Failed to apply Omarchy theme:", e)
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

        base_scale = max(1.0, dpi_scale, geometry_scale)
        scale = self._platform_scale_adjust(base_scale, dpi_scale, tk_scaling)
        return max(1.0, scale)

    def _get_tk_scaling(self):
        try:
            scaling = float(self.root.tk.call("tk", "scaling"))
            if scaling <= 0:
                return 1.0
            return scaling
        except Exception:
            return 1.0

    def _platform_scale_adjust(self, base_scale, dpi_scale, tk_scaling):
        scale = max(1.0, base_scale)
        try:
            if sys.platform == "darwin":
                # Older mac hardware often reports ~72 DPI with tk scaling near 1.0.
                # Push those panels to a noticeably larger baseline so text climbs
                # roughly two points while still respecting explicit tk scaling.
                if dpi_scale < 1.3:
                    scale = max(scale, 1.22)
                else:
                    scale = max(scale, min(dpi_scale, 1.32))
                if tk_scaling > scale:
                    scale = tk_scaling
                return min(scale, 1.38)
            else:
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
        try:
            return os.path.getmtime(self.omarchy_theme_path)
        except OSError:
            return None

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
        for i in range(6):
            self.button_frame.columnconfigure(i, weight=1)

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
            command=self.clear_journal_entry,
            style="Omarchy.TButton",
            padding=action_button_padding,
        ).grid(row=1, column=3, padx=5)

        ttk.Button(
            self.button_frame,
            text="Change Password",
            command=self.change_journal_password,
            style="Omarchy.TButton",
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

        scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.treeview = ttk.Treeview(self.tree_frame, yscrollcommand=scrollbar.set)
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
            print(f"Icon not applied: {e}")

    def days_since_last_entry(self):
        data = self.load_json()
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
        current_date = datetime.now().date()
        days_since = (current_date - most_recent_date).days

        if days_since == 0:
            return "You have made an entry today."
        elif days_since == 1:
            return "It has been 1 day since your last entry."
        else:
            return f"It has been {days_since} days since your last entry."

    def resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS  # PyInstaller
        except Exception:
            base_path = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(base_path, relative_path)

    def apply_theme(self):
        try:
            self.root.tk.call("set_theme", self.current_theme)
        except tk.TclError as e:
            print(f"Error applying theme: {e}")
            messagebox.showerror(
                "Error",
                "Unable to apply theme. Ensure that the theme is loaded correctly.",
            )

    def load_theme_file(self):
        try:
            azure_tcl_path = self.resource_path("azure.tcl")
            self.root.tk.call("source", azure_tcl_path)
        except tk.TclError as e:
            print(f"Error loading theme file: {e}")
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
            print(f"Spellcheck disabled due to runtime error: {e}")

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

    def prompt_for_password(self):
        if self.failed_attempts >= self.max_attempts:
            messagebox.showerror(
                "Error", "Too many failed attempts. Application will exit."
            )
            self.root.destroy()
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
        entry = ttk.Entry(dialog, textvariable=password_var, show="*")
        entry.pack(padx=20, pady=(0, 15))
        entry.focus_set()

        button_row = ttk.Frame(dialog, style="Omarchy.TFrame")
        button_row.pack(padx=20, pady=(0, 20))

        result = {"value": None}

        def submit(event=None):
            result["value"] = password_var.get()
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

    def encrypt_message(self, message, password):
        salt = secrets.token_bytes(16)
        try:
            key = self.derive_key(password, salt)
        except Exception:
            messagebox.showerror("Error", "Incorrect password.")
            return None
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, message.encode(), None)
        return base64.urlsafe_b64encode(salt + nonce + ciphertext).decode("utf-8")

    def decrypt_message(self, encrypted_message, password, count_attempt=True):
        try:
            encrypted_data = base64.urlsafe_b64decode(encrypted_message)
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            if count_attempt:
                self.failed_attempts = 0
            return plaintext.decode("utf-8")
        except Exception:
            if count_attempt:
                self.failed_attempts += 1
            raise ValueError("Incorrect password or corrupted data.")

    def change_journal_password(self):
        self.last_action_time = datetime.now()
        backup_path = None
        if os.path.exists(self.filename):
            try:
                backup_path = self.create_journal_backup()
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

        encrypted_entries = [entry.get("entry") for entry in data if entry.get("entry")]
        if encrypted_entries:
            try:
                with secure_password(current_password) as old_pwd:
                    self.decrypt_message(encrypted_entries[0], old_pwd, count_attempt=True)
            except ValueError as e:
                messagebox.showerror("Error", str(e))
                return

        updated_data = []
        failed_entries = []
        total_encrypted_entries = 0
        successful_updates = 0
        failure_threshold = 0.9

        with secure_password(current_password) as old_pwd:
            with secure_password(new_password) as new_pwd:
                for entry in data:
                    encrypted_entry = entry.get("entry")
                    if not encrypted_entry:
                        updated_data.append(entry)
                        continue
                    total_encrypted_entries += 1
                    try:
                        plaintext = self.decrypt_message(
                            encrypted_entry, old_pwd, count_attempt=False
                        )
                    except Exception as error:
                        failed_entries.append(
                            {
                                "date": entry.get("date")
                                or entry.get("timestamp")
                                or entry.get("created_at")
                                or "Unknown entry",
                                "reason": str(error),
                            }
                        )
                        updated_data.append(entry)
                        continue

                    encrypted_new = self.encrypt_message(plaintext, new_pwd)
                    if encrypted_new is None:
                        failed_entries.append(
                            {
                                "date": entry.get("date")
                                or entry.get("timestamp")
                                or entry.get("created_at")
                                or "Unknown entry",
                                "reason": "Failed to encrypt entry with the new password.",
                            }
                        )
                        updated_data.append(entry)
                        continue

                    updated_entry = dict(entry)
                    updated_entry["entry"] = encrypted_new
                    updated_data.append(updated_entry)
                    successful_updates += 1

        current_password = None
        new_password = None

        success_ratio = (
            successful_updates / total_encrypted_entries
            if total_encrypted_entries
            else 1.0
        )

        log_path = None
        if failed_entries:
            try:
                log_path = self.log_password_rotation_failures(failed_entries)
            except Exception as log_error:
                messagebox.showwarning(
                    "Logging Failed",
                    "Unable to record failed entry details for the password change.\n\n"
                    f"Details: {log_error}",
                )

        if total_encrypted_entries and success_ratio < failure_threshold:
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

    def create_journal_backup(self):
        self._ensure_parent_dir()
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_name = os.path.basename(self.filename)
        backup_name = f"{base_name}.bak-{timestamp}"
        backup_path = os.path.join(os.path.dirname(self.filename), backup_name)
        shutil.copy2(self.filename, backup_path)
        return backup_path

    def log_password_rotation_failures(self, failed_entries):
        if not failed_entries:
            return None
        log_path = os.path.join(
            os.path.dirname(self.filename), "password_rotation_failures.log"
        )
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [
            f"[{timestamp}] {failure['date']} - {failure['reason']}"
            for failure in failed_entries
        ]
        with open(log_path, "a", encoding="utf-8") as log_file:
            log_file.write("\n".join(lines) + "\n")
        return log_path

    def _ensure_parent_dir(self):
        parent = os.path.dirname(self.filename)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def save_json(self, data):
        temp_path = None
        try:
            self._ensure_parent_dir()

            parent_dir = os.path.dirname(self.filename) or "."
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

            os.replace(temp_path, self.filename)
            temp_path = None

            if os.name == "nt" and win32security:
                try:
                    user, domain, type = win32security.LookupAccountName(
                        "", os.getlogin()
                    )
                    sd = win32security.GetFileSecurity(
                        self.filename, win32security.DACL_SECURITY_INFORMATION
                    )
                    dacl = win32security.ACL()
                    dacl.AddAccessAllowedAce(
                        win32security.ACL_REVISION,
                        con.FILE_GENERIC_READ | con.FILE_GENERIC_WRITE,
                        user,
                    )
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)
                    win32security.SetFileSecurity(
                        self.filename, win32security.DACL_SECURITY_INFORMATION, sd
                    )
                except Exception as perm_error:
                    messagebox.showwarning(
                        "Warning",
                        f"Failed to set restrictive permissions on Windows: {perm_error}",
                    )
            else:
                os.chmod(self.filename, 0o600)  # lock down on Unix

        except PermissionError as e:
            raise PermissionError(
                f"Permission denied when accessing {self.filename}: {e}"
            )
        except Exception as e:
            raise Exception(f"Failed to save JSON data: {e}")
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    def load_json(self):
        if not os.path.exists(self.filename):
            return []

        try:
            with gzip.open(self.filename, "rt", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            messagebox.showwarning(
                "Warning",
                "The journal file appears to be corrupted or unreadable. "
                "It will be ignored until it is replaced with a valid backup.",
            )
            print(f"Failed to read journal file '{self.filename}': {e}")
            return []

        if isinstance(data, list):
            return data

        messagebox.showwarning(
            "Warning",
            "The journal file contains unexpected data and will be ignored.",
        )
        print(
            "Unexpected journal file contents. Expected a list of entries, "
            f"got {type(data).__name__}."
        )
        return []

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

                encrypted_entry = self.encrypt_message(journal_entry, pwd)
                if encrypted_entry is None:
                    return

                entry = {"date": date_str, "entry": encrypted_entry}
                data = self.load_json()

                # Update or append entry
                for existing_entry in data:
                    if existing_entry.get("date") == date_str:
                        existing_entry["entry"] = encrypted_entry
                        break
                else:
                    data.append(entry)

                self.save_json(data)
                messagebox.showinfo(
                    "Success", "Your journal entry has been encrypted and saved."
                )

                self.clear_journal_entry()
                self.update_treeview()
                self.days_since_label.config(text=self.days_since_last_entry())

            except Exception as e:
                messagebox.showerror("Error", f"Failed to save entry: {str(e)}")

    def load_journal_entry(self):
        self.last_action_time = datetime.now()

        password = self.prompt_for_password()
        if password is None:
            return

        try:
            selected_item = self.treeview.selection()[0]
            selected_date = self.treeview.item(selected_item, "text")
            if self.treeview.parent(selected_item):
                data = self.load_json()
                for entry in data:
                    if entry.get("date") == selected_date:
                        with secure_password(password) as pwd:
                            password = None
                            decrypted_entry = self.decrypt_message(
                                entry["entry"], pwd
                            )
                        self.text_entry.delete("1.0", tk.END)
                        self.text_entry.insert(tk.END, decrypted_entry)
                        self.date_entry.delete(0, tk.END)
                        self.date_entry.insert(0, selected_date)
                        self.entry_loaded = True
                        break
                else:
                    messagebox.showwarning(
                        "Warning", "No entry found for the selected date."
                    )
            else:
                messagebox.showinfo("Information", "Please select a date, not a month.")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except IndexError:
            messagebox.showwarning("Warning", "Please select a date from the list.")
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
                self.days_since_label.config(text=self.days_since_last_entry())
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
        resolution_ratio = (screen_width * screen_height) / float(1920 * 1080)
        resolution_scale = resolution_ratio**0.08
    except Exception:
        resolution_scale = 1.0

    return _clamp(dpi_scale * resolution_scale, 0.95, 1.45)


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
