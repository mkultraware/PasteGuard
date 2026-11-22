import re
import json
import copy
import threading
import tkinter as tk
import winreg
import logging
import os
import sys
import ctypes
import ctypes.wintypes
from urllib.parse import urlparse, unquote, urlunparse
import win32clipboard
import win32con
import win32gui
import win32api
import pystray
from PIL import Image, ImageDraw, ImageTk, ImageFont

APP_NAME    = "Sekura PasteGuard"
LOG_FILE    = os.path.join(os.path.expanduser("~"), "pasteguard.log")
CONFIG_FILE = os.path.join(os.path.expanduser("~"), "pasteguard.json")

DEFAULT_STATE = {
    "silent_mode": False,
    "notifications": True,
    "stats": {"blocked": 0, "cleaned": 0},
}

# --- Persistence ---

def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            saved = json.load(f)
        config = copy.deepcopy(DEFAULT_STATE)
        config["silent_mode"]      = saved.get("silent_mode", DEFAULT_STATE["silent_mode"])
        config["notifications"]    = saved.get("notifications", DEFAULT_STATE["notifications"])
        config["stats"]["blocked"] = saved.get("stats", {}).get("blocked", 0)
        config["stats"]["cleaned"] = saved.get("stats", {}).get("cleaned", 0)
        return config
    except Exception:
        return copy.deepcopy(DEFAULT_STATE)

def save_config():
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump({
                "silent_mode":   state["silent_mode"],
                "notifications": state["notifications"],
                "stats":         state["stats"],
            }, f, indent=2)
    except Exception as e:
        log(f"Config save failed: {e}", "warning")

_saved = load_config()
state = {
    **_saved,
    "recent_value":  "",
    "icon":          None,
    "whitelist":     set(),  # session-only, cleared on restart
    "settings_open": False,
}

# --- Startup (Run key) ---

RUN_KEY_PATH   = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = "Sekura PasteGuard"

def startup_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH) as key:
            winreg.QueryValueEx(key, RUN_VALUE_NAME)
            return True
    except Exception:
        return False

def set_startup_enabled(enabled):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY_PATH, 0, winreg.KEY_SET_VALUE) as key:
            if enabled:
                if getattr(sys, "frozen", False):
                    cmd = f'"{sys.executable}"'
                else:
                    cmd = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
                winreg.SetValueEx(key, RUN_VALUE_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(key, RUN_VALUE_NAME)
                except FileNotFoundError:
                    pass
    except Exception as e:
        log(f"Startup toggle failed: {e}", "warning")

# --- Logging ---

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log(msg, level="info"):
    print(msg)
    getattr(logging, level)(msg)

# --- Tracking params ---

TRACKING_PARAMS_SET = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "dclid", "gbraid", "wbraid",
    "ttclid", "igshid", "twclid", "msclkid", "yclid",
    "li_fat_id", "trk", "lipi", "mc_eid", "_ga",
    "si", "ref", "ref_",
}

# --- Detection ---
#
# Tier 1: structurally unambiguous patterns, fire standalone.
# Tier 2: tool name + shell signal required, prevents false positives
#         when tool names appear in prose or documentation.

# Anchored to line start so prose mentioning these tools mid-sentence does not fire.
TIER1_PATTERNS = [
    (r"^\s*cmd(?:\.exe)?\s+/[cCkK](?=\s|$)",                "CMD /c"),
    (r"^\s*(?:powershell|pwsh)(?:\.exe)?\s+-\w",             "PowerShell"),
    (r"-(?:enc(?:odedcommand)?|e)\s+[A-Za-z0-9+/=]{20,}",     "Encoded PowerShell command"),
    (r"(?:Invoke-WebRequest|iwr)\b[^\n]{0,80}?[\"']?https?://", "Invoke-WebRequest"),
    (r"(?:Invoke-RestMethod|irm)\b[^\n]{0,80}?[\"']?https?://", "Invoke-RestMethod"),
    (r"\biex\b|Invoke-Expression",                           "Invoke-Expression"),
    (r"DownloadString|DownloadFile",                         "WebClient download"),
    (r"&\s*\(\s*\$",                                         "Dynamic invocation"),
    (r"\bcurl(?:\.exe)?\b[^\n]*?[\"']?https?://",            "curl download"),
    (r"^\s*reg(?:\.exe)?\s+add\s+(?:HKEY|HKCU|HKLM|HKCR|HKU|HKCC)", "Registry write"),
    (r"bash\s+-c\s+[\"'$\{]",                                 "Bash (WSL)"),
    (r"certutil(?:\.exe)?[^\n]{0,40}(?:-urlcache|-decode|-encode|/urlcache)", "Certutil fetch/decode"),
    (r"bitsadmin\s+(?:/transfer|/create|/addfile)",           "BitsAdmin transfer"),
    (r"\bnet\s+(?:user|localgroup)\b[^\n|;&]{0,80}/(?:add|delete|reset)\b",
                                                                "Net user/group"),
    (r"Start-Process\s+(?:-FilePath\s+\S+|\S+\.(?:exe|bat|cmd|ps1|vbs|msi)\b"
       r"|powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|certutil|bitsadmin)",
                                                                "Start-Process"),
    (r"New-Object\s+(?:-TypeName\s+)?(?:System\.)?Net\.(?:WebClient|TcpClient)",
                                                                "WebClient/TcpClient object"),
    (r"(?:powershell|pwsh|mshta|cmd|wscript|cscript|rundll32)[^\n]{0,60}[A-Za-z0-9+/]{60,}={0,2}",
                                                                "Base64 payload"),
]

_SHELL_TOOLS = r"(?:mshta|msiexec|rundll32|certutil|wscript|cscript|wmic|regsvr32|bitsadmin|schtasks)"  # cmd/powershell/pwsh are handled by anchored tier-1 patterns
_SHELL_SIGNAL = (
    r"(?:"
    r"\s*[|&;]\s*"
    r"|\s+[\"']?https?://"
    r"|\s+-\w"
    r"|\s+//?\w"
    r"|\s+\$\w"
    r"|\s+vbscript:"
    r"|\s+javascript:"
    r"|\s+[\"']?\S+\.(?:dll|vbs|js|hta|bat|ps1|cmd|exe)\b"
    r")"
)

COMPILED_TIER1 = [(re.compile(p, re.IGNORECASE | re.MULTILINE), l) for p, l in TIER1_PATTERNS]
COMPILED_TIER2 = re.compile(_SHELL_TOOLS + r"(?:\.exe)?" + _SHELL_SIGNAL, re.IGNORECASE)

def detect_command(text):
    for pattern, label in COMPILED_TIER1:
        if pattern.search(text):
            return True, label
    m = COMPILED_TIER2.search(text)
    if m:
        return True, f"Shell command ({m.group(0).strip()[:40]})"
    return False, None

# --- URL cleaning ---

def clean_url(text):
    """Returns (cleaned_url, removed_params) if tracking params were removed, else None.
    Non-tracking query segments are kept verbatim so their encoding is preserved."""
    text = text.strip()
    if not (text.startswith("http://") or text.startswith("https://")):
        return None
    try:
        parsed = urlparse(text)
        if not parsed.query:
            return None
        # Tolerate HTML-escaped separators (&amp;) when copying links from web pages.
        query = parsed.query.replace("&amp;", "&")
        kept, removed = [], set()
        for segment in query.split("&"):
            if not segment:
                continue
            key = unquote(segment.split("=", 1)[0])
            if key in TRACKING_PARAMS_SET or key.startswith("ref_"):
                removed.add(key)
            else:
                kept.append(segment)
        if not removed:
            return None
        cleaned = urlunparse(parsed._replace(query="&".join(kept)))
        return cleaned, sorted(removed)
    except Exception:
        return None

# --- Notifications ---

def notify_tray(title, message):
    if not state["notifications"]:
        return
    try:
        if state["icon"]:
            state["icon"].notify(message, title)
    except Exception:
        log(f"[NOTIFY] {title}: {message}")

# --- System theme ---

def is_dark_mode():
    key = None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        )
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return value == 0
    except Exception:
        return True  # default to dark
    finally:
        if key is not None:
            try:
                winreg.CloseKey(key)
            except Exception:
                pass

# --- Windows 11 rounded corners ---

def apply_rounded_corners(hwnd):
    try:
        DWMWA_WINDOW_CORNER_PREFERENCE = 33
        DWMWCP_ROUND = 2
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            ctypes.byref(ctypes.c_int(DWMWCP_ROUND)),
            ctypes.sizeof(ctypes.c_int)
        )
    except Exception:
        pass

def enable_dpi_awareness():
    """Per-monitor DPI awareness. Without it Windows bitmap-stretches our
    windows on high-DPI displays, which disables ClearType and makes text
    and icons look jagged. Must be called before any window is created."""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PROCESS_PER_MONITOR_DPI_AWARE
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

# --- Warning dialog ---

def show_warning_dialog(payload_text, trigger_label):
    """Returns: 'cancel' | 'keep' | 'whitelist'"""
    dark = is_dark_mode()

    # Colors based on system theme
    if dark:
        bg          = "#1c1c1e"
        surface     = "#2c2c2e"
        text_pri    = "#ffffff"
        text_sec    = "#ababab"
        text_dim    = "#636366"
        accent      = "#f0a500"
        btn_cancel  = "#3a3a3c"
        btn_cancel_fg = "#ffffff"
        btn_keep    = "#2c2c2e"
        btn_keep_fg = "#ababab"
        btn_trust   = "#1c3a1c"
        btn_trust_fg = "#4cd964"
        border      = "#3a3a3c"
    else:
        bg          = "#f2f2f7"
        surface     = "#ffffff"
        text_pri    = "#000000"
        text_sec    = "#3c3c43"
        text_dim    = "#8e8e93"
        accent      = "#c07800"
        btn_cancel  = "#e5e5ea"
        btn_cancel_fg = "#000000"
        btn_keep    = "#e5e5ea"
        btn_keep_fg = "#3c3c43"
        btn_trust   = "#d4edda"
        btn_trust_fg = "#1a7a2e"
        border      = "#d1d1d6"

    # Flash fix: invisible root, never shown
    root = tk.Tk()
    root.geometry("0x0+0+0")
    root.attributes("-alpha", 0)
    root.withdraw()

    dialog = tk.Toplevel(root)
    dialog.title("")
    dialog.geometry("480x310")
    dialog.resizable(False, False)
    dialog.attributes("-topmost", True)
    dialog.configure(bg=bg)
    dialog.overrideredirect(False)

    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth()  // 2) - 240
    y = (dialog.winfo_screenheight() // 2) - 155
    dialog.geometry(f"+{x}+{y}")

    # Apply Windows 11 rounded corners
    dialog.update()
    hwnd = ctypes.windll.user32.GetParent(dialog.winfo_id())
    if hwnd == 0:
        hwnd = dialog.winfo_id()
    apply_rounded_corners(hwnd)

    result = {"action": "cancel"}

    # App label
    tk.Label(dialog, text="Sekura PasteGuard",
             font=("Segoe UI", 9), fg=text_dim, bg=bg).pack(pady=(20, 0))

    # Title
    tk.Label(dialog, text="Suspicious command detected",
             font=("Segoe UI", 14, "bold"), fg=text_pri, bg=bg).pack(pady=(4, 0))

    # Trigger label
    tk.Label(dialog, text=f"Triggered by: {trigger_label}",
             font=("Segoe UI", 9), fg=accent, bg=bg).pack(pady=(4, 0))

    # Divider
    tk.Frame(dialog, height=1, bg=border).pack(fill="x", padx=24, pady=(12, 0))

    # Snippet
    snippet = payload_text[:120].replace("\n", " ").replace("\r", "")
    if len(payload_text) > 120:
        snippet += "..."
    tk.Label(dialog, text=snippet,
             font=("Cascadia Code", 8) if True else ("Courier New", 8),
             fg=text_sec, bg=surface,
             wraplength=420, justify="left", anchor="w",
             padx=12, pady=8).pack(fill="x", padx=24, pady=(12, 0))

    # Subtext
    tk.Label(dialog,
             text="Only proceed if you know exactly what this command does.",
             font=("Segoe UI", 8), fg=text_dim, bg=bg,
             wraplength=420).pack(pady=(10, 0))

    # Divider
    tk.Frame(dialog, height=1, bg=border).pack(fill="x", padx=24, pady=(12, 0))

    # Buttons
    btn_frame = tk.Frame(dialog, bg=bg)
    btn_frame.pack(pady=(10, 0))

    def on_cancel():
        result["action"] = "cancel"
        dialog.destroy()
        root.destroy()

    def on_keep():
        result["action"] = "keep"
        dialog.destroy()
        root.destroy()

    def on_whitelist():
        result["action"] = "whitelist"
        dialog.destroy()
        root.destroy()

    btn_cfg = {"relief": "flat", "padx": 16, "pady": 6, "cursor": "hand2", "bd": 0}

    tk.Button(btn_frame, text="Clear Clipboard", command=on_cancel,
              font=("Segoe UI", 9, "bold"),
              bg="#c0392b", fg="#ffffff",
              activebackground="#a93226", activeforeground="#ffffff",
              **btn_cfg).pack(side="left", padx=(0, 8))

    tk.Button(btn_frame, text="Copy Anyway", command=on_keep,
              font=("Segoe UI", 9),
              bg=btn_keep, fg=btn_keep_fg,
              activebackground=border, activeforeground=text_pri,
              **btn_cfg).pack(side="left", padx=(0, 8))

    tk.Button(btn_frame, text="Trust This Session", command=on_whitelist,
              font=("Segoe UI", 9),
              bg=btn_trust, fg=btn_trust_fg,
              activebackground=btn_trust, activeforeground=btn_trust_fg,
              **btn_cfg).pack(side="left")

    dialog.protocol("WM_DELETE_WINDOW", on_cancel)
    dialog.grab_set()
    root.wait_window(dialog)

    return result["action"]

# --- Settings window ---

SETTINGS_BG      = "#060609"   # canvas base (fallback before gradient paints)
SETTINGS_SURFACE = "#1b1b22"
SETTINGS_PILL    = "#26262e"
SETTINGS_BORDER  = "#2b2b35"
SETTINGS_TEXT    = "#f5f5f8"
SETTINGS_SUB     = "#a9a9b8"
SETTINGS_DIM     = "#6e6e7d"
SETTINGS_LAV     = "#b8a9ff"
SETTINGS_BLUE    = "#2e7dff"

_RESAMPLE = getattr(Image, "Resampling", Image).LANCZOS
_FONT_CACHE = {}

def _settings_hex(c):
    c = c.lstrip("#")
    return tuple(int(c[i:i + 2], 16) for i in (0, 2, 4))

def _pil_font(px, bold=False):
    key = (px, bold)
    if key in _FONT_CACHE:
        return _FONT_CACHE[key]
    names = (["segoeuib.ttf", "segoeui.ttf", "arialbd.ttf", "arial.ttf"] if bold
             else ["segoeui.ttf", "segoeuil.ttf", "arial.ttf"])
    font = None
    for name in names:
        try:
            font = ImageFont.truetype(name, px)
            break
        except Exception:
            continue
    if font is None:
        font = ImageFont.load_default()
    _FONT_CACHE[key] = font
    return font

def _icon_image(kind, size=24, color=SETTINGS_LAV):
    """Flat monochrome icon, PIL-rendered at 4x and downscaled."""
    scale = 4
    w = h = size * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img)
    rgb = _settings_hex(color)
    lw = max(3, int(scale * 2.5))

    if kind == "logo":
        # Rounded square (lavender) with a white clipboard check
        dc.rounded_rectangle((w*0.10, h*0.10, w*0.90, h*0.90), radius=w*0.24,
                             fill=_settings_hex(SETTINGS_LAV) + (255,))
        dc.line((w*0.32, h*0.50, w*0.46, h*0.66), fill=_settings_hex(SETTINGS_BG), width=lw)
        dc.line((w*0.46, h*0.66, w*0.70, h*0.36), fill=_settings_hex(SETTINGS_BG), width=lw)
    elif kind == "bell":
        dome = (w*0.24, h*0.14, w*0.76, h*0.72)
        dc.arc(dome, 180, 360, fill=rgb, width=lw)
        dc.line((w*0.24, h*0.48, w*0.76, h*0.48), fill=rgb, width=lw)
        dc.ellipse((w*0.44, h*0.66, w*0.56, h*0.78), fill=rgb)
    elif kind == "bell_dot":
        dome = (w*0.22, h*0.16, w*0.72, h*0.72)
        dc.arc(dome, 180, 360, fill=rgb, width=lw)
        dc.line((w*0.22, h*0.48, w*0.72, h*0.48), fill=rgb, width=lw)
        dc.ellipse((w*0.40, h*0.68, w*0.52, h*0.80), fill=rgb)
        dc.ellipse((w*0.70, h*0.16, w*0.88, h*0.34), fill=rgb)
    elif kind == "windows":
        gap, cell = w*0.06, (w - w*0.06) / 2
        for i in range(2):
            for j in range(2):
                x0 = i * (cell + gap)
                y0 = j * (cell + gap)
                dc.rounded_rectangle((x0, y0, x0 + cell, y0 + cell), radius=scale, fill=rgb)
    elif kind == "chart":
        base = h * 0.86
        heights = [h*0.32, h*0.54, h*0.76]
        xs = [w*0.16, w*0.42, w*0.68]
        for x, hh in zip(xs, heights):
            dc.rounded_rectangle((x, base - hh, x + w*0.16, base), radius=scale, fill=rgb)
    elif kind == "check":
        dc.ellipse((w*0.12, h*0.12, w*0.88, h*0.88), outline=rgb, width=lw)
        dc.line((w*0.30, h*0.50, w*0.44, h*0.66), fill=rgb, width=lw)
        dc.line((w*0.44, h*0.66, w*0.72, h*0.34), fill=rgb, width=lw)
    elif kind == "doc":
        dc.rounded_rectangle((w*0.26, h*0.14, w*0.74, h*0.86), radius=scale, outline=rgb, width=lw//2 + 2)
        dc.line((w*0.38, h*0.44, w*0.62, h*0.44), fill=rgb, width=max(2, lw // 2))
        dc.line((w*0.38, h*0.60, w*0.62, h*0.60), fill=rgb, width=max(2, lw // 2))
    elif kind == "exit":
        dc.line((w*0.44, h*0.18, w*0.44, h*0.82), fill=rgb, width=lw)
        dc.line((w*0.44, h*0.50, w*0.84, h*0.50), fill=rgb, width=lw)
        dc.line((w*0.68, h*0.34, w*0.86, h*0.50), fill=rgb, width=lw)
        dc.line((w*0.86, h*0.50, w*0.68, h*0.66), fill=rgb, width=lw)
    elif kind == "minimize":
        dc.line((w*0.26, h*0.50, w*0.74, h*0.50), fill=rgb, width=lw)
    elif kind == "close":
        dc.line((w*0.30, h*0.30, w*0.70, h*0.70), fill=rgb, width=lw)
        dc.line((w*0.70, h*0.30, w*0.30, h*0.70), fill=rgb, width=lw)

    return img.resize((size, size), _RESAMPLE)

def _pill_image(text, fill, text_color="#ffffff", height=40, bold=False,
                icon_kind=None, icon_color=None):
    scale = 2
    font = _pil_font(15 * scale, bold)
    icon = None
    if icon_kind:
        icon = _icon_image(icon_kind, 17 * scale, icon_color or text_color)
    bb = font.getbbox(text)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    pad_x = 20 * scale
    icon_w = (17 * scale + 9 * scale) if icon_kind else 0
    w = pad_x * 2 + icon_w + tw
    h = height * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img)
    dc.rounded_rectangle((0, 0, w - 1, h - 1), radius=h // 2, fill=_settings_hex(fill) + (255,))
    x = pad_x
    if icon:
        img.paste(icon, (x, (h - 17 * scale) // 2), icon)
        x += 17 * scale + 9 * scale
    dc.text((x, (h - th) // 2 - bb[1]), text, font=font, fill=_settings_hex(text_color))
    return img.resize((w // scale, h // scale), _RESAMPLE)

def _toggle_image(on):
    """Render the pill switch with PIL at 4x and downscale, so edges
    are antialiased (Tk canvas ovals are not)."""
    scale = 4
    w, h = 52 * scale, 28 * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img)
    fill = _settings_hex(SETTINGS_BLUE) if on else _settings_hex(SETTINGS_PILL)
    dc.rounded_rectangle((0, 0, w - 1, h - 1), radius=h // 2, fill=fill + (255,))
    knob = h - 4 * scale
    x0 = (w - knob - 2 * scale) if on else (2 * scale)
    dc.ellipse((x0, 2 * scale, x0 + knob, 2 * scale + knob), fill=(255, 255, 255, 255))
    return img.resize((52, 28), _RESAMPLE)

def _gradient_image(w, h):
    """Vertical black-to-dark-grey gradient."""
    top = (5, 5, 9)
    bottom = (33, 33, 40)
    img = Image.new("RGB", (w, h))
    px = img.load()
    for y in range(h):
        t = y / (h - 1)
        r = round(top[0] + (bottom[0] - top[0]) * t)
        g = round(top[1] + (bottom[1] - top[1]) * t)
        b = round(top[2] + (bottom[2] - top[2]) * t)
        for x in range(w):
            px[x, y] = (r, g, b)
    return img

def _card_image(w, h):
    """Rounded stats card, rendered at 2x for antialiasing."""
    scale = 2
    img = Image.new("RGBA", (w * scale, h * scale), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img)
    dc.rounded_rectangle((0, 0, w * scale - 1, h * scale - 1),
                         radius=13 * scale,
                         fill=_settings_hex(SETTINGS_SURFACE) + (255,))
    dc.rounded_rectangle((0, 0, w * scale - 1, h * scale - 1),
                         radius=13 * scale,
                         outline=_settings_hex(SETTINGS_BORDER),
                         width=scale)
    return img.resize((w, h), _RESAMPLE)

def _settings_window():
    # Flash fix: invisible root, never shown
    root = tk.Tk()
    root.geometry("0x0+0+0")
    root.attributes("-alpha", 0)
    root.withdraw()

    win = tk.Toplevel(root)
    win.title("PasteGuard Settings")
    win.overrideredirect(True)
    win.resizable(False, False)
    win.attributes("-topmost", True)
    win.configure(bg=SETTINGS_BG)

    WIN_W, WIN_H = 500, 500
    win.geometry(f"{WIN_W}x{WIN_H}")
    win.update_idletasks()
    x = (win.winfo_screenwidth()  // 2) - WIN_W // 2
    y = (win.winfo_screenheight() // 2) - WIN_H // 2
    win.geometry(f"+{x}+{y}")
    win.update()
    hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
    if hwnd == 0:
        hwnd = win.winfo_id()
    apply_rounded_corners(hwnd)

    photos = []

    def photo(img):
        p = ImageTk.PhotoImage(img)
        photos.append(p)
        return p

    def close_win():
        win.destroy()

    def minimize_win():
        # Override-redirect windows can't be iconified (iconify raises TclError
        # on them). Minimize hides the window; the app keeps running in the
        # tray, and Settings can be re-opened from the tray's Settings menu.
        win.withdraw()
        win.destroy()

    canvas = tk.Canvas(win, width=WIN_W, height=WIN_H, bg=SETTINGS_BG,
                       highlightthickness=0, bd=0, cursor="arrow")
    canvas.pack(fill="both", expand=True)
    canvas.create_image(0, 0, anchor="nw",
                        image=photo(_gradient_image(WIN_W, WIN_H)))

    # ---- Title bar ----
    canvas.create_image(16, 14, anchor="nw",
                        image=photo(_icon_image("logo", 22, SETTINGS_LAV)))
    canvas.create_text(46, 19, text="PasteGuard Settings", fill="#e8e8ee",
                       font=("Segoe UI", 10, "bold"), anchor="nw")

    def title_button(kind, x, y, size, color, cmd):
        item = canvas.create_image(x, y, anchor="nw",
                                   image=photo(_icon_image(kind, size, color)),
                                   tags=("tb_btn",))
        canvas.tag_bind(item, "<Button-1>", lambda e: cmd())
        canvas.tag_bind(item, "<Enter>", lambda e: canvas.configure(cursor="hand2"))
        canvas.tag_bind(item, "<Leave>", lambda e: canvas.configure(cursor=""))

    title_button("minimize", 424, 17, 15, SETTINGS_DIM, minimize_win)
    title_button("close", 458, 17, 15, "#ff6b6b", close_win)

    # ---- Header ----
    canvas.create_text(28, 52, text="Settings", fill="#ffffff",
                       font=("Segoe UI", 22, "bold"), anchor="nw")

    def pill(x, y, text, fill, command, icon_kind=None, icon_color=None,
             bold=False, height=34, text_color="#ffffff"):
        img = _pill_image(text, fill, text_color, height=height, bold=bold,
                          icon_kind=icon_kind, icon_color=icon_color)
        item = canvas.create_image(x, y, anchor="nw", image=photo(img),
                                   tags=("pill",))
        canvas.tag_bind(item, "<Button-1>", lambda e: command())
        canvas.tag_bind(item, "<Enter>", lambda e: canvas.configure(cursor="hand2"))
        canvas.tag_bind(item, "<Leave>", lambda e: canvas.configure(cursor=""))

        return img.size

    close_w = _pill_image("Close", SETTINGS_PILL, "#ffffff", height=34).size[0]
    pill(WIN_W - 28 - close_w, 54, "Close", SETTINGS_PILL, close_win, height=34)

    # ---- Sections / rows ----
    def section(y, title):
        canvas.create_rectangle(28, y + 3, 31, y + 19, fill=SETTINGS_LAV,
                                outline=SETTINGS_LAV)
        canvas.create_text(42, y, text=title, fill=SETTINGS_LAV,
                           font=("Segoe UI", 11, "bold"), anchor="nw")

    def toggle(x, y, on, on_toggle):
        st = {"on": on, "item": None}

        def draw():
            if st["item"] is not None:
                canvas.delete(st["item"])
            st["item"] = canvas.create_image(x, y, anchor="nw",
                                              image=photo(_toggle_image(st["on"])),
                                              tags=("toggle",))
            canvas.tag_bind(st["item"], "<Button-1>", lambda e: fire())
            canvas.tag_bind(st["item"], "<Enter>", lambda e: canvas.configure(cursor="hand2"))
            canvas.tag_bind(st["item"], "<Leave>", lambda e: canvas.configure(cursor=""))

        def fire():
            st["on"] = not st["on"]
            draw()
            on_toggle(st["on"])

        draw()

    def row(y, icon_kind, label, on, on_toggle):
        canvas.create_image(28, y, anchor="nw",
                            image=photo(_icon_image(icon_kind, 22, SETTINGS_LAV)))
        canvas.create_text(62, y + 4, text=label, fill=SETTINGS_TEXT,
                           font=("Segoe UI", 11), anchor="nw")
        toggle(WIN_W - 28 - 52, y + 1, on, on_toggle)

    def set_silent(v):
        state["silent_mode"] = v
        save_config()
        log(f"Silent mode: {'ON' if v else 'OFF'}")

    def set_notifications(v):
        state["notifications"] = v
        save_config()
        log(f"Notifications: {'ON' if v else 'OFF'}")

    def set_startup(v):
        set_startup_enabled(v)
        log(f"Startup: {'ON' if v else 'OFF'}")

    section(104, "Behavior")
    row(140, "bell", "Silent Mode", state["silent_mode"], set_silent)
    row(184, "bell_dot", "Notifications", state["notifications"], set_notifications)

    section(234, "Startup")
    row(276, "windows", "Start with Windows", startup_enabled(), set_startup)

    section(326, "Stats")
    card_y = 358
    canvas.create_image(28, card_y, anchor="nw",
                        image=photo(_card_image(WIN_W - 56, 50)))
    canvas.create_image(44, card_y + 15, anchor="nw",
                        image=photo(_icon_image("chart", 20, SETTINGS_LAV)))
    canvas.create_text(74, card_y + 14, text=f"Blocked:  {state['stats']['blocked']}",
                       fill=SETTINGS_TEXT, font=("Segoe UI", 11, "bold"), anchor="nw")
    canvas.create_line(252, card_y + 13, 252, card_y + 37, fill="#35353f", width=1)
    canvas.create_image(270, card_y + 15, anchor="nw",
                        image=photo(_icon_image("check", 20, SETTINGS_LAV)))
    canvas.create_text(300, card_y + 14, text=f"Cleaned:  {state['stats']['cleaned']}",
                       fill=SETTINGS_TEXT, font=("Segoe UI", 11, "bold"), anchor="nw")

    # ---- Footer ----
    ft_y = 432
    s = pill(28, ft_y, "View Log", SETTINGS_PILL, lambda: os.startfile(LOG_FILE),
             icon_kind="doc", icon_color=SETTINGS_SUB, height=40)
    quit_w = _pill_image("Quit App", SETTINGS_BLUE, "#ffffff", height=40, bold=True,
                         icon_kind="exit").size[0]
    pill(WIN_W - 28 - quit_w, ft_y, "Quit App", SETTINGS_BLUE,
         lambda: on_quit(state["icon"], None), icon_kind="exit", bold=True, height=40)

    win.protocol("WM_DELETE_WINDOW", close_win)
    win.bind("<Escape>", lambda e: close_win())
    root.wait_window(win)
    root.destroy()

# --- Clipboard I/O ---

def get_clipboard_text():
    try:
        win32clipboard.OpenClipboard()
        if win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
            data = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT)
        elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_TEXT):
            data = win32clipboard.GetClipboardData(win32con.CF_TEXT).decode("utf-8", errors="replace")
        else:
            data = None
        win32clipboard.CloseClipboard()
        return data
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass
        return None

def clear_clipboard():
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.CloseClipboard()
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass

def set_clipboard_text(text):
    try:
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardData(win32con.CF_UNICODETEXT, text)
        win32clipboard.CloseClipboard()
    except Exception:
        try:
            win32clipboard.CloseClipboard()
        except Exception:
            pass

# --- Clipboard processing ---

def process_clipboard(text):
    if text == state["recent_value"]:
        return
    state["recent_value"] = text

    is_cmd, label = detect_command(text)

    if is_cmd:
        if text in state["whitelist"]:
            log(f"Whitelisted payload skipped [{label}]")
            return

        log(f"Command detected [{label}]: {text[:100]!r}")

        if state["silent_mode"]:
            if get_clipboard_text() == text:
                clear_clipboard()
                state["recent_value"] = ""
                state["stats"]["blocked"] += 1
                save_config()
                update_tray_menu()
                log("Silently cleared.")
        else:
            action = show_warning_dialog(text, label)
            if action == "cancel":
                if get_clipboard_text() == text:
                    clear_clipboard()
                    state["recent_value"] = ""
                    state["stats"]["blocked"] += 1
                    save_config()
                    update_tray_menu()
                    log("User cancelled. Clipboard cleared.")
            elif action == "whitelist":
                state["whitelist"].add(text)
                log(f"Payload whitelisted for session [{label}]")
            else:
                log("User chose to keep command in clipboard.")
    else:
        result = clean_url(text)
        if result:
            cleaned, removed = result
            if get_clipboard_text() == text:
                set_clipboard_text(cleaned)
                state["recent_value"] = cleaned
                state["stats"]["cleaned"] += 1
                save_config()
                update_tray_menu()
                log(f"URL cleaned -> {cleaned} (removed: {', '.join(removed)})")
                notify_tray("URL Cleaned", "Tracking parameters removed.")

# --- Clipboard listener (event-driven via WM_CLIPBOARDUPDATE) ---

WM_CLIPBOARDUPDATE = 0x031D

def clipboard_wnd_proc(hwnd, msg, wparam, lparam):
    if msg == WM_CLIPBOARDUPDATE:
        text = get_clipboard_text()
        if text:
            threading.Thread(target=process_clipboard, args=(text,), daemon=True).start()
    elif msg == win32con.WM_DESTROY:
        win32gui.PostQuitMessage(0)
    return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

def run_clipboard_listener():
    wc = win32gui.WNDCLASS()
    wc.lpfnWndProc   = clipboard_wnd_proc
    wc.lpszClassName = "PasteGuardListener"
    wc.hInstance     = win32api.GetModuleHandle(None)
    win32gui.RegisterClass(wc)

    hwnd = win32gui.CreateWindow(
        wc.lpszClassName, "PasteGuard Listener",
        0, 0, 0, 0, 0, win32con.HWND_MESSAGE, 0, wc.hInstance, None
    )

    ctypes.windll.user32.AddClipboardFormatListener(hwnd)
    log("Clipboard listener active.")
    win32gui.PumpMessages()

# --- Tray ---

def resource_path(filename):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, filename)

def create_icon_image():
    try:
        return Image.open(resource_path("clipboard-x.512.ico"))
    except Exception:
        img = Image.new("RGB", (64, 64), "#1a1a2e")
        dc  = ImageDraw.Draw(img)
        dc.rectangle((16, 16, 48, 48), fill="#f0a500")
        return img

def open_settings(icon, item):
    # Must run on a worker thread, NOT the pystray callback thread. The callback
    # fires inside pystray's GetMessage/DispatchMessage loop on the main thread;
    # if _settings_window() blocks that thread in root.wait_window(), the two
    # message pumps (pystray's and Tk's) fight over the queue and the native
    # WM_CLOSE from the title-bar X is lost. A worker thread keeps pystray's
    # loop free - the same pattern show_warning_dialog already uses.
    if state.get("settings_open"):
        return
    state["settings_open"] = True
    def runner():
        try:
            _settings_window()
        except Exception as e:
            log(f"Settings window failed: {e}", "error")
        finally:
            state["settings_open"] = False
    threading.Thread(target=runner, daemon=True).start()

def on_quit(icon, item):
    save_config()
    icon.stop()

def build_menu():
    return pystray.Menu(
        pystray.MenuItem("Settings", open_settings),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Quit", on_quit),
    )

def update_tray_menu():
    if state["icon"]:
        state["icon"].menu = build_menu()
        state["icon"].update_menu()

def main():
    enable_dpi_awareness()
    icon_image    = create_icon_image()
    icon          = pystray.Icon(APP_NAME, icon_image, APP_NAME, build_menu())
    state["icon"] = icon

    threading.Thread(target=run_clipboard_listener, daemon=True).start()
    icon.run()

if __name__ == "__main__":
    main()
