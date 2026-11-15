import re
import json
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
from PIL import Image, ImageDraw, ImageTk

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
        config = DEFAULT_STATE.copy()
        config["silent_mode"]      = saved.get("silent_mode", DEFAULT_STATE["silent_mode"])
        config["notifications"]    = saved.get("notifications", DEFAULT_STATE["notifications"])
        config["stats"]["blocked"] = saved.get("stats", {}).get("blocked", 0)
        config["stats"]["cleaned"] = saved.get("stats", {}).get("cleaned", 0)
        return config
    except Exception:
        return DEFAULT_STATE.copy()

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

TIER1_PATTERNS = [
    (r"cmd(?:\.exe)?\s*/[cCkK]",                                "CMD /c"),
    (r"powershell(?:\.exe)?\s+-\w",                             "PowerShell"),
    (r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}",            "Encoded PowerShell command"),
    (r"Invoke-WebRequest|iwr\s+https?://",                      "Invoke-WebRequest"),
    (r"Invoke-RestMethod|irm\s+https?://",                      "Invoke-RestMethod"),
    (r"\biex\b|Invoke-Expression",                              "Invoke-Expression"),
    (r"DownloadString|DownloadFile",                            "WebClient download"),
    (r"&\s*\(\s*\$",                                            "Dynamic invocation"),
    (r"curl\s+https?://",                                       "curl download"),
    (r"reg\s+add\s+HKEY",                                       "Registry write"),
    (r"bash\s+-c\s+[\"'$\{]",                                   "Bash (WSL)"),
    (r"certutil\s+(?:-urlcache|-decode|-encode|/urlcache)",     "Certutil fetch/decode"),
    (r"bitsadmin\s+(?:/transfer|/create|/addfile)",             "BitsAdmin transfer"),
    (r"\bnet\s+(?:user|localgroup)\b[^\n|;&]{0,80}/(?:add|delete|reset)\b",
                                                                "Net user/group"),
    (r"Start-Process\s+(?:-FilePath\s+\S+|\S+\.(?:exe|bat|cmd|ps1|vbs|msi)\b"
       r"|powershell|cmd|mshta|wscript|cscript|rundll32|certutil|bitsadmin)",
                                                                "Start-Process"),
    (r"New-Object\s+(?:-TypeName\s+)?(?:System\.)?Net\.(?:WebClient|TcpClient)",
                                                                "WebClient/TcpClient object"),
    (r"(?:powershell|mshta|cmd|wscript|cscript|rundll32)[^\n]{0,60}[A-Za-z0-9+/]{60,}={0,2}",
                                                                "Base64 payload"),
]

_SHELL_TOOLS = r"(?:mshta|msiexec|rundll32|certutil|wscript|cscript|wmic|regsvr32|bitsadmin|schtasks|powershell|cmd)"
_SHELL_SIGNAL = (
    r"(?:"
    r"\s*[|&;]\s*"
    r"|\s+https?://"
    r"|\s+-\w"
    r"|\s+//?\w"
    r"|\s+\$\w"
    r"|\s+vbscript:"
    r"|\s+javascript:"
    r"|\s+\S+\.(?:dll|vbs|js|hta|bat|ps1|cmd|exe)\b"
    r")"
)

COMPILED_TIER1 = [(re.compile(p, re.IGNORECASE), l) for p, l in TIER1_PATTERNS]
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
        kept, removed = [], set()
        for segment in parsed.query.split("&"):
            if not segment:
                continue
            key = unquote(segment.split("=", 1)[0])
            if key in TRACKING_PARAMS_SET:
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
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        )
        value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
        winreg.CloseKey(key)
        return value == 0
    except Exception:
        return True  # default to dark

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

def _settings_colors():
    if is_dark_mode():
        return {
            "bg":        "#1c1c1e",
            "surface":   "#2c2c2e",
            "text_pri":  "#ffffff",
            "text_sec":  "#ababab",
            "text_dim":  "#636366",
            "border":    "#3a3a3c",
            "accent":    "#f0a500",
            "track_off": "#39393d",
            "btn":       "#3a3a3c",
            "btn_fg":    "#ffffff",
            "danger":    "#c0392b",
        }
    return {
        "bg":        "#f2f2f7",
        "surface":   "#ffffff",
        "text_pri":  "#000000",
        "text_sec":  "#3c3c43",
        "text_dim":  "#8e8e93",
        "border":    "#d1d1d6",
        "accent":    "#c07800",
        "track_off": "#e0e0e5",
        "btn":       "#e5e5ea",
        "btn_fg":    "#000000",
        "danger":    "#c0392b",
    }

def _hex(color):
    color = color.lstrip("#")
    return tuple(int(color[i:i + 2], 16) for i in (0, 2, 4))

def _toggle_image(on, colors):
    """Render the pill switch with PIL at 4x and downscale, so the edges
    are antialiased (Tk canvas ovals are not)."""
    scale = 4
    w, h = 44 * scale, 24 * scale
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    dc = ImageDraw.Draw(img)
    fill = _hex("#34c759") if on else _hex(colors["track_off"])
    dc.rounded_rectangle((0, 0, w - 1, h - 1), radius=h // 2, fill=fill + (255,))
    knob = h - 4 * scale
    x0 = (w - knob - 2 * scale) if on else (2 * scale)
    dc.ellipse((x0, 2 * scale, x0 + knob, 2 * scale + knob), fill=(255, 255, 255, 255))
    resample = getattr(Image, "Resampling", Image).LANCZOS
    return img.resize((44, 24), resample)

class _Toggle(tk.Label):
    """macOS-style pill switch, PIL-rendered for smooth edges."""
    def __init__(self, parent, on, on_toggle, colors):
        super().__init__(parent, bg=colors["bg"], cursor="hand2")
        self.on = on
        self.on_toggle = on_toggle
        self.colors = colors
        self._img_on  = ImageTk.PhotoImage(_toggle_image(True, colors))
        self._img_off = ImageTk.PhotoImage(_toggle_image(False, colors))
        self._show()
        self.bind("<Button-1>", lambda e: self.set(not self.on))

    def set(self, value):
        self.on = value
        self._show()
        self.on_toggle(value)

    def _show(self):
        self.configure(image=self._img_on if self.on else self._img_off)

def _settings_window():
    c = _settings_colors()

    # Flash fix: invisible root, never shown
    root = tk.Tk()
    root.geometry("0x0+0+0")
    root.attributes("-alpha", 0)
    root.withdraw()

    win = tk.Toplevel(root)
    win.title("PasteGuard Settings")
    win.geometry("480x460")
    win.resizable(False, False)
    win.attributes("-topmost", True)
    win.configure(bg=c["bg"])

    win.update_idletasks()
    x = (win.winfo_screenwidth()  // 2) - 240
    y = (win.winfo_screenheight() // 2) - 230
    win.geometry(f"+{x}+{y}")

    # Apply Windows 11 rounded corners
    win.update()
    hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
    if hwnd == 0:
        hwnd = win.winfo_id()
    apply_rounded_corners(hwnd)

    # Header
    header = tk.Frame(win, bg=c["bg"])
    header.pack(fill="x", padx=24, pady=(20, 0))
    tk.Label(header, text="Settings",
             font=("Segoe UI", 13, "bold"), fg=c["text_pri"], bg=c["bg"],
             anchor="w").pack(side="left")
    tk.Button(header, text="Close", command=win.destroy,
              font=("Segoe UI", 9), bg=c["btn"], fg=c["btn_fg"],
              activebackground=c["border"], activeforeground=c["btn_fg"],
              relief="flat", padx=14, pady=4, bd=0, cursor="hand2").pack(side="right")

    tk.Frame(win, height=1, bg=c["border"]).pack(fill="x", padx=24, pady=(14, 0))

    def section(title):
        tk.Label(win, text=title, font=("Segoe UI", 9), fg=c["text_dim"],
                 bg=c["bg"], anchor="w").pack(fill="x", padx=24, pady=(16, 4))

    def row(label, on, on_toggle):
        r = tk.Frame(win, bg=c["bg"])
        r.pack(fill="x", padx=24, pady=5)
        tk.Label(r, text=label, font=("Segoe UI", 10), fg=c["text_pri"],
                 bg=c["bg"], anchor="w").pack(side="left")
        _Toggle(r, on, on_toggle, c).pack(side="right")

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

    section("Behavior")
    row("Silent Mode", state["silent_mode"], set_silent)
    row("Notifications", state["notifications"], set_notifications)

    section("Startup")
    row("Start with Windows", startup_enabled(), set_startup)

    section("Stats")
    stats = tk.Frame(win, bg=c["bg"])
    stats.pack(fill="x", padx=24, pady=5)
    tk.Label(stats,
             text=f"Blocked: {state['stats']['blocked']}      Cleaned: {state['stats']['cleaned']}",
             font=("Segoe UI", 10), fg=c["text_sec"], bg=c["bg"],
             anchor="w").pack(side="left")

    tk.Frame(win, height=1, bg=c["border"]).pack(fill="x", padx=24, pady=(18, 0))

    footer = tk.Frame(win, bg=c["bg"])
    footer.pack(fill="x", padx=24, pady=(14, 20))
    tk.Button(footer, text="View Log", command=lambda: os.startfile(LOG_FILE),
              font=("Segoe UI", 9), bg=c["btn"], fg=c["btn_fg"],
              activebackground=c["border"], activeforeground=c["btn_fg"],
              relief="flat", padx=14, pady=5, bd=0, cursor="hand2").pack(side="left")
    tk.Button(footer, text="Quit App", command=lambda: on_quit(state["icon"], None),
              font=("Segoe UI", 9, "bold"), bg=c["danger"], fg="#ffffff",
              activebackground="#a93226", activeforeground="#ffffff",
              relief="flat", padx=14, pady=5, bd=0, cursor="hand2").pack(side="right")

    win.protocol("WM_DELETE_WINDOW", win.destroy)
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
