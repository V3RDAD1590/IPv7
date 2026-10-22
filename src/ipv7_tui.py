#!/usr/bin/env python3
"""ipv7_tui.py: the small terminal primitives shared by every router-look screen in this project
(key reading on Windows and POSIX, the redrawing screen, the white-highlight row style).

This file is deliberately generic: it knows nothing about bind, keys, tickets or any particular
menu's rows. `ipv7_menu.py` (the client's login and settings screen) and `ipv7_host_menu.py` (the
host operator's admin console) both build on this, but neither depends on the other, and this
module has no notion of what either of them shows.

No colour but the one highlight style (black on white), same as every other screen here.
"""
import os
import sys

MARK_STEP, MARK_OK, MARK_BAD = "|_", "*_", "-_"
EXIT_LINE = "......Program exits!"
SEL_ON, SEL_OFF = "\x1b[47m\x1b[30m", "\x1b[0m"      # black text on a white background
WIDTH = 66


# ---------------------------------------------------------------- keys
WIN_KEYS = {"H": "up", "P": "down", "K": "left", "M": "right", "S": "delete", "G": "home", "O": "end"}
POSIX_KEYS = {"A": "up", "B": "down", "D": "left", "C": "right"}


def map_char(c):
    if c in ("\r", "\n"):
        return "enter"
    if c == "\x1b":
        return "esc"
    if c in ("\x7f", "\x08"):
        return "backspace"
    if c == "\x03":
        raise KeyboardInterrupt
    return c if c.isprintable() else "other"


def decode_posix(seq):
    """Bytes read after ESC, such as '[A' or 'OB', -> key name. An empty sequence is a lone Esc."""
    if not seq:
        return "esc"
    if len(seq) >= 2 and seq[0] in "[O":
        return POSIX_KEYS.get(seq[1], "other")
    return "other"


class TtyRaw:
    """Keep a POSIX terminal in cbreak mode for the whole menu, so keys typed or pasted quickly are
    not lost between reads. Does nothing on Windows."""
    saved = None

    def __enter__(self):
        if os.name != "nt" and sys.stdin.isatty():
            import termios
            import tty
            fd = sys.stdin.fileno()
            TtyRaw.saved = (fd, termios.tcgetattr(fd))
            tty.setcbreak(fd)
        return self

    def __exit__(self, *a):
        if TtyRaw.saved:
            import termios
            fd, old = TtyRaw.saved
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
            TtyRaw.saved = None


def read_key():
    """One key from the real terminal."""
    if os.name == "nt":
        import msvcrt
        c = msvcrt.getwch()
        if c in ("\x00", "\xe0"):
            return WIN_KEYS.get(msvcrt.getwch(), "other")
        return map_char(c)
    import select
    import termios
    import tty
    fd = sys.stdin.fileno()
    held = TtyRaw.saved is not None
    old = None if held else termios.tcgetattr(fd)
    try:
        if not held:
            tty.setcbreak(fd)
        # read the raw descriptor: sys.stdin's buffer would swallow keys typed or pasted quickly
        c = os.read(fd, 1).decode("utf-8", "replace")
        if c == "\x1b":
            seq = ""
            while select.select([fd], [], [], 0.05)[0] and len(seq) < 2:
                seq += os.read(fd, 1).decode("utf-8", "replace")
            return decode_posix(seq)
        return map_char(c)
    finally:
        if not held:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def enable_vt():
    """Windows consoles need ANSI processing switched on. Harmless elsewhere."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False
        return bool(k.SetConsoleMode(h, mode.value | 0x0004))
    except Exception:
        return False


# ---------------------------------------------------------------- the console window's own icon
APP_ICON = "ipv7.ico"


def _icon_file(icon=None):
    """The .ico next to the program (a PyInstaller build has it embedded too, but a loose file
    works for `python ipv7_client.py` as well)."""
    if icon and os.path.isfile(icon):
        return icon
    base = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
    cand = os.path.join(base, APP_ICON)
    return cand if os.path.isfile(cand) else None


def console_icon(title=None, icon=None):
    """Windows only: give the console window THIS program's icon (title bar and taskbar
    button) and, when given, a title. -> True when the icon was set.

    A console program has no window of its own: the window belongs to the console host, so by
    default it shows conhost's or cmd.exe's icon, not the one PyInstaller embedded in the exe.
    Classic conhost honours WM_SETICON sent to that window, which is all this does: take the
    icon out of the exe's own resources (or ipv7.ico beside it), hand it to the window. Nothing
    is drawn, nothing changes about the console look. Windows Terminal ignores WM_SETICON (its
    icons are per profile) -- `install_terminal_profile` covers that side. Off Windows, or if
    anything is missing, this does nothing and says so with False."""
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes
        k32, u32, sh32 = ctypes.windll.kernel32, ctypes.windll.user32, ctypes.windll.shell32
        k32.GetConsoleWindow.restype = wintypes.HWND
        u32.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u32.SendMessageW.restype = ctypes.c_ssize_t
        u32.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT, ctypes.c_int, ctypes.c_int, wintypes.UINT]
        u32.LoadImageW.restype = wintypes.HANDLE
        sh32.ExtractIconExW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(wintypes.HICON),
                                        ctypes.POINTER(wintypes.HICON), wintypes.UINT]
        sh32.ExtractIconExW.restype = wintypes.UINT
        if title:
            try:
                k32.SetConsoleTitleW(title)
            except Exception:
                pass
        hwnd = k32.GetConsoleWindow()
        if not hwnd:
            return False
        big = small = None
        if getattr(sys, "frozen", False):                       # the exe's own embedded icon first
            hb, hs = wintypes.HICON(), wintypes.HICON()
            if sh32.ExtractIconExW(sys.executable, 0, ctypes.byref(hb), ctypes.byref(hs), 1) > 0:
                big, small = hb.value, hs.value
        if not big:
            ico = _icon_file(icon)
            if ico:
                IMAGE_ICON, LR_LOADFROMFILE = 1, 0x0010
                big = u32.LoadImageW(None, ico, IMAGE_ICON, 32, 32, LR_LOADFROMFILE)
                small = u32.LoadImageW(None, ico, IMAGE_ICON, 16, 16, LR_LOADFROMFILE)
        if not big:
            return False
        WM_SETICON, ICON_SMALL, ICON_BIG = 0x0080, 0, 1
        u32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, big)
        u32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, small or big)
        return True
    except Exception:
        return False


def relaunch_in_conhost(marker="IPV7_CONHOST"):
    """Windows, compiled builds only: when this process was given a ConPTY console (Windows
    Terminal -- the default host on Windows 11 -- or any other pseudo console), start the same
    exe again under the classic console host, `conhost.exe`, and tell the caller to exit 0 so
    the Terminal tab closes. The classic host honours `console_icon`; a Terminal tab never
    will. -> True when the relaunch was started (then return at once), False to just carry on.

    Detection: the fake window conhost gives a ConPTY session has the class name
    "PseudoConsoleWindow"; a real console window is "ConsoleWindowClass". The marker in the
    environment stops the relaunched copy from doing it again; IPV7_NO_CONHOST=1 turns the
    whole thing off (for running the exe inside a terminal on purpose). A `python x.py` run is
    never relaunched."""
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return False
    if os.environ.get(marker) or os.environ.get("IPV7_NO_CONHOST"):
        return False
    try:
        import ctypes
        import subprocess
        from ctypes import wintypes
        k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
        k32.GetConsoleWindow.restype = wintypes.HWND
        hwnd = k32.GetConsoleWindow()
        if not hwnd:
            return False
        buf = ctypes.create_unicode_buffer(64)
        u32.GetClassNameW(hwnd, buf, 64)
        if buf.value != "PseudoConsoleWindow":
            return False                                       # classic conhost already
        conhost = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "conhost.exe")
        if not os.path.isfile(conhost):
            return False
        # a one-off token in this window's title: the relaunched copy finds the Terminal window
        # by it and closes it once this copy has exited (close_handoff_window)
        token = "IPv7-%08x" % int.from_bytes(os.urandom(4), "big")
        try:
            k32.SetConsoleTitleW("IPv7 " + token)
        except Exception:
            pass
        env = child_env(os.environ)
        env[marker] = token
        env[marker + "_PARENT"] = str(os.getpid())
        DETACHED_PROCESS = 0x00000008                          # no console of its own: conhost makes the window
        subprocess.Popen([conhost, sys.executable] + sys.argv[1:], env=env, cwd=os.getcwd(),
                         creationflags=DETACHED_PROCESS, close_fds=True)
        return True
    except Exception:
        return False


def child_env(environ):
    """The environment for a copy of this exe started by this exe: everything, minus the
    bookkeeping PyInstaller's bootloader leaves for ITS child (`_MEIPASS2`, `_PYI_*`). Passed
    on, those made the relaunched copy run out of the FIRST copy's extracted temp folder
    instead of unpacking its own -- and when the first copy exited and deleted that folder,
    the next lazy import (pysequoia, right after the host setup form) found nothing:
    "No module named pysequoia.pysequoia"."""
    return {k: v for k, v in environ.items() if k != "_MEIPASS2" and not k.startswith("_PYI_")}


def close_handoff_window(marker="IPV7_CONHOST", wait_ms=4000):
    """The relaunched copy's half of `relaunch_in_conhost`: the Terminal window the first copy
    was handed to is supposed to close by itself when that copy exits (Terminal's own rule for
    handed-off processes), and on the real machine it did not. So: wait for the first copy to
    be gone (its pid travels in the environment), then find the Windows Terminal window whose
    title carries the token the first copy set, and ask it to close. Only a window with that
    exact token in its title is touched; a Terminal window holding other tabs as well would
    show its own "close all tabs?" question rather than lose them. -> True when a close was
    sent. Does nothing without the token (a plain run, or off Windows)."""
    token = os.environ.get(marker)
    if os.name != "nt" or not token or not token.startswith("IPv7-"):
        return False
    try:
        import ctypes
        from ctypes import wintypes
        k32, u32 = ctypes.windll.kernel32, ctypes.windll.user32
        try:                                                   # let the first copy finish its own exit first
            pid = int(os.environ.get(marker + "_PARENT", "0"))
            if pid:
                SYNCHRONIZE = 0x00100000
                h = k32.OpenProcess(SYNCHRONIZE, False, pid)
                if h:
                    k32.WaitForSingleObject(h, wait_ms)
                    k32.CloseHandle(h)
        except Exception:
            pass
        WM_CLOSE = 0x0010
        found = []
        EnumProc = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

        def each(hwnd, _):
            cls = ctypes.create_unicode_buffer(64)
            u32.GetClassNameW(hwnd, cls, 64)
            if cls.value == "CASCADIA_HOSTING_WINDOW_CLASS":
                n = u32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(n + 1)
                u32.GetWindowTextW(hwnd, buf, n + 1)
                if token in buf.value:
                    found.append(hwnd)
            return True
        u32.EnumWindows(EnumProc(each), 0)
        for hwnd in found:
            u32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
        return bool(found)
    except Exception:
        return False


def terminal_fragment(profiles):
    """The Windows Terminal fragment (a settings extension, one JSON file) that gives each exe
    its own profile: a name, the icon, its folder as the starting directory. `profiles` is a
    list of (name, exe path, icon path or None)."""
    import ntpath                                               # Windows paths, whatever this runs on
    out = []
    for name, exe, icon in profiles:
        prof = {"name": name, "commandline": exe, "startingDirectory": ntpath.dirname(exe)}
        if icon:
            prof["icon"] = icon
        out.append(prof)
    return {"profiles": out}


def terminal_fragment_path(root=None):
    """%LOCALAPPDATA%\\Microsoft\\Windows Terminal\\Fragments\\IPv7\\ipv7.json -- where Windows Terminal
    (Store and unpackaged alike) looks for fragments from other programs."""
    root = root or os.environ.get("LOCALAPPDATA")
    if not root:
        return None
    return os.path.join(root, "Microsoft", "Windows Terminal", "Fragments", "IPv7", "ipv7.json")


def install_terminal_profile(name, exe=None, icon=None, root=None, force=False):
    """Best effort, idempotent: write (or refresh) the Windows Terminal fragment for this
    program, so a tab opened from Terminal's menu -- and, when Terminal is the default console
    and it matches the started exe to a profile, a double-clicked build too -- carries IPv7's
    own name and icon instead of the Terminal's. -> "written", "unchanged", or None when it is
    not applicable (not Windows, no LOCALAPPDATA) or could not be written. Nothing else in
    Terminal's settings is touched; deleting the one file undoes it."""
    if os.name != "nt" and root is None and not force:
        return None
    import json
    exe = exe or (sys.executable if getattr(sys, "frozen", False) else None)
    if not exe:
        return None
    path = terminal_fragment_path(root)
    if not path:
        return None
    frag = terminal_fragment([(name, os.path.abspath(exe), _icon_file(icon))])
    text = json.dumps(frag, indent=2)
    try:
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                if f.read() == text:
                    return "unchanged"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return "written"
    except OSError:
        return None


def clear_screen(out=None):
    """A full terminal clear, not the incremental redraw `Screen` does. `Screen` only ever erases
    the lines IT has itself drawn (its own `prev` count) -- it has no way to know about, and so
    can never clear, whatever was printed to the terminal before it existed. A host (fingerprint,
    "waiting for binds ...") or a client (password prompt, "Incorrect.") both print plain `say()`
    lines like that before their first `Screen` is ever constructed, so without a real clear here,
    the admin console's or the login menu's very first `draw()` just prints its own lines below
    that leftover text forever, since its fresh `Screen(prev=0)` has nothing of its own to erase
    yet. Call this once, right before handing control to a `Screen`-driven menu, not between that
    menu's own screens -- `Screen.reset()` already does that part."""
    enable_vt()
    w = out.write if out is not None else sys.stdout.write
    w("\x1b[2J\x1b[H")
    if out is not None and hasattr(out, "flush"):
        out.flush()
    elif out is None:
        sys.stdout.flush()


def confirm_exit(out=None, keys=None):
    """What Ctrl-C does everywhere in this project now, instead of killing the program on the
    spot: ask. 'Exit? (y/n)' -> True to exit, False to carry on with whatever was running (the
    menu redraws, the Command: prompt comes back, a login starts over). Reads single keys, so it
    works the same inside a router-look menu, at a plain prompt and in the middle of a bind.
    Enter and Esc count as no, so a reflex Ctrl-C costs nothing; a second Ctrl-C at the question
    counts as yes, so two of them in a row still get someone out in a hurry."""
    out = out or sys.stdout
    keys = keys or read_key
    out.write("\nExit? (y/n) ")
    if hasattr(out, "flush"):
        out.flush()
    while True:
        try:
            k = keys()
        except KeyboardInterrupt:
            k = "y"
        if k in ("y", "Y"):
            out.write("y\n")
            if hasattr(out, "flush"):
                out.flush()
            return True
        if k in ("n", "N", "esc", "enter"):
            out.write("n\n")
            if hasattr(out, "flush"):
                out.flush()
            return False


def report_crash(e, out=None, pause=None):
    """The last line of defence in both entry points: an unexpected exception becomes one
    readable line (type and message, no traceback -- there is nothing a person at this screen can
    do with one), then `......Program exits!`. At a real terminal it then waits for Enter, so a
    double-clicked build does not vanish with its only explanation. -> 1, the exit code."""
    out = out or sys.stdout
    out.write("%sunexpected error: %s: %s\n" % (MARK_BAD, type(e).__name__, e))
    out.write(EXIT_LINE + "\n")
    if hasattr(out, "flush"):
        out.flush()
    if pause is None:
        pause = sys.stdin.isatty() if hasattr(sys.stdin, "isatty") else False
    if pause:
        try:
            input("Enter to close.")
        except (EOFError, KeyboardInterrupt):
            pass
    return 1


# ---------------------------------------------------------------- the screen
class Screen:
    """Draws a block of lines, clearing the WHOLE terminal first every time (the same full
    `\\x1b[2J\\x1b[H` as `clear_screen()` above, not an incremental cursor-up-and-erase-below).
    Each line is (text, style), where style is '' (plain), 'sel' (the highlighted row, black on
    white) or 'dim' (not available now).

    This used to track only its own previously drawn line count (`prev`) and move the cursor up
    by exactly that many lines before erasing -- correct in theory, but fragile in practice in
    two ways real runs kept finding: it only ever knew about lines THIS `Screen` had itself
    printed, so anything else printed to the same terminal in between two draws (the host
    console's own `say()`/`_note()` activity lines -- "revoked an invite", a bind, a kick -- each
    print directly, outside of whatever screen happens to be showing) just sat there forever,
    never erased by a redraw that had no idea it existed; and it meant every caller had to get the
    handoff between one `Screen` and the next exactly right (section 30's whole bug was `reset()`
    not doing its half of that). A full clear before every single `draw()` sidesteps both: it wipes
    the entire terminal regardless of who printed what since the last one, so there is no
    leftover-text case left to get wrong. The trade-off is a touch more flicker on some terminals,
    which does not matter for a screen that only ever redraws after a keypress."""

    def __init__(self, out, ansi=True):
        self.out, self.ansi, self.prev = out, ansi, 0

    def draw(self, lines):
        w = self.out.write
        if self.ansi:
            w("\x1b[2J\x1b[H")
        for text, style in lines:
            if style == "sel" and self.ansi:
                w(SEL_ON + text.ljust(WIDTH) + SEL_OFF + "\n")
            elif style == "sel":
                w("> " + text + "\n")
            elif style == "dim":
                w("  " + text + "\n")
            else:
                w(("" if self.ansi else "  ") + text + "\n")
        self.prev = len(lines)
        if hasattr(self.out, "flush"):
            self.out.flush()

    def reset(self):
        """Clear the whole terminal and forget what this screen last drew. Leaving one screen for
        another (a sub-prompt returning to its menu, or one console screen to the next) used to
        just print the new screen's lines below whatever was already there, because the next
        `draw()` had no drawn-line count of its own to move up and clear -- that was section 30's
        bug. A full clear here (the same one `draw()` itself now does every time) means the
        screen that follows starts from nothing regardless, whether or not its own first `draw()`
        call remembers to clear too."""
        if self.ansi:
            self.out.write("\x1b[2J\x1b[H")
            if hasattr(self.out, "flush"):
                self.out.flush()
        self.prev = 0


def row(label, value):
    """A line in the ipconfig style: 'Host . . . . . . . . : value'."""
    return "   %s : %s" % ((label + " " + ". " * 40)[:32].rstrip().ljust(32), value)


# ---------------------------------------------------------------- selftest
def selftest():
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    check("Windows and POSIX arrow keys decode", WIN_KEYS["H"] == "up" and WIN_KEYS["P"] == "down"
          and decode_posix("[A") == "up" and decode_posix("[B") == "down" and decode_posix("OC") == "right"
          and decode_posix("[D") == "left" and decode_posix("") == "esc" and decode_posix("[Z") == "other")
    check("characters map to keys", map_char("\r") == "enter" and map_char("\x1b") == "esc"
          and map_char("\x7f") == "backspace" and map_char("a") == "a" and map_char("\x01") == "other")
    try:
        map_char("\x03")
        check("Ctrl-C raises KeyboardInterrupt", False)
    except KeyboardInterrupt:
        check("Ctrl-C raises KeyboardInterrupt", True)
    check("row() lays out the ipconfig-style dots", row("Host", "x").startswith("   Host ") and row("Host", "x").endswith(": x"))
    import io
    out = io.StringIO()
    s = Screen(out)
    s.draw([("a", ""), ("b", "sel")])
    text = out.getvalue()
    check("Screen highlights exactly the 'sel' line, padded to WIDTH", SEL_ON + "b".ljust(WIDTH) + SEL_OFF + "\n" in text
          and SEL_ON not in text.split("\n")[0])
    out2 = io.StringIO()
    s2 = Screen(out2, ansi=False)
    s2.draw([("a", ""), ("b", "sel")])
    check("without ANSI the selection is '> ' instead", "> b\n" in out2.getvalue() and SEL_ON not in out2.getvalue())
    before_c = len(out.getvalue())
    s.draw([("c", "")])
    check("a second draw clears the whole screen first, not just the cursor up by the old line "
          "count -- this is what stops anything printed outside Screen in between (a host's own "
          "activity line) from ever surviving the next redraw",
          out.getvalue()[before_c:].startswith("\x1b[2J\x1b[H"))

    out3 = io.StringIO()
    s3 = Screen(out3)
    s3.draw([("a", ""), ("b", "sel")])
    before = len(out3.getvalue())
    s3.reset()
    check("reset() clears the whole screen too, then forgets what it drew",
          out3.getvalue()[before:] == "\x1b[2J\x1b[H")
    after = len(out3.getvalue())
    s3.draw([("d", "")])
    check("the next draw() after reset() clears again and starts fresh",
          out3.getvalue()[after:].startswith("\x1b[2J\x1b[H"))

    def drive_confirm(keys):
        it = iter(keys)
        o = io.StringIO()
        return confirm_exit(out=o, keys=lambda: next(it)), o.getvalue()
    yes, text = drive_confirm(["y"])
    check("confirm_exit asks 'Exit? (y/n)' and y means exit", yes is True and "Exit? (y/n)" in text)
    check("n, Esc and Enter all mean stay", drive_confirm(["n"])[0] is False and drive_confirm(["esc"])[0] is False
          and drive_confirm(["enter"])[0] is False)
    check("any other key is ignored until an answer comes", drive_confirm(["x", "up", "N"])[0] is False)

    def ctrl_c_again():
        raise KeyboardInterrupt
    o = io.StringIO()
    check("a second Ctrl-C at the question counts as yes", confirm_exit(out=o, keys=ctrl_c_again) is True)
    o = io.StringIO()
    rc = report_crash(ValueError("boom"), out=o, pause=False)
    check("report_crash prints one readable line and the exit line, no traceback, and returns 1",
          rc == 1 and "unexpected error: ValueError: boom" in o.getvalue() and EXIT_LINE in o.getvalue()
          and "Traceback" not in o.getvalue())

    # -- the console icon and the Windows Terminal fragment
    check("console_icon() off Windows does nothing and returns False, no exception",
          (console_icon("x") is False) if os.name != "nt" else True)
    check("relaunch_in_conhost() never fires for a plain python run (or off Windows)", relaunch_in_conhost() is False)
    check("close_handoff_window() does nothing without the relaunch token", close_handoff_window() is False)
    ce = child_env({"PATH": "p", "_MEIPASS2": "C:\\Temp\\_MEI1", "_PYI_ARCHIVE_FILE": "x", "_PYI_PARENT_PROCESS_LEVEL": "1", "HOME": "h"})
    check("child_env strips PyInstaller's bootloader variables and keeps the rest",
          ce == {"PATH": "p", "HOME": "h"})
    import json as _json
    import tempfile as _tf
    frag = terminal_fragment([("IPv7 Client", r"C:\\x\\IPv7Client.exe", r"C:\\x\\ipv7.ico"), ("IPv7 Host", r"C:\\x\\IPv7Host.exe", None)])
    check("terminal_fragment lists one profile per exe with its name, commandline, folder and icon",
          len(frag["profiles"]) == 2 and frag["profiles"][0]["icon"].endswith("ipv7.ico")
          and frag["profiles"][0]["commandline"].endswith("IPv7Client.exe") and "icon" not in frag["profiles"][1]
          and frag["profiles"][1]["startingDirectory"] == r"C:\\x")
    with _tf.TemporaryDirectory() as d:
        r1 = install_terminal_profile("IPv7 Client", exe=os.path.join(d, "IPv7Client.exe"), root=d)
        p = terminal_fragment_path(d)
        with open(p, encoding="utf-8") as f:
            written = _json.load(f)
        r2 = install_terminal_profile("IPv7 Client", exe=os.path.join(d, "IPv7Client.exe"), root=d)
        check("install_terminal_profile writes Fragments\\IPv7\\ipv7.json under the given root, valid JSON, and is idempotent",
              r1 == "written" and r2 == "unchanged" and written["profiles"][0]["name"] == "IPv7 Client"
              and p.endswith(os.path.join("Microsoft", "Windows Terminal", "Fragments", "IPv7", "ipv7.json")))
    check("install_terminal_profile with nothing to point at returns None",
          install_terminal_profile("IPv7", exe=None, root="/nonexistent") is None)

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


def main():
    import sys as _sys
    return selftest() if "--selftest" in _sys.argv else (print(__doc__) or 0)


if __name__ == "__main__":
    sys.exit(main())
