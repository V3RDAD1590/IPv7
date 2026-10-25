#!/usr/bin/env python3
"""ipv7_menu.py: the startup login and configuration menu (router look).

    python ipv7_menu.py --demo        try the menu with sample adapters (nothing is connected)
    python ipv7_menu.py               the menu with the real adapters Npcap finds
    python ipv7_menu.py --selftest    scripted-key checks, no terminal needed

Keys: Up and Down move the highlighted row (black text on a white background), Enter changes
the row, Left and Right step through the choices of a row, Esc leaves a prompt or exits.
Nothing secret is stored: the settings file `IPv7.conf` holds the host address, the path to the
invite file, the Ethernet device name, the EtherType and the link-address policy. The invite
(the ticket) stays in `IPv7.key`, and a passphrase is never asked for or written.

The menu only collects settings. It opens no socket and sends nothing.
The terminal mechanics (key reading, the redrawing screen, the white-highlight row) live in
`ipv7_tui.py`, shared with the host operator's own, separate admin console (`ipv7_host_menu.py`);
this file still knows nothing about that one, and still names nothing to do with logging.
This is an unaudited prototype: it should not protect anyone whose safety depends on it.
"""
import ipaddress
import os
import re
import sys

from ipv7_tui import (MARK_STEP, MARK_OK, MARK_BAD, EXIT_LINE, SEL_ON, SEL_OFF, WIDTH,
                       WIN_KEYS, POSIX_KEYS, map_char, decode_posix, TtyRaw, read_key, enable_vt,
                       Screen, row)

DEFAULT_PORT = 7171
CONF = "IPv7.conf"

PATHS = ("UDP only", "UDP, then Ethernet")
ETHERTYPES = ("0x88B6 (default)", "0x88B5", "custom")
LINKS = ("random", "real adapter address", "custom")


# ---------------------------------------------------------------- settings
class Settings:
    def __init__(self):
        self.host = ""
        self.invite = "IPv7.key"
        self.paths = 0                      # index in PATHS
        self.device = ""                    # Npcap device name
        self.ethertype = 0                  # index in ETHERTYPES
        self.custom_ethertype = ""
        self.link = 0                       # index in LINKS
        self.custom_link = ""
        self.automove = False               # move to Ethernet right after login (O39)
        self.bind = ""                      # host only: the address it answers from ("" = any)

    FIELDS = ("host", "invite", "paths", "device", "ethertype", "custom_ethertype", "link",
              "custom_link", "automove", "bind")

    def dump(self):
        return "".join("%s %s\n" % (k, int(v) if isinstance(v, bool) else v)
                       for k in self.FIELDS for v in [getattr(self, k)])

    def load(self, text):
        for line in text.splitlines():
            k, _, v = line.partition(" ")
            if k not in self.FIELDS:
                continue
            cur = getattr(self, k)
            try:
                if isinstance(cur, bool):
                    setattr(self, k, v.strip() == "1")
                elif isinstance(cur, int):
                    setattr(self, k, int(v))
                else:
                    setattr(self, k, v.strip())
            except ValueError:
                pass
        self.paths %= len(PATHS)
        self.ethertype %= len(ETHERTYPES)
        self.link %= len(LINKS)

    def ethertype_value(self):
        import ipv7_ether as E
        if self.ethertype == 0:
            return E.DEFAULT_ETHERTYPE
        if self.ethertype == 1:
            return 0x88B5
        return E.parse_ethertype(self.custom_ethertype)


def load_settings(path=CONF):
    s = Settings()
    try:
        with open(path, encoding="utf-8") as f:
            s.load(f.read())
    except OSError:
        pass
    return s


def save_settings(s, path=CONF):
    with open(path, "w", encoding="utf-8") as f:
        f.write(s.dump())


def parse_host(text):
    """'host', 'host:port', '1.2.3.4:7171' or '[2001:db8::1]:7171' -> (host, port) or None."""
    t = text.strip()
    if not t:
        return None
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::(\d{1,5}))?", t)
    if m:
        host, port = m.group(1), m.group(2)
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return None
    else:
        host, _, port = t.partition(":") if t.count(":") <= 1 else (None, None, None)
        if host is None:
            return None
        if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", host):
            return None
    if port and not port.isdigit():
        return None
    p = int(port) if port else DEFAULT_PORT
    if not 1 <= p <= 65535:
        return None
    return host, p


def host_text(h):
    host, port = h
    return ("[%s]:%d" if ":" in host else "%s:%d") % (host, port)


# ---------------------------------------------------------------- the menu
class Menu:
    """Rows are indexed in `self.items`. `devices` is a list of (name, description, mac bytes or
    None). `npcap` says whether Npcap was found. `keys` returns the next key name."""

    def __init__(self, settings, devices, npcap, keys, out, ansi=True, saver=None):
        self.s, self.devices, self.npcap = settings, devices, npcap
        self.keys, self.out, self.saver = keys, out, saver
        self.screen = Screen(out, ansi)
        self.pos = 0
        self.msg = ""
        self.items = ["host", "invite", "paths", "device", "ethertype", "link", "automove",
                      "connect", "exit"]

    # -- text of a row
    def usable_devices(self):
        return [d for d in self.devices if d[2] and "loopback" not in d[0].lower()]

    def device_text(self):
        for name, desc, mac in self.devices:
            if name == self.s.device:
                return "%s  %s" % (desc, ":".join("%02X" % x for x in mac) if mac else "no address")
        return "(none chosen)" if self.s.device == "" else "(not found: re-select)"

    def eth_on(self):
        return self.s.paths == 1

    def lines(self):
        s = self.s
        h = parse_host(s.host)
        inv = "found" if os.path.isfile(s.invite) else "not found"
        et = ETHERTYPES[s.ethertype] if s.ethertype != 2 else "custom %s" % (s.custom_ethertype or "(not set)")
        lk = LINKS[s.link] if s.link != 2 else "custom %s" % (s.custom_link or "(not set)")
        rows = {
            "host": row("Host", host_text(h) if h else "(not set)"),
            "invite": row("Invite file", "%s  (%s)" % (s.invite, inv)),
            "paths": row("Paths", PATHS[s.paths]),
            "device": row("Ethernet device", self.device_text()),
            "ethertype": row("EtherType", et),
            "link": row("Link address", lk),
            "automove": row("Move to Ethernet after login", "yes" if s.automove else "no"),
            "connect": "   Connect",
            "exit": "   Exit",
        }
        out = [("IPv7 SETUP        Up/Down move   Enter change   Left/Right step   Esc exit", ""), ("", "")]
        for i, k in enumerate(self.items):
            if k == "connect":
                out.append(("", ""))
            text = rows[k]
            if k in ("device", "ethertype", "link", "automove") and not self.eth_on():
                text += "  (off)"
            out.append((text, "sel" if i == self.pos else ""))
        out.append(("", ""))
        out.append((self.msg, ""))
        return out

    def draw(self):
        self.screen.draw(self.lines())

    def say(self, mark, text):
        self.msg = "%s%s" % (mark, text) if text else ""

    # -- editing
    def edit_text(self, title, current, validate):
        """Inline prompt. -> new text, or None when cancelled. validate(text) -> '' or an error."""
        buf = current
        while True:
            self.screen.draw([(title, ""), ("   > " + buf + "_", "sel"), ("", ""), (self.msg, "")])
            k = self.keys()
            if k == "enter":
                err = validate(buf)
                if err:
                    self.say(MARK_BAD, err)
                    continue
                self.say("", "")
                self.screen.reset()
                return buf
            if k == "esc":
                self.say("", "")
                self.screen.reset()
                return None
            if k == "backspace":
                buf = buf[:-1]
            elif len(k) == 1:
                buf += k

    def pick(self, title, labels, start=0):
        """List with a highlighted row. -> index, or None when cancelled."""
        i = start
        while True:
            lines = [(title, ""), ("", "")] + [("   " + t, "sel" if j == i else "") for j, t in enumerate(labels)]
            self.screen.draw(lines)
            k = self.keys()
            if k == "up":
                i = (i - 1) % len(labels)
            elif k == "down":
                i = (i + 1) % len(labels)
            elif k == "enter":
                self.screen.reset()
                return i
            elif k == "esc":
                self.screen.reset()
                return None

    # -- row actions
    def step(self, key, direction):
        s = self.s
        if key == "paths":
            new = (s.paths + direction) % len(PATHS)
            if new == 1 and not self.npcap:
                self.say(MARK_BAD, "Npcap was not found: install it from npcap.com. UDP only for now.")
                return
            s.paths = new
            self.say("", "")
        elif key == "ethertype":
            s.ethertype = (s.ethertype + direction) % len(ETHERTYPES)
            if s.ethertype == 2 and not s.custom_ethertype:
                self.change(key)
            elif s.ethertype == 1:
                self.say(MARK_STEP, "0x88B5 is also used by XTTP")
            else:
                self.say("", "")
        elif key == "link":
            s.link = (s.link + direction) % len(LINKS)
            if s.link == 2 and not s.custom_link:
                self.change(key)
            elif s.link == 1:
                self.say(MARK_STEP, "Wi-Fi needs the real address; wired and virtual links can use a random one")
            else:
                self.say("", "")
        elif key == "automove":
            s.automove = not s.automove
            self.say("", "")

    def change(self, key):
        import ipv7_ether as E
        s = self.s
        if key == "host":
            def v(t):
                return "" if parse_host(t) else "a host looks like 192.0.2.1:7171 or [2001:db8::1]:7171"
            r = self.edit_text("Host address (port %d if left out)" % DEFAULT_PORT, s.host, v)
            if r is not None:
                s.host = host_text(parse_host(r))
        elif key == "invite":
            r = self.edit_text("Invite file", s.invite, lambda t: "" if t.strip() else "a file name is needed")
            if r is not None:
                s.invite = r.strip()
        elif key == "device":
            if not self.eth_on():
                self.say(MARK_STEP, "Paths is UDP only: the Ethernet rows are off")
                return
            devs = self.usable_devices()
            if not devs:
                self.say(MARK_BAD, "No Ethernet adapter with a link address was found")
                return
            labels = ["%s  %s" % (d[1], ":".join("%02X" % x for x in d[2])) for d in devs]
            cur = next((i for i, d in enumerate(devs) if d[0] == s.device), 0)
            i = self.pick("Ethernet device (adapters without a link address are hidden)", labels, cur)
            if i is not None:
                s.device = devs[i][0]
                self.say("", "")
        elif key == "ethertype":
            def v(t):
                try:
                    E.parse_ethertype(t)
                    return ""
                except E.CarrierError as e:
                    return str(e)
            r = self.edit_text("EtherType in hex, such as 0x9000 (not 0x0800 or other well-known types)",
                               s.custom_ethertype, v)
            if r is not None:
                s.ethertype, s.custom_ethertype = 2, r
                note = E.check_ethertype(E.parse_ethertype(r))[1]
                self.say(MARK_STEP if note else "", note)
        elif key == "link":
            def v(t):
                try:
                    E.link_address(t)
                    return ""
                except E.CarrierError as e:
                    return str(e)
            r = self.edit_text("Link address, such as 02:00:5E:10:20:30 (unicast only)", s.custom_link, v)
            if r is not None:
                s.link, s.custom_link = 2, r
                self.say("", "")
        else:
            self.step(key, 1)

    def check_ready(self):
        """-> '' when Connect may go ahead, else the reason."""
        s = self.s
        if not parse_host(s.host):
            return "the host is not set"
        if self.eth_on():
            if not self.npcap:
                return "Npcap was not found"
            if not any(d[0] == s.device for d in self.usable_devices()):
                return "no Ethernet device is chosen"
            if s.ethertype == 2:
                try:
                    s.ethertype_value()
                except Exception as e:
                    return str(e)
            if s.link == 1 and not next(d for d in self.devices if d[0] == s.device)[2]:
                return "that adapter has no real link address"
            if s.link == 2:
                import ipv7_ether as E
                try:
                    E.link_address(s.custom_link)
                except E.CarrierError as e:
                    return str(e)
        return ""

    def run(self):
        """-> the Settings when the user picks Connect, or None for Exit or Esc."""
        while True:
            self.draw()
            k = self.keys()
            key = self.items[self.pos]
            if k == "up":
                self.pos = (self.pos - 1) % len(self.items)
            elif k == "down":
                self.pos = (self.pos + 1) % len(self.items)
            elif k in ("left", "right") and key in ("paths", "ethertype", "link", "automove"):
                if not self.eth_on() and key != "paths":
                    self.say(MARK_STEP, "Paths is UDP only: the Ethernet rows are off")
                else:
                    self.step(key, 1 if k == "right" else -1)
            elif k == "enter":
                if key == "exit":
                    self.screen.reset()
                    return None
                if key == "connect":
                    why = self.check_ready()
                    if why:
                        self.say(MARK_BAD, why)
                        continue
                    if self.saver:
                        self.saver(self.s)
                    self.screen.reset()
                    return self.s
                if key in ("ethertype", "link", "automove") and not self.eth_on():
                    self.say(MARK_STEP, "Paths is UDP only: the Ethernet rows are off")
                    continue
                if key in ("paths", "automove"):
                    self.step(key, 1)
                else:
                    self.change(key)
            elif k == "esc":
                self.screen.reset()
                return None


def run_menu(settings, devices, npcap, keys=read_key, out=None, ansi=True, saver=None):
    out = out or sys.stdout
    return Menu(settings, devices, npcap, keys, out, ansi, saver).run()


def find_devices():
    """-> (devices, npcap found). devices = [(name, description, mac or None)]."""
    import ipv7_ether as E
    try:
        raw = E.pcap_devices()
    except (E.NpcapMissing, E.CarrierError):
        return [], False
    return [(n, d, E.adapter_mac(n)) for n, d in raw], True


SAMPLE_DEVICES = [
    ("\\Device\\NPF_{11111111-0000-0000-0000-000000000001}", "WAN Miniport (IP)", None),
    ("\\Device\\NPF_{11111111-0000-0000-0000-000000000002}", "Sample Wi-Fi adapter",
     bytes.fromhex("02005e102030")),
    ("\\Device\\NPF_{11111111-0000-0000-0000-000000000003}", "Sample wired adapter",
     bytes.fromhex("02005e102031")),
    ("\\Device\\NPF_Loopback", "Adapter for loopback traffic capture", None),
]


# ---------------------------------------------------------------- selftest
def selftest():
    import io
    import tempfile
    import ipv7_ether as E
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    def drive(keys, settings=None, devices=SAMPLE_DEVICES, npcap=True, saver=None, ansi=True):
        ks = iter(keys)
        out = io.StringIO()
        s = settings or Settings()
        try:
            r = run_menu(s, devices, npcap, keys=lambda: next(ks), out=out, ansi=ansi, saver=saver)
        except StopIteration:
            r = "ran out of keys"
        return r, s, out.getvalue()

    def typed(text):
        return list(text)

    D, U, E_, X = "down", "up", "enter", "esc"
    check("parse_host: v4, v6, name, default port",
          parse_host("192.0.2.1:7171") == ("192.0.2.1", 7171) and parse_host("[2001:db8::1]:9") == ("2001:db8::1", 9)
          and parse_host("example.org") == ("example.org", DEFAULT_PORT) and parse_host("[2001:db8::1]") == ("2001:db8::1", DEFAULT_PORT))
    check("parse_host refuses junk, bad ports and bare IPv6",
          all(parse_host(t) is None for t in ("", "a b", "host:0", "host:70000", "host:x", "2001:db8::1", "[nope]:1", "[2001:db8::1", "-bad:5")))
    check("host_text brackets IPv6", host_text(("2001:db8::1", 7171)) == "[2001:db8::1]:7171" and host_text(("a.b", 5)) == "a.b:5")

    # --- keys
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

    # --- rendering
    r, s, out = drive([X])
    check("Esc exits with None", r is None)
    first = out.split("\n")
    sel_lines = [l for l in first if SEL_ON in l]
    check("exactly one row is highlighted, black on white", len(sel_lines) == 1 and "Host" in sel_lines[0]
          and sel_lines[0].endswith(SEL_OFF))
    check("the highlighted row is padded to a full bar", len(sel_lines[0]) - len(SEL_ON) - len(SEL_OFF) == WIDTH)
    r, s, out = drive([D, X])
    check("Down moves the highlight to the next row", "Invite" in [l for l in out.split("\n") if SEL_ON in l][-1])
    r, s, out = drive([U, X])
    check("Up from the first row wraps to Exit", "Exit" in [l for l in out.split("\n") if SEL_ON in l][-1])
    check("each redraw clears the whole screen first (section 33: no leftovers from anything printed in between)",
          out.count("\x1b[2J\x1b[H") >= 2)
    r, s, out = drive([X], ansi=False)
    check("without ANSI the selection is marked with '> '", any(l.startswith("> ") and "Host" in l for l in out.split("\n")))
    check("no colour anywhere but the white highlight bar",
          set(re.findall(r"\x1b\[[0-9;]*m", out + drive([D, D, X])[2])) <= {"\x1b[47m", "\x1b[30m", "\x1b[0m"})

    # --- host entry
    r, s, out = drive([E_] + typed("192.0.2.1") + [E_, X])
    check("typing a host sets it, port added", s.host == "192.0.2.1:7171")
    r, s, out = drive([E_] + typed("bad host") + [E_, X])
    check("a bad host is refused with a message and the prompt stays", s.host == "" and "a host looks like" in out)
    r, s, out = drive([E_] + typed("x") + ["backspace"] + typed("[2001:db8::7]:8000") + [E_, X])
    check("backspace edits the entry", s.host == "[2001:db8::7]:8000")
    r, s, out = drive([E_] + typed("junk") + [X, X])
    check("Esc in the prompt leaves the old value", s.host == "")

    # --- paths, Ethernet rows off until Paths is changed
    r, s, out = drive([D, D, "right", X])
    check("Right on Paths turns Ethernet on", s.paths == 1)
    r, s, out = drive([D, D, "left", X])
    check("Left wraps back", s.paths == 1)
    r, s, out = drive([D, D, E_, E_, X])
    check("Enter cycles Paths", s.paths == 0)
    r, s, out = drive([D, D, D, E_, X])
    check("Ethernet rows are refused while Paths is UDP only", s.device == "" and "Ethernet rows are off" in out)
    r, s, out = drive([D, D, "right", X], npcap=False)
    check("without Npcap, Paths stays UDP only with a clear message", s.paths == 0 and "Npcap was not found" in out)

    # --- device pick
    r, s, out = drive([D, D, "right", D, E_, D, E_, X])
    check("the device list hides adapters without an address and the loopback",
          "WAN Miniport" not in out.split("Ethernet device (adapters")[-1] and "loopback" not in out.split("Ethernet device (adapters")[-1].lower()
          and "Sample Wi-Fi adapter" in out)
    check("choosing a device stores its Npcap name", s.device == SAMPLE_DEVICES[2][0])
    r, s, out = drive([D, D, "right", D, E_, X, X])
    check("Esc in the device list changes nothing", s.device == "")

    # --- EtherType
    r, s, out = drive([D, D, "right", D, D, "right", X])
    check("Right on EtherType: default to 0x88B5 with the XTTP note", s.ethertype == 1 and "XTTP" in out)
    r, s, out = drive([D, D, "right", D, D, "right", "right"] + typed("9000") + [E_, X])
    check("the custom choice asks for a number and keeps it", s.ethertype == 2 and s.custom_ethertype == "9000" and s.ethertype_value() == 0x9000)
    r, s, out = drive([D, D, "right", D, D, "right", "right"] + typed("0800") + [E_, X, X])
    check("a well-known EtherType is refused in the prompt", s.custom_ethertype == "" and "IPv4" in out)
    check("default EtherType value is 0x88B6", Settings().ethertype_value() == 0x88B6)

    # --- link address
    r, s, out = drive([D, D, "right", D, D, D, "right", X])
    check("link choice 'real adapter address' warns about Wi-Fi", s.link == 1 and "Wi-Fi" in out)
    r, s, out = drive([D, D, "right", D, D, D, "right", "right"] + typed("ff:ff:ff:ff:ff:ff") + [E_, X, X])
    check("a broadcast link address is refused", s.custom_link == "" and "multicast" in out)
    r, s, out = drive([D, D, "right", D, D, D, "right", "right"] + typed("02:00:5E:10:20:30") + [E_, X])
    check("a custom unicast link address is kept", s.link == 2 and s.custom_link == "02:00:5E:10:20:30")

    # --- automove and connect rules
    r, s, out = drive([D, D, "right", D, D, D, D, E_, X])
    check("move-to-Ethernet-after-login toggles", s.automove is True)
    r, s, out = drive([D] * 7 + [E_, X])
    check("Connect with no host is refused", "the host is not set" in out)
    s0 = Settings(); s0.host = "192.0.2.1:7171"
    r, s, out = drive([D] * 7 + [E_], settings=s0)
    check("Connect with a host on UDP only returns the settings", r is s0)
    s1 = Settings(); s1.host = "192.0.2.1:7171"; s1.paths = 1
    r, s, out = drive([D] * 7 + [E_, X], settings=s1)
    check("Connect with Ethernet on but no device is refused", "no Ethernet device" in out)
    s1.device = SAMPLE_DEVICES[2][0]
    r, s, out = drive([D] * 7 + [E_], settings=s1)
    check("Connect with Ethernet and a device goes ahead", r is s1)
    s1.link = 2; s1.custom_link = "nope"
    r, s, out = drive([D] * 7 + [E_, X], settings=s1)
    check("Connect with a bad custom link address is refused", r is None and "link address looks like" in out)
    saved = []
    s2 = Settings(); s2.host = "192.0.2.1:7171"
    r, s, out = drive([D] * 7 + [E_], settings=s2, saver=saved.append)
    check("the saver is called on Connect only", saved == [s2])
    r, s, out = drive([D] * 8 + [E_], settings=s2)
    check("Exit returns None", r is None)

    # --- settings file
    s3 = Settings()
    s3.host, s3.invite, s3.paths, s3.device = "[2001:db8::5]:7171", "my.key", 1, SAMPLE_DEVICES[1][0]
    s3.ethertype, s3.custom_ethertype, s3.link, s3.custom_link, s3.automove = 2, "9000", 2, "02:11:22:33:44:55", True
    s4 = Settings(); s4.load(s3.dump())
    check("settings survive a dump and load", s4.dump() == s3.dump() and s4.automove is True and s4.paths == 1)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "IPv7.conf")
        save_settings(s3, p)
        check("settings file round trip", load_settings(p).dump() == s3.dump() and load_settings(os.path.join(d, "none")).host == "")
        with open(p) as f:
            txt = f.read()
    check("the settings file holds no ticket, key or passphrase",
          not re.search(r"pass|secret|ticket|key ", txt.lower().replace("invite my.key", "")))
    s5 = Settings(); s5.load("paths 99\nethertype -4\nlink x\nbogus 1\nhost a.b:1")
    check("a damaged settings file cannot break the menu", 0 <= s5.paths < 2 and 0 <= s5.ethertype < 3 and s5.host == "a.b:1")

    # --- hardening: logging/debug controls must never be reachable from the menu. A user
    # (or anyone who gets hold of the client) should not be able to find, in this screen, any
    # way to turn on verbose output, read a log file, or see internal protocol state. If this
    # ever fires, something added a row or message that leaks that surface; move it out of the
    # menu, not into it.
    import re as _re
    forbidden = _re.compile(r"\b(log|debug|verbose|trace)\b", _re.I)
    with open(__file__, encoding="utf-8") as f:
        src = f.read()
    src = src.split("\n# ---------------------------------------------------------------- selftest\n")[0]
    import ast as _ast
    tree = _ast.parse(src)
    literal_hits = []
    for node in _ast.walk(tree):
        if isinstance(node, _ast.Constant) and isinstance(node.value, str):
            if forbidden.search(node.value) and "login" not in node.value.lower():
                literal_hits.append(node.value)
    check("no row label, prompt or message in this file names logging, debug, verbose or trace",
          literal_hits == [])
    r, s, out = drive([X])
    check("a run of the real menu's output mentions none of those words either",
          not forbidden.search(out.replace("Login", "")))

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


def main():
    if "--selftest" in sys.argv:
        return selftest()
    if not sys.stdin.isatty():
        print(__doc__)
        return 0
    enable_vt()
    if "--demo" in sys.argv:
        devices, npcap = SAMPLE_DEVICES, True
        saver = None
    else:
        devices, npcap = find_devices()
        saver = save_settings
    with TtyRaw():
        s = run_menu(load_settings(), devices, npcap, saver=saver)
    if s is None:
        print(EXIT_LINE)
        return 1
    print("%sSettings: host %s, %s" % (MARK_OK, s.host, PATHS[s.paths]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
