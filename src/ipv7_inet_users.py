#!/usr/bin/env python3
"""ipv7_inet_users.py - IPv7 with nicknames: a host, users who log in with a name, and a terminal.
A TEST version, a copy of ipv7_inet_peer.py with a user layer on top. It has no key: the frames are sealed with
a public key, so they hide nothing and anyone can join. Do not put anything private through it.

  python ipv7_inet_users.py --host [PORT] --name V3RDAD   host a network; you are the ADMIN        default port 7171
  python ipv7_inet_users.py --connect HOST [PORT] --name NICK
                                                           log in and get a terminal: ListUsers, Ping, Status, Help, Quit
  python ipv7_inet_users.py --help                        every option, and what $ * - mean
  python ipv7_inet_users.py --selftest                    checks against the terminal's own bytes, loopback only

  --name NAME  your nickname: 1 to 16 letters, digits, _ or -. On the host it is the ADMIN alias. Asked for if left out.
  --bind ADDR  (host) listen on this one carrier address only, so every answer leaves from it
  --status     add the explanatory Status lines to the screens; without it the screens carry only facts
  --hide6      print no ipv6 address anywhere, so a screenshot is safe to share
  --creator    the logo and the link
  -4           use ipv4 instead of ipv6 for the UDP carrier

Addresses: the host is HOST 1 of its network (192.0.0.172.16.0.2.1). Every nickname that logs in is given the next
free HOST in SUB 2 (.2.2, .2.3 ...) and keeps it as long as the host runs. In the list, Tree is #SUB_HOST.
IPv7 in the list: active when the user is bound on the Ethernet path, inactive while he is on UDP.
Names are shown only in the list. Everywhere else a user is his TP/IX address.
Relaying: a ping from one user to another goes through the host, which lowers the TTL by one on the way.

What travels (the same code as ipv7_inet_peer.py, the terminal's frame7 / lfsr7):
  AA frame  spi 4 | ctr 8 (masked) | sealed( hl cls proto flags | xa 8 | payload ) | tag 16     AES-256-GCM
  cls 0     data: a 36-byte TP/IX header (RFC 1475) + an ICMP echo       cls 1  FIX: wrong address, here is the right one
  cls 2     user: proto is the operation. 1 login, 2 list, 3 keepalive, 4 bye / 0x81 welcome, 0x82 denied, 0x83 users
Class numbers are provisional.

Needs:  pip install cryptography      (everything else is the standard library)
"""
import argparse
import hashlib
import io
import ipaddress
import os
import queue
import re
import secrets
import shutil
import socket
import sys
import textwrap
import threading
import time

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False

PORT = 7171
ME_RECEIVE = "192.0.0.172.16.0.2.2"
ME_CONNECT = "192.0.0.172.16.0.2.3"
LOOP7 = [192, 0, 0, 127, 0, 0, 1, 1]
CLS_DATA, CLS_FIX = 0, 1
FIX_NOT_HERE = 4
CLOCK_OK = 30           # seconds of clock difference that still counts as in step
CLOCK_SCAN = 86400      # how far the scan looks for the difference


# ---- screen ------------------------------------------------------------------------------------------

W = 96


def bar(ch="#"):
    print(ch * W)


BW = 36                  # the banner is this wide and sits in the middle of the terminal


def banner(title):
    pad = " " * max(0, (shutil.get_terminal_size((W, 24)).columns - BW) // 2)
    print(pad + "#" * BW)
    print()
    for t in ("IPv7_INET_TEST", title):
        print(pad + t.center(BW).rstrip())
    print()
    print(pad + "$" * BW)


def head(s, ch="*"):
    print("\n%s %s %s" % (ch, s, ch * max(3, W - len(s) - 3)))


def adapter(name):
    """a section header, the way ipconfig prints one:  'Ethernet adapter Ethernet 2:'"""
    print("\n%s:\n" % name)


KV_COL = 33


def kv(label, value=""):
    """   Label . . . . . . . . . : value     the dots sit on fixed columns, so a label of odd or even length
    touches them the way ipconfig's do ('IPv4 Address. . .' and 'Subnet Mask . . .'); 30 characters at most"""
    dots = "".join("." if i >= len(label) and i % 2 == (KV_COL - 1) % 2 else " " for i in range(len(label), KV_COL))
    print("   %s%s : %s" % (label, dots, value))


def more(value):
    """a second value under the same label, aligned like ipconfig does"""
    print(" " * (3 + KV_COL + 3) + value)


STATUS = False
HIDE6 = False            # --hide6: no ipv6 address is printed anywhere, for screenshots


def hidden(host):
    return HIDE6 and ":" in host


def show_src(src):
    return "hidden" if hidden(src[0]) else fmt_src(src)


def status(text):
    """an explanation, printed only with --status: the screens carry facts, not commentary"""
    if STATUS:
        lines = textwrap.wrap(text, W - (3 + KV_COL + 3))
        kv("Status", lines[0])
        for line in lines[1:]:
            more(line)


LEGEND = [
    ("--host [PORT]", "host a network, default port 7171; you are the ADMIN"),
    ("--connect HOST [PORT]", "log in to a host and get a terminal"),
    ("   Command:", "ListUsers, Ping [name] [n], Status, Help, Quit"),
    ("--name NAME", "your nickname, 1 to 16 letters, digits, _ or -"),
    ("--bind ADDR", "host: listen on this one carrier address, answers leave from it"),
    ("--hide6", "print no ipv6 address anywhere, for screenshots"),
    ("--status", "add the explanatory Status lines"),
    ("--creator", "who made this"),
    ("-4", "ipv4 carrier instead of ipv6"),
    ("--selftest", "check the code against the terminal's own bytes, loopback only"),
    ("--help", "this text"),
]
SYMBOLS = [
    ("$", "event"),
    ("*", "detail"),
    ("-", "silent: a stranger got nothing"),
    ("+0 s", "clock in step"),
]


def help_lines():
    out = ["IPv7_INET_USERS   nicknames over TP/IX, a test version with no key", "", "ipv7_inet_users.py [options]", ""]
    out += ["   %-24s %s" % (k, d) for k, d in LEGEND]
    out += ["", "Symbols:", ""]
    out += ["   %-24s %s" % (k, d) for k, d in SYMBOLS]
    return out


# ---- TP/IX addresses (RFC 1475 section 2.5 mapping) -----------------------------------------------------

def v4to7(a):
    return [192, 0, 0, a[0], a[1], a[2], 1, a[3]]


def v7to4(b):
    if b[:3] != [192, 0, 0] or b[6] != 1:
        return None
    return [b[3], b[4], b[5], b[7]]


def parse_addr(s):
    p = s.strip().split(".")
    try:
        n = [int(x) for x in p]
    except ValueError:
        raise ValueError("not an address: %r" % s)
    if any(x < 0 or x > 255 for x in n) or len(n) not in (4, 8):
        raise ValueError("an address is 4 numbers (ipv4) or 8 numbers (TP/IX), 0 to 255: %r" % s)
    return v4to7(n) if len(n) == 4 else n


def dotted(b):
    return ".".join(str(x) for x in b)


def csum(data):
    """one's complement of the one's complement sum of 16-bit words (IPv4 and TP/IX)"""
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | (data[i + 1] if i + 1 < len(data) else 0)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


# ---- TP/IX header + ICMP echo ----------------------------------------------------------------------------

def tpix_build(dst, src, payload, ttl=64, proto=1):
    ttl7 = ttl * 16
    b = bytearray([0x70, 9, ttl7 >> 8, ttl7 & 255]) + (36 + len(payload)).to_bytes(4, "big") + bytes(8) \
        + bytes(dst) + bytes(src) + bytes([0, proto, 0, 0])
    c = csum(b)
    b[34], b[35] = c >> 8, c & 255
    return bytes(b) + payload


def tpix_parse(pkt):
    if len(pkt) < 36:
        return {"err": "short header"}
    if pkt[0] != 0x70:
        return {"err": "version byte %02x" % pkt[0]}
    if int.from_bytes(pkt[4:8], "big") != len(pkt):
        return {"err": "length field %d, packet %d" % (int.from_bytes(pkt[4:8], "big"), len(pkt))}
    if csum(pkt[:36]) != 0:
        return {"err": "header checksum"}
    return {"ttl": ((pkt[2] << 8) | pkt[3]) >> 4, "dst": list(pkt[16:24]), "src": list(pkt[24:32]),
            "proto": pkt[33], "csum": (pkt[34] << 8) | pkt[35], "payload": pkt[36:], "len": len(pkt)}


def icmp_build(kind, ident, seq, data):
    m = bytearray([kind, 0, 0, 0, ident >> 8, ident & 255, seq >> 8, seq & 255]) + data
    c = csum(m)
    m[2], m[3] = c >> 8, c & 255
    return bytes(m)


def icmp_parse(m):
    if len(m) < 8 or csum(m) != 0:
        return {"err": "icmp checksum"}
    return {"type": m[0], "code": m[1], "id": (m[4] << 8) | m[5], "seq": (m[6] << 8) | m[7], "data": m[8:]}


# ---- LFSR clock (same maths as lfsr7 / sync7) ------------------------------------------------------------

LFSR_P = {32: 0x400007, 64: 0xB000000000000001}


def lfsr_mul(a, b, w=64):
    m, low, r = (1 << w) - 1, LFSR_P[w], 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if (a >> w) & 1:
            a = (a & m) ^ low
    return r


def lfsr_jump(seed, k, w=64):
    r, base = seed, 2
    while k > 0:
        if k & 1:
            r = lfsr_mul(r, base, w)
        base = lfsr_mul(base, base, w)
        k >>= 1
    return r


def lfsr_step(s, w=64):
    s <<= 1
    return ((s & ((1 << w) - 1)) ^ LFSR_P[w]) if (s >> w) & 1 else s


def lfsr_unstep(s, w=64):
    top = s & 1
    if top:
        s ^= LFSR_P[w]
    return (s >> 1) | (top << (w - 1))


_TABLES = {}


def lfsr_tables(w=64):
    if w not in _TABLES:
        L, R = [], []
        for b in range(256):
            s = b << (w - 8)
            for _ in range(8):
                s = lfsr_step(s, w)
            L.append(s)
            s = b
            for _ in range(8):
                s = lfsr_unstep(s, w)
            R.append(s)
        _TABLES[w] = (L, R)
    return _TABLES[w]


def lfsr_shl8(s, w=64):
    return ((s << 8) & ((1 << w) - 1)) ^ lfsr_tables(w)[0][s >> (w - 8)]


def lfsr_shr8(s, w=64):
    return (s >> 8) ^ lfsr_tables(w)[1][s & 255]


def find_drift(seed, label, now, span=CLOCK_SCAN):
    """the label is state(t) for the sender's clock t. returns t - now (seconds), or None if out of range"""
    s = lfsr_jump(seed, now)
    if s == label:
        return 0
    fw = bw = s
    for d in range(1, span + 1):
        fw, bw = lfsr_step(fw), lfsr_unstep(bw)
        if fw == label:
            return d
        if bw == label:
            return -d
    return None


# ---- AA frame ---------------------------------------------------------------------------------------------

AA_AAD = b"AA"


def hkdf(master, info, n):
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=b"AA-salt", info=info).derive(master)


class Keys:
    def __init__(self, master):
        self.aead = AESGCM(hkdf(master, b"AA aead", 32))
        self.hp = hkdf(master, b"AA hp", 32)
        self.salt = hkdf(master, b"AA salt", 4)


def aa_mask(keys, sample):
    e = Cipher(algorithms.AES(keys.hp), modes.ECB()).encryptor()      # one AES block: the same as the CTR trick
    return (e.update(sample) + e.finalize())[:8]


def aa_seal(keys, spi, ctr, cls, proto, payload, xa=None, hops=None, extra=b"", extra_flags=0):
    flags, slots = extra_flags, b""
    if xa is not None:
        flags |= 1
        slots += bytes(xa)
    if hops is not None:
        flags |= 2
        slots += bytes([hops])
    plain = bytes([4 + len(slots) + len(extra), cls, proto, flags]) + slots + bytes(extra) + bytes(payload)
    c = ctr.to_bytes(8, "big")
    ct = keys.aead.encrypt(keys.salt + c, plain, AA_AAD)
    mask = aa_mask(keys, ct[:16])
    return bytes(spi) + bytes(x ^ y for x, y in zip(c, mask)) + ct


class Window:
    """2048-slot replay window: check before the work, commit only after the tag verified"""

    def __init__(self, size=2048):
        self.S, self.top, self.bm = size, -1, 0

    def check(self, c):
        if self.top < 0 or c > self.top:
            return True
        d = self.top - c
        return d < self.S and not (self.bm >> d) & 1

    def commit(self, c):
        if self.top < 0:
            self.bm, self.top = 1, c
        elif c > self.top:
            shift = c - self.top
            self.bm = (((self.bm << shift) | 1) & ((1 << self.S) - 1)) if shift < self.S else 1   # a big jump must not build a big number
            self.top = c
        else:
            self.bm |= 1 << (self.top - c)


MASK48 = (1 << 48) - 1
EPOCH_MS = 1767225600000          # 2026-01-01 00:00 UTC: the sender's counter counts milliseconds from here


class WindowBook:
    """one replay window per sender. The top 16 bits of the counter name the sender; they are part of the nonce,
    so the tag covers them and a replayed frame lands in the same window it came from.
    Windows are created only after a frame has verified, and only the newest `cap` senders are kept."""

    def __init__(self, size=2048, cap=256):
        self.size, self.cap, self.w = size, cap, {}

    def check(self, c):
        w = self.w.get(c >> 48)
        return True if w is None else w.check(c & MASK48)

    def commit(self, c):
        k = c >> 48
        if k not in self.w:
            if len(self.w) >= self.cap:
                self.w.pop(next(iter(self.w)))
            self.w[k] = Window(self.size)
        self.w[k].commit(c & MASK48)


def aa_open(keys, wire, win=None):
    if len(wire) < 32:
        return {"err": "short"}
    sealed = wire[12:]
    mask = aa_mask(keys, sealed[:16])
    c = bytes(x ^ y for x, y in zip(wire[4:12], mask))
    ctr = int.from_bytes(c, "big")
    if win is not None and not win.check(ctr):
        return {"err": "replay"}
    try:
        pt = keys.aead.decrypt(keys.salt + c, sealed, AA_AAD)
    except InvalidTag:
        return {"err": "tag"}
    hl, flags, at = pt[0], pt[3], 4
    out = {"spi": wire[:4], "ctr": ctr, "cls": pt[1], "proto": pt[2], "flags": flags, "hl": hl, "xa": None, "hops": None}
    if hl < 4 or hl > len(pt):
        return {"err": "head"}
    if flags & 1:
        out["xa"], at = pt[at:at + 8], at + 8
    if flags & 2:
        out["hops"], at = pt[at], at + 1
    if at > hl:
        return {"err": "head"}
    out["skipped"], out["payload"] = hl - at, pt[hl:]
    if win is not None:
        win.commit(ctr)
    return out


# ---- the node ---------------------------------------------------------------------------------------------

def stamp():
    return time.strftime("%H:%M:%S")


def fmt_src(src):
    return "[%s]:%d" % (src[0].split("%")[0], src[1]) if ":" in src[0] else "%s:%d" % (src[0], src[1])


def same_host(a, b):
    try:
        return ipaddress.ip_address(a[0].split("%")[0]) == ipaddress.ip_address(b[0].split("%")[0])
    except ValueError:
        return a[0] == b[0]


def outbound(fam, target):
    """the address the OS would send from; a UDP connect() sends nothing"""
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((target, 53))
        a = s.getsockname()[0].split("%")[0]
        s.close()
        return a
    except OSError:
        return None


class Node:
    def __init__(self, passphrase, role, me, out=print, accept=False):
        master = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), b"IPv7 test", 100000, 32)
        c2r, r2c = hkdf(master, b"AA dir c2r", 32), hkdf(master, b"AA dir r2c", 32)
        tx, rx = (c2r, r2c) if role == "c" else (r2c, c2r)
        self.tx, self.rx = Keys(tx), Keys(rx)
        self.tx_spi, self.rx_spi = hkdf(tx, b"AA spi", 4), hkdf(rx, b"AA spi", 4)
        self.tx_seed = int.from_bytes(hkdf(tx, b"AA lfsr", 8), "big") or 1
        self.rx_seed = int.from_bytes(hkdf(rx, b"AA lfsr", 8), "big") or 1
        self.win, self.low, self.me, self.out = WindowBook(), 0, me, out
        self.cid = secrets.randbits(16)       # names this process in every nonce it uses
        self.lock = threading.Lock()          # a session seals from its keepalive thread and from its terminal
        self.accept, self.peer = accept, None   # receive: may more than one peer join?
        self.st = {"strangers": 0, "declined": 0, "bad": 0, "ignored": 0, "echo": 0, "fix": 0}
        self.mine = [me, LOOP7]
        lan = outbound(socket.AF_INET, "8.8.8.8")
        if lan:
            self.mine.append(v4to7([int(x) for x in lan.split(".")]))
        self.lan = lan

    def ctr(self):
        """16 bits sender id | 40 bits milliseconds since 2026 | 8 bits for several frames in one millisecond.
        Strictly increasing in this process, and a restart starts later in time, so a nonce is never reused"""
        with self.lock:
            self.low = max(self.low + 1, (int(time.time() * 1000) - EPOCH_MS) << 8)
            return (self.cid << 48) | (self.low & MASK48)

    def label(self):
        return lfsr_jump(self.tx_seed, int(time.time())).to_bytes(8, "big")

    def seal(self, cls, proto, payload):
        return aa_seal(self.tx, self.tx_spi, self.ctr(), cls, proto, payload, xa=self.label())

    def drift(self, xa):
        return find_drift(self.rx_seed, int.from_bytes(xa, "big"), int(time.time())) if xa else None

    @staticmethod
    def clock_text(d):
        if d is None:
            return "clock ?  further than a day apart"
        return "clock %+d s%s" % (d, "" if abs(d) <= CLOCK_OK else "  OUT OF STEP")

    def ping(self, dst, seq, size):
        data = (b"IPv7test" + bytes((i * 7 + 1) & 255 for i in range(max(0, size - 8))))[:size]
        pkt = tpix_build(dst, self.me, icmp_build(8, 0x4950, seq, data))
        return self.seal(CLS_DATA, 0, pkt), pkt

    def open(self, data, who):
        """spi, replay window and tag: the opened AA frame, or None. What is refused is counted and logged as a - line"""
        if data[:4] != self.rx_spi:
            self.st["strangers"] += 1
            self.out("- Request from %s: bytes=%d silence, spi is not ours" % (who, len(data)))
            return None
        r = aa_open(self.rx, data, self.win)
        if "err" in r:
            self.st["bad"] += 1
            self.out("- Request from %s: bytes=%d silence, %s" % (who, len(data), r["err"]))
            return None
        return r

    def on_datagram(self, data, src):
        """returns the reply datagram, or None: strangers get silence.
        One block per request, the way ping prints one line per echo; --status adds a * line for each detail"""
        say, who = self.out, show_src(src)
        if data[:4] != self.rx_spi:
            self.st["strangers"] += 1
            say("- Request from %s: bytes=%d silence, spi is not ours" % (who, len(data)))
            return None
        r = aa_open(self.rx, data, self.win)
        if "err" in r:
            self.st["bad"] += 1
            say("- Request from %s: bytes=%d silence, %s" % (who, len(data), r["err"]))
            return None
        if r["cls"] != CLS_DATA:
            self.st["ignored"] += 1
            say("- Request from %s: bytes=%d ignored, cls %d" % (who, len(data), r["cls"]))
            return None
        host = src[0].split("%")[0]
        if not self.accept:
            if self.peer is None:
                self.peer = host                      # the first peer that opens a frame holds the receiver
            elif not same_host(src, (self.peer,)):
                self.st["declined"] += 1
                say("- Request from %s: bytes=%d declined, another peer holds this receiver" % (who, len(data)))
                return None
        d = self.drift(r["xa"])
        age = int(time.time() * 1000) - EPOCH_MS - ((r["ctr"] & MASK48) >> 8)
        h = tpix_parse(r["payload"])
        if "err" in h:
            say("- Request from %s: bytes=%d ignored, TP/IX %s" % (who, len(data), h["err"]))
            return None
        mine = h["dst"] in self.mine
        v4 = v7to4(h["src"])
        frm = dotted(h["src"])
        via = "" if hidden(host) else " via %s" % who
        dl = ["*   %s  AA frame from %s  %d B  cls DATA  %s" % (stamp(), who, len(data), self.clock_text(d)),
              "*   tp/ix    %d B  ttl %d  proto %d  csum 0x%04x OK" % (h["len"], h["ttl"], h["proto"], h["csum"]),
              "*   dst      %-22s %s" % (dotted(h["dst"]), "for me" if mine else "NOT me"),
              "*   src      %-22s%s" % (frm, ("   = ipv4 %s" % dotted(v4)) if v4 else "")]

        def details():
            """with --status, the facts behind the line above, one per line, right under it"""
            if STATUS:
                for line in dl:
                    say(line)
        if not mine:
            self.st["fix"] += 1
            say("Request from %s: bytes=%d for %s, not here" % (frm, h["len"], dotted(h["dst"])))
            details()
            if STATUS:
                say("Reply to %s: FIX 04, this node is %s%s" % (frm, dotted(self.me), via))
            return self.seal(CLS_FIX, FIX_NOT_HERE, bytes(self.me))
        if h["proto"] != 1:
            say("- Request from %s: bytes=%d ignored, proto %d is not handled here" % (frm, len(data), h["proto"]))
            details()
            return None
        m = icmp_parse(h["payload"])
        if "err" in m or m["type"] != 8:
            say("- Request from %s: bytes=%d ignored, icmp %s" % (frm, len(data), m.get("err") or "type %d" % m["type"]))
            details()
            return None
        if STATUS:
            say("%r" % m["data"][:12].decode("latin1"))          # the payload, only with --status
        say("Request from %s: bytes=%d %s TTL=%d" % (frm, len(m["data"]), time_text(age), h["ttl"]))
        dl.append("*   icmp     echo request  id 0x%04x  seq %d" % (m["id"], m["seq"]))
        details()
        reply = tpix_build(h["src"], h["dst"], icmp_build(0, m["id"], m["seq"], m["data"]))
        wire = self.seal(CLS_DATA, 0, reply)
        self.st["echo"] += 1
        if STATUS:
            say("Reply to %s: bytes=%d TTL=64%s" % (frm, len(m["data"]), via))
            say("")
        return wire

    def on_reply(self, data):
        """connect side: an authenticated reply, or None"""
        if data[:4] != self.rx_spi:
            return None
        r = aa_open(self.rx, data, self.win)
        if "err" in r:
            return None
        r["drift"] = self.drift(r["xa"])
        if r["cls"] == CLS_FIX:
            r["fix"] = r["proto"]
            r["fix_addr"] = list(r["payload"][:8])
            return r
        h = tpix_parse(r["payload"])
        if "err" in h:
            return None
        m = icmp_parse(h["payload"])
        if "err" in m or m["type"] != 0:
            return None
        r["h"], r["m"] = h, m
        return r


def ms_text(ms):
    return "%dms" % int(round(ms))


def ping_stats(target, sent, got, rtts):
    """the block that closes a Windows ping, word for word"""
    lost = sent - got
    pct = int(round(100.0 * lost / sent)) if sent else 0
    out = ["Ping statistics for %s:" % target,
           "    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss)," % (sent, got, lost, pct)]
    if rtts:
        out += ["Approximate round trip times in milli-seconds:",
                "    Minimum = %s, Maximum = %s, Average = %s" % (
                    ms_text(min(rtts)), ms_text(max(rtts)), ms_text(sum(rtts) / len(rtts)))]
    return out


def reply_line(target, nbytes, ms, ttl):
    """Reply from 192.0.0.172.16.0.2.2: bytes=32 time=2ms TTL=64"""
    t = "time<1ms" if ms < 0.5 else "time=%s" % ms_text(ms)
    return "Reply from %s: bytes=%d %s TTL=%d" % (target, nbytes, t, ttl)


def receiver_totals(st):
    return [("Answered", "%d echo requests" % st["echo"]),
            ("FIX Sent", "%d" % st["fix"]),
            ("Strangers", "%d" % st["strangers"]),
            ("Declined", "%d" % st["declined"]),
            ("Failed Open", "%d" % st["bad"]),
            ("Ignored", "%d" % st["ignored"])]


def time_text(age):
    """the frame's age on arrival by the two clocks: it includes any difference between them, so it is an estimate"""
    if abs(age) > 5000:
        return "time=?"
    return "time<1ms" if age < 1 else "time=%dms" % age


# ---- local view -------------------------------------------------------------------------------------------

def local_view(node, port, fam):
    adapter("TP/IX Adapter IPv7")
    kv("TP/IX Address", dotted(node.me))
    kv("Loopback Address", dotted(LOOP7))
    if node.lan:
        kv("Mapped IPv4 Address", dotted(v4to7([int(x) for x in node.lan.split(".")])))
        more("= %s" % node.lan)
        status("SUB 1 means a plain IPv4 address")

    v6 = outbound(socket.AF_INET6, "2001:4860:4860::8888")
    if not (v6 and HIDE6):
        adapter("Adapter UDP6")
        if v6:
            kv("IPv6 Address", v6)
            kv("Carrier Endpoint", "[%s]:%d" % (v6, port))
            status("this is the address the machine sends from, it may be a temporary one that changes; "
                   "a stable one is what you give out, see ipv6_inet_check.py")
        else:
            kv("Media State", "Media disconnected")
            kv("Reason", "no IPv6 route out from here")

    adapter("Adapter UDP4")
    if node.lan:
        kv("IPv4 Address", node.lan)
        kv("Carrier Endpoint", "%s:%d" % (node.lan, port))
        status("lan only, a private address does not cross the internet")
    else:
        kv("Media State", "Media disconnected")

    adapter("Adapter LFSR64")
    poly = LFSR_P[64].to_bytes(8, "big")
    if STATUS:
        kv("Polynomial", poly_text(LFSR_P[64]))
    kv("Polynomial Address", dotted(poly))
    kv("Polynomial Taps", poly_taps(LFSR_P[64]))
    kv("Time", "%d s" % int(time.time()))
    kv("Label", "%016x" % int.from_bytes(node.label(), "big"))
    if STATUS:
        s = 0x0123456789ABCDEF
        kv("Self-check", "shl8 equals 8 steps %s, shr8 after shl8 is identity %s" % (
            "OK" if lfsr_shl8(s) == _eight(s) else "FAIL", "OK" if lfsr_shr8(lfsr_shl8(s)) == s else "FAIL"))
    return v6


def poly_taps(mask, w=64):
    """the exponents of the polynomial as a dotted list: x^64+x^63+x^61+x^60+1 is 64.63.61.60.0"""
    return ".".join(str(e) for e in [w] + [i for i in range(w - 1, -1, -1) if (mask >> i) & 1])


def poly_text(mask, w=64):
    return "+".join("1" if e == 0 else "x" if e == 1 else "x^%d" % e for e in map(int, poly_taps(mask, w).split(".")))


def _eight(s):
    for _ in range(8):
        s = lfsr_step(s)
    return s


# ---- receive / connect ------------------------------------------------------------------------------------

LOGO = [
    ' ██▒   █ █████▓▓  ██▀███  ▓█████▄  ▄▄▄      ▓█████▄ ',
    '▓██░   █ ▀   █▓▒ ▓██ ▒ ██▒▒██▀ ██▌▒████▄    ▒██▀ ██▌',
    ' ▓██  █▒   ███▒░ ▓██ ░▄█ ▒░██   █▌▒██  ▀█▄  ░██   █▌',
    '  ▒██ █░ ▄  █▓▒░ ▒██▀▀█▄  ░▓█▄   ▌░██▄▄▄▄██ ░▓█▄   ▌',
    '   ▒▀█░  ████▒░ ▒░██▓ ▒██▒░▒████▓  ▓█   ▓██▒░▒████▓ ',
    '   ░ ▐░   ░▒ ░░ ░░ ▒▓ ░▒▓░ ▒▒▓  ▒  ▒▒   ▓▒█░ ▒▒▓  ▒ ',
    '   ░ ░░    ░ ░  ░  ░▒ ░ ▒░ ░ ▒  ▒   ▒   ▒▒ ░ ░ ▒  ▒ ',
    '     ░░    ░       ░░   ░  ░ ░  ░   ░   ▒    ░ ░  ░ ',
    '      ░    ░    ░   ░        ░          ░  ░   ░    ',
    '     ░                     ░                 ░     ',
]
CREATOR_URL = "https://t.me/V3RDAD"


def creator():
    """--creator: the logo, a line, and the link. In a terminal that knows hyperlinks (Windows Terminal does) the logo
    is clickable; everywhere else the link is printed under it"""
    click = sys.stdout.isatty() and bool(os.environ.get("WT_SESSION") or os.environ.get("VTE_VERSION")
                                         or os.environ.get("TERM_PROGRAM"))
    try:
        for line in LOGO:
            print("\x1b]8;;%s\x1b\\%s\x1b]8;;\x1b\\" % (CREATOR_URL, line) if click else line)
    except UnicodeEncodeError:
        print("V3RDAD")
    print("\nKnowledge is free\n")
    print(CREATOR_URL)
    return 0


EXIT_LINE = "......Program exits!"        # printed when the program is closed, or when the crypto is refused


def need_crypto():
    if not HAVE_CRYPTO:
        print("$ needs the cryptography package:   pip install cryptography")
        print(EXIT_LINE)
        sys.exit(2)


# ---- users: a nickname, a directory, a terminal -----------------------------------------------------------

CLS_USER = 2                                       # provisional, like the other class numbers
OP_LOGIN, OP_LIST, OP_KEEP, OP_BYE = 1, 2, 3, 4    # user to host
OP_WELCOME, OP_DENIED, OP_USERS = 0x81, 0x82, 0x83  # host to user
TEST_KEY = "ipv7-users-test"       # public, it is in the source: this test version has no key and no secrecy
ME_HOST = "192.0.0.172.16.0.2.1"   # HOST 1: the host is the .1 of its network, users are given .2, .3 ... at login
POOL_SUB = 2                       # SUB 1 is the plain-ipv4 mapping, so the users live in SUB 2
ONLINE_SECS, KEEP_SECS, MAX_USERS = 30, 10, 40
NAME_OK = re.compile(r"^[A-Za-z0-9_-]{1,16}$")
ADMIN, USER = 0, 1
RANK_TEXT = {ADMIN: "ADMIN", USER: "USER"}
DENY = {1: "that name is not allowed, use 1 to 16 letters, digits, _ or -",
        2: "that name is online already",
        3: "this host is full",
        4: "log in first",
        5: "this connection is logged in under another name"}


def ckey(src):
    """the carrier as a dictionary key: ipv6 spelled one way, no scope id"""
    try:
        h = str(ipaddress.ip_address(src[0].split("%")[0]))
    except ValueError:
        h = src[0]
    return (h, src[1])


class Directory:
    """who is on this host: the ADMIN, which is the host itself, and every nickname that has logged in.
    A nickname keeps its TP/IX address for as long as the host runs, online or not"""

    def __init__(self, name, addr):
        self.addr = list(addr)
        self.host_rec = {"name": name, "rank": ADMIN, "addr": list(addr), "carrier": None, "raw": None,
                         "seen": None, "host": True, "on": True, "eth": False}
        self.users = {name.lower(): self.host_rec}
        self.order = [name.lower()]
        self.by_key = {}

    def online(self, rec, now):
        return bool(rec.get("host")) or (rec["seen"] is not None and now - rec["seen"] <= ONLINE_SECS)

    def active(self, rec, now=None):
        """IPv7 active: the user is bound on the Ethernet path. On UDP, the host included, it is inactive"""
        return bool(rec.get("eth", False))

    @staticmethod
    def set_eth(rec, bound):
        """a user moved to the Ethernet path (True) or back to UDP (False)"""
        rec["eth"] = bool(bound)

    @staticmethod
    def mark(rec, now):
        rec["act"] = now

    def by_carrier(self, key):
        k = self.by_key.get(key)
        rec = self.users.get(k) if k else None
        return rec if rec is not None and rec["carrier"] == key else None

    def by_addr(self, addr):
        for rec in self.users.values():
            if rec["addr"] == list(addr):
                return rec
        return None

    def free_host(self):
        used = {r["addr"][7] for r in self.users.values() if r["addr"][6] == POOL_SUB}
        return next((n for n in range(2, 255) if n not in used), None)

    def login(self, name, key, now, raw=None):
        """("ok", record) or ("err", code)"""
        name = name.strip()
        if not NAME_OK.match(name) or name.lower() == "admin":
            return ("err", 1)
        rec = self.users.get(name.lower())
        here = self.by_carrier(key)
        if here is not None and here is not rec:
            return ("err", 5)
        if rec is not None:
            if rec.get("host") or (self.online(rec, now) and rec["carrier"] != key):
                return ("err", 2)
        else:
            n = self.free_host() if len(self.users) < MAX_USERS else None
            if n is None:
                return ("err", 3)
            rec = {"name": name, "rank": USER, "addr": self.addr[:6] + [POOL_SUB, n], "carrier": None, "raw": None,
                   "seen": None, "on": False, "eth": False}
            self.users[name.lower()] = rec
            self.order.append(name.lower())
        if rec["carrier"] is not None:
            self.by_key.pop(rec["carrier"], None)
        rec["carrier"], rec["raw"], rec["seen"], rec["on"] = key, raw or key, now, True
        rec["eth"] = False                        # a login is a bind over UDP; Ethernet comes after it
        self.by_key[key] = name.lower()
        return ("ok", rec)

    def touch(self, rec, now, raw=None):
        rec["seen"], rec["on"] = now, True
        if raw is not None:
            rec["raw"] = raw

    def logout(self, rec):
        if rec["carrier"] is not None:
            self.by_key.pop(rec["carrier"], None)
        rec["carrier"], rec["raw"], rec["seen"], rec["on"] = None, None, None, False
        rec["eth"] = False

    def remove(self, rec):
        """A revoked user leaves the table entirely (not just offline): ListUsers no longer shows
        the name, and the TP/IX address goes back to the pool. The ADMIN row cannot be removed."""
        if rec is None or rec.get("host"):
            return False
        self.logout(rec)
        key = rec["name"].lower()
        if self.users.get(key) is rec:
            del self.users[key]
            if key in self.order:
                self.order.remove(key)
            return True
        return False

    def sweep(self, now):
        """the users whose keepalives stopped since the last sweep"""
        gone = [r for r in self.users.values() if not r.get("host") and r["on"] and not self.online(r, now)]
        for r in gone:
            r["on"] = False
        return gone

    def rows(self, now):
        return [(self.users[k]["rank"], self.online(self.users[k], now), self.users[k]["addr"], self.users[k]["name"],
                 self.active(self.users[k])) for k in self.order][:MAX_USERS]


def pack_users(rows):
    """a row is (rank, online, addr, name, active); active means bound on Ethernet.
    On the wire: rank, online, active, addr 8, name length, name"""
    out = bytearray([len(rows)])
    for rank, on, addr, name, act in rows:
        nb = name.encode()
        out += bytes([rank, 1 if on else 0, 1 if act else 0]) + bytes(addr) + bytes([len(nb)]) + nb
    return bytes(out)


def unpack_users(b):
    rows, at = [], 1
    for _ in range(b[0] if b else 0):
        rank, on, act, addr, n = b[at], b[at + 1], b[at + 2], list(b[at + 3:at + 11]), b[at + 11]
        rows.append((rank, bool(on), addr, b[at + 12:at + 12 + n].decode("utf-8", "replace"), bool(act)))
        at += 12 + n
    return rows


def pack_welcome(rec, host_rec):
    return bytes(rec["addr"]) + bytes([rec["rank"]]) + bytes(host_rec["addr"]) + host_rec["name"].encode()


def unpack_welcome(b):
    return list(b[:8]), b[8], list(b[9:17]), b[17:].decode("utf-8", "replace")


class HostNode(Node):
    """the host: logs nicknames in, keeps the directory, answers pings, and relays pings between users.
    Relaying is routing: the host lowers the TTL by one and seals the packet again for the next carrier"""

    def __init__(self, name, me, out=print):
        super().__init__(TEST_KEY, "r", me, out=out, accept=True)
        self.dir = Directory(name, me)
        self.st.update(logins=0, denied=0, forwarded=0, nologin=0)

    def handle(self, data, src, send):
        """one datagram in; send(wire, carrier) for every datagram out"""
        say, who = self.out, show_src(src)
        r = self.open(data, who)
        if r is None:
            return
        now, key = time.time(), ckey(src)
        via = "" if hidden(src[0]) else " via %s" % who
        if r["cls"] == CLS_USER:
            return self.control(r, src, key, who, via, now, send)
        if r["cls"] != CLS_DATA:
            self.st["ignored"] += 1
            say("- Request from %s: bytes=%d ignored, cls %d" % (who, len(data), r["cls"]))
            return
        u = self.dir.by_carrier(key)
        if u is None:
            self.st["nologin"] += 1
            say("- Request from %s: bytes=%d silence, not logged in" % (who, len(data)))
            send(self.seal(CLS_USER, OP_DENIED, bytes([4]) + DENY[4].encode()), src)
            return
        self.dir.touch(u, now, src)
        h = tpix_parse(r["payload"])
        if "err" in h:
            say("- Request from %s: bytes=%d ignored, TP/IX %s" % (dotted(u["addr"]), len(data), h["err"]))
            return
        frm, dst = dotted(h["src"]), h["dst"]
        if h["src"] != u["addr"]:
            say("- Request from %s: bytes=%d ignored, source %s is not his address" % (dotted(u["addr"]), len(data), frm))
            return
        if STATUS:
            say("*   %s  AA frame from %s%s  %d B  %s" % (stamp(), dotted(u["addr"]), via, len(data), self.clock_text(self.drift(r["xa"]))))
        if dst == self.me or dst == LOOP7:
            return self.echo(h, r, src, via, now, send)
        target = self.dir.by_addr(dst)
        if target is not None and not target.get("host") and self.dir.online(target, now) and target["raw"]:
            if h["ttl"] <= 1:
                say("- Request from %s: bytes=%d dropped, TTL expired" % (frm, len(data)))
                return
            pkt = tpix_build(h["dst"], h["src"], h["payload"], ttl=h["ttl"] - 1, proto=h["proto"])
            self.st["forwarded"] += 1
            say("Forward %s to %s: bytes=%d TTL=%d" % (frm, dotted(dst), max(0, len(h["payload"]) - 8), h["ttl"] - 1))
            send(self.seal(CLS_DATA, 0, pkt), target["raw"])
            return
        self.st["fix"] += 1
        say("Request from %s: bytes=%d for %s, not here" % (frm, h["len"], dotted(dst)))
        if STATUS:
            say("Reply to %s: FIX 04, this node is %s%s" % (frm, dotted(self.me), via))
        send(self.seal(CLS_FIX, FIX_NOT_HERE, bytes(self.me)), src)

    def echo(self, h, r, src, via, now, send):
        say, frm = self.out, dotted(h["src"])
        m = icmp_parse(h["payload"])
        if "err" in m or m["type"] != 8:
            say("- Request from %s: bytes=%d ignored, icmp %s" % (frm, h["len"], m.get("err") or "type %d" % m["type"]))
            return
        age = int(now * 1000) - EPOCH_MS - ((r["ctr"] & MASK48) >> 8)
        if STATUS:
            say("%r" % m["data"][:12].decode("latin1"))          # the payload, only with --status
        say("Request from %s: bytes=%d %s TTL=%d" % (frm, len(m["data"]), time_text(age), h["ttl"]))
        reply = tpix_build(h["src"], h["dst"], icmp_build(0, m["id"], m["seq"], m["data"]))
        self.st["echo"] += 1
        if STATUS:
            say("Reply to %s: bytes=%d TTL=64%s" % (frm, len(m["data"]), via))
            say("")
        send(self.seal(CLS_DATA, 0, reply), src)

    def control(self, r, src, key, who, via, now, send):
        say, op = self.out, r["proto"]
        if op == OP_LOGIN:
            name = r["payload"].decode("utf-8", "replace")
            kind, res = self.dir.login(name, key, now, src)
            if kind == "err":
                self.st["denied"] += 1
                say("Login%s: denied, %s" % (via, DENY[res]))
                send(self.seal(CLS_USER, OP_DENIED, bytes([res]) + DENY[res].encode()), src)
                return
            self.st["logins"] += 1
            say("Login%s: assigned %s" % (via, dotted(res["addr"])))
            send(self.seal(CLS_USER, OP_WELCOME, pack_welcome(res, self.dir.host_rec)), src)
            return
        u = self.dir.by_carrier(key)
        if u is None:
            self.st["nologin"] += 1
            say("- Request from %s: silence, not logged in" % who)
            send(self.seal(CLS_USER, OP_DENIED, bytes([4]) + DENY[4].encode()), src)
            return
        self.dir.touch(u, now, src)
        if op == OP_LIST:
            send(self.seal(CLS_USER, OP_USERS, pack_users(self.dir.rows(now))), src)
        elif op == OP_BYE:
            self.dir.logout(u)
            say("Logout from %s" % dotted(u["addr"]))
        elif op != OP_KEEP:
            say("- Request from %s: ignored, user op %d" % (dotted(u["addr"]), op))


class Session:
    """a user's side: one socket, a thread that reads it, a thread that keeps the line warm.
    It answers echo requests the host relays to it, and hands everything else to whoever is waiting"""

    def __init__(self, host, port, name, fam=socket.AF_UNSPEC):
        af, st, pr, cn, sa = socket.getaddrinfo(host, port, fam, socket.SOCK_DGRAM)[0]
        self.af, self.sa, self.sock, self.name = af, sa, socket.socket(af, st), name
        self.sock.settimeout(0.5)
        self.node = Node(TEST_KEY, "c", parse_addr("192.0.0.172.16.0.2.0"), out=lambda *_: None)
        self.me = self.host_addr = self.host_name = None
        self.rank, self.answered, self.lost = USER, 0, False
        self.q, self.stop = queue.Queue(), threading.Event()

    def start(self):
        for target in (self.pump, self.keep):
            threading.Thread(target=target, daemon=True).start()

    def send(self, cls, proto, payload=b""):
        self.sock.sendto(self.node.seal(cls, proto, payload), self.sa)

    def pump(self):
        node = self.node
        while not self.stop.is_set():
            try:
                data, src = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                time.sleep(0.05)
                continue
            if ckey(src) != ckey(self.sa):
                continue
            r = node.open(data, "host")
            if r is None:
                continue
            if r["cls"] == CLS_USER:
                if r["proto"] == OP_DENIED and r["payload"][:1] == b"\x04":
                    self.lost = True
                self.q.put(("user", r))
            elif r["cls"] == CLS_FIX:
                self.q.put(("fix", {"fix": list(r["payload"][:8])}))
            elif r["cls"] == CLS_DATA:
                h = tpix_parse(r["payload"])
                m = icmp_parse(h["payload"]) if "err" not in h else {"err": "x"}
                if "err" in m:
                    continue
                if m["type"] == 8 and h["dst"] == self.me:
                    reply = tpix_build(h["src"], h["dst"], icmp_build(0, m["id"], m["seq"], m["data"]))
                    self.sock.sendto(node.seal(CLS_DATA, 0, reply), self.sa)
                    self.answered += 1
                elif m["type"] == 0:
                    self.q.put(("echo", {"h": h, "m": m, "n": len(data)}))

    def keep(self):
        while not self.stop.wait(KEEP_SECS):
            try:
                self.send(CLS_USER, OP_KEEP)
            except OSError:
                pass

    def wait(self, kinds, ok, timeout):
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return None
            try:
                kind, val = self.q.get(timeout=left)
            except queue.Empty:
                return None
            if kind in kinds and ok(val):
                return kind, val

    def ask(self, op, payload, want, tries=3, wait=1.5):
        for _ in range(tries):
            self.send(CLS_USER, op, payload)
            got = self.wait(("user",), lambda r: r["proto"] in want or r["proto"] == OP_DENIED, wait)
            if got:
                return got[1]
        return None

    def login(self):
        """("ok", None), ("denied", why) or ("silent", why)"""
        self.start()
        r = self.ask(OP_LOGIN, self.name.encode(), (OP_WELCOME,))
        if r is None:
            return "silent", "the host did not answer: nothing listens there, a firewall drops it, or the port is wrong"
        if r["proto"] == OP_DENIED:
            return "denied", r["payload"][1:].decode("utf-8", "replace")
        self.me, self.rank, self.host_addr, self.host_name = unpack_welcome(r["payload"])
        self.node.me = self.me
        return "ok", None

    def list_users(self):
        r = self.ask(OP_LIST, b"", (OP_USERS,))
        return unpack_users(r["payload"]) if r is not None and r["proto"] == OP_USERS else None

    def ping(self, dst, count, size=32, interval=1.0, show=None):
        results = []
        for seq in range(1, count + 1):
            wire, _ = self.node.ping(dst, seq, size)
            t0 = time.perf_counter()
            self.sock.sendto(wire, self.sa)
            got = self.wait(("echo", "fix"), lambda v, s=seq: "fix" in v or v["m"]["seq"] == s, 3.0)
            if got is None:
                res = {"kind": "timeout"}
            elif got[0] == "fix":
                res = {"kind": "fix", "fix": got[1]["fix"]}
            else:
                v = got[1]
                res = {"kind": "reply", "ms": (time.perf_counter() - t0) * 1000, "ttl": v["h"]["ttl"],
                       "n": len(v["m"]["data"]), "src": v["h"]["src"]}
            results.append(res)
            if show:
                show(res)
            if seq < count:
                time.sleep(max(0, interval - (time.perf_counter() - t0)))
        return results

    def close(self, bye=True):
        if bye:
            try:
                self.send(CLS_USER, OP_BYE)
            except OSError:
                pass
        self.stop.set()


def table_lines(rows):
    """the user list, the way the terminal prints it, with no border. Tree is the SUB and HOST of the TP/IX address.
    Every column is left-aligned, and its values start under the first letter of its header. Rank has no left
    border, so it starts at the left edge; the other columns start two spaces after their bar. iPv7 says active when
    the user is bound on the Ethernet path, inactive while he is on UDP. The names are shown here and nowhere else"""
    def line(a, b, d, e, c):
        return "%s  |  %s  |  %s  |  %s  |  %s  |" % (a.ljust(5), b.ljust(10), d.ljust(6), e.ljust(16), c.ljust(8))
    out = [line("Rank", "Connected?", "Tree", "ALIAS", "iPv7")]
    for rank, on, addr, name, act in rows:
        out.append(line(RANK_TEXT.get(rank, "USER"), "Yes" if on else "No", "#%d_%d" % (addr[6], addr[7]),
                        name, "active" if act else "inactive"))
    return out


PRIVATE_BOX = ["############ iPv7 ##################",
               'Warning! THIS IS A PRIVATE NETWORK.#  "Knowledge is free" - V3RDAD',
               "####################################"]


def status_banner(online=True):
    label, mid = "IPv7 NETWORK STATUS:", "######%s#####" % ("ONLINE" if online else "OFFLINE")
    return [" " * len(label) + "#" * len(mid), label + mid, " " * len(label) + "#" * len(mid)]


def print_ping(sess, addr, count, size=32, out=print):
    """Windows ping of an address: no name is shown, only the TP/IX address"""
    out("\nPinging %s with %d bytes of data:" % (dotted(addr), size))

    def show(res):
        if res["kind"] == "reply":
            out(reply_line(dotted(res["src"]), res["n"], res["ms"], res["ttl"]))
        elif res["kind"] == "fix":
            out("Reply from %s: Destination host unreachable." % dotted(res["fix"]))
        else:
            out("Request timed out.")
    results = sess.ping(addr, count, size, show=show)
    got = [x for x in results if x["kind"] == "reply"]
    out("")
    for line in ping_stats(dotted(addr), len(results), len(got), [x["ms"] for x in got]):
        out(line)
    return results


HELP_COMMANDS = [("ListUsers", "who is on this host"),
                 ("Ping [name] [n]", "ping the host, or another user through the host"),
                 ("Status", "the network status"),
                 ("Help", "this list"),
                 ("Quit", "log out")]


def command(sess, line, out=print):
    """one line typed after Command: . Returns False when the user quits"""
    parts = line.split()
    if not parts:
        return True
    c = parts[0].lower()
    if c in ("listusers", "list", "users"):
        rows = sess.list_users()
        if rows is None:
            out("The host does not answer. Quit and connect again." if sess.lost else "Request timed out.")
        else:
            out("\n" + dotted(sess.host_addr))
            for x in table_lines(rows):
                out(x)
    elif c == "ping":
        target, count = None, 4
        for p in parts[1:]:
            if p.isdigit():
                count = max(1, min(int(p), 50))
            else:
                target = p
        if target is None:
            addr = sess.host_addr
        else:
            rows = sess.list_users() or []
            hit = next((r for r in rows if r[3].lower() == target.lower()), None)
            if hit is None:
                out("Ping request could not find that host. Please check the name and try again.")
                return True
            addr = hit[2]
        print_ping(sess, addr, count, out=out)
    elif c == "status":
        for x in status_banner(not sess.lost):
            out(x)
    elif c in ("help", "?"):
        for k, d in HELP_COMMANDS:
            out("   %-18s %s" % (k, d))
    elif c in ("quit", "exit", "logout"):
        return False
    else:
        out("%s is not a command. Type Help." % parts[0])
    return True


def ask_name():
    try:
        name = input("Username:").strip()
    except EOFError:
        name = ""
    if not name:
        raise ValueError("a nickname is needed: --name NAME")
    return name


def host_main(args):
    need_crypto()
    bind = (args.bind or "").split("%")[0]
    fam = socket.AF_INET if args.v4 or (bind and ":" not in bind) else socket.AF_INET6
    name = args.name or ask_name()
    node = HostNode(name, parse_addr(ME_HOST))
    banner("HOST")
    local_view(node, args.port, fam)
    s = socket.socket(fam, socket.SOCK_DGRAM)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    host = args.bind or ("::" if fam == socket.AF_INET6 else "0.0.0.0")
    try:
        s.bind((host, args.port))
    except OSError as e:
        print("\n$ cannot bind udp/%d: %s" % (args.port, e))
        return 1
    s.settimeout(1)
    adapter("Adapter UDP%s" % ("6" if fam == socket.AF_INET6 else "4"))
    if not (fam == socket.AF_INET6 and HIDE6):
        kv("Bound", "[%s]:%d" % (host, args.port) if fam == socket.AF_INET6 else "%s:%d" % (host, args.port))
        kv("Reply Source", args.bind or "the OS chooses")
        status("without --bind the OS picks the source of each answer, and on ipv6 that can be a temporary address "
               "other than the one the user sent to: a stateful firewall drops it. --bind a stable address to prevent that")
    kv("Key", "0")
    status("this test version has no key: the frames are sealed with a public key, so they hide nothing and anyone can join")
    kv("Strangers", "ACCEPT")
    kv("Login", "NICKNAME")
    kv("ADMIN", dotted(node.me))
    kv("Stop", "Ctrl+C")
    print("\nWaiting for logins on UDP %d:" % args.port)

    def send(wire, dest):
        try:
            s.sendto(wire, dest)
        except OSError:
            pass
    try:
        while True:
            try:
                data, src = s.recvfrom(4096)
                node.handle(data, src, send)
            except (socket.timeout, ConnectionResetError):
                pass
            for rec in node.dir.sweep(time.time()):
                print("Timed out: %s" % dotted(rec["addr"]))
    except KeyboardInterrupt:
        print("Control-C")
    adapter("Host totals")
    st = node.st
    for k, v in (("Logins", st["logins"]), ("Denied", st["denied"]), ("Answered", st["echo"]),
                 ("Forwarded", st["forwarded"]), ("Not Logged In", st["nologin"]), ("FIX Sent", st["fix"]),
                 ("Strangers", st["strangers"]), ("Failed Open", st["bad"]), ("Ignored", st["ignored"])):
        kv(k, "%d" % v)
    print("\n$ stopped")
    return 0


def connect_main(args):
    need_crypto()
    name = args.name or ask_name()
    try:
        sess = Session(args.host, args.port, name, socket.AF_INET if args.v4 else socket.AF_UNSPEC)
    except socket.gaierror as e:
        print("\n$ cannot resolve %s: %s" % (args.host, e))
        print(EXIT_LINE)
        return 1
    kind, why = sess.login()
    if kind != "ok":
        sess.close(bye=False)
        for x in status_banner(False):
            print(x)
        print("\n$ login %s: %s" % (kind, why))
        print(EXIT_LINE)
        return 1
    for x in status_banner(True):
        print(x)
    adapter("Adapter UDP%s" % ("6" if sess.af == socket.AF_INET6 else "4"))
    if not hidden(sess.sa[0]):
        kv("Carrier Endpoint", fmt_src(sess.sa))
    kv("Key", "0")
    status("this test version has no key: the frames are sealed with a public key, so they hide nothing")
    kv("Login", "Yes")
    adapter("TP/IX Adapter")
    kv("TP/IX Address", dotted(sess.me))
    kv("Host", dotted(sess.host_addr))
    print("\nLogin Accepted! Welcome: %s\n" % dotted(sess.me))
    for x in PRIVATE_BOX:
        print(x)
    print()
    try:
        while True:
            try:
                line = input("Command:")
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not command(sess, line):
                break
            print()
    finally:
        sess.close()
    print(EXIT_LINE)
    return 0




# ---- selftest ---------------------------------------------------------------------------------------------

def selftest():
    n = bad = 0

    def check(name, ok):
        nonlocal n, bad
        n += 1
        bad += 0 if ok else 1
        print("%-4s %s" % ("PASS" if ok else "FAIL", name))

    # addressing
    check("192.42.95.15 -> 192.0.0.192.42.95.1.15", dotted(v4to7([192, 42, 95, 15])) == "192.0.0.192.42.95.1.15")
    check("127.0.0.1 -> 192.0.0.127.0.0.1.1", dotted(v4to7([127, 0, 0, 1])) == "192.0.0.127.0.0.1.1")
    check("v7 -> v4 back", v7to4(parse_addr("192.0.0.192.42.95.1.15")) == [192, 42, 95, 15])
    check("SUB 2 is not plain ipv4", v7to4(parse_addr("192.0.0.172.16.0.2.2")) is None)
    check("parse_addr rejects 7 numbers and 300", all(_raises(lambda x=x: parse_addr(x)) for x in ("1.2.3.4.5.6.7", "1.2.3.300")))

    # the display
    import contextlib as _cl
    import io as _io2
    buf = _io2.StringIO()
    with _cl.redirect_stdout(buf):
        kv("TP/IX Address", "x")
        kv("Mapped IPv4 Address", "y")
        kv("Media State", "z")
        more("w")
    rows = buf.getvalue().splitlines()
    check("ipconfig style: every ' : ' sits in the same column", len({r.index(" : ") for r in rows[:3]}) == 1 and rows[0].startswith("   TP/IX Address . ."))
    check("ipconfig style: a second value lines up under the first", rows[3].endswith("w") and rows[3].index("w") == rows[0].index(" : ") + 3)
    hl = help_lines()
    check("help fits the screen, has no border, lists every option", all(len(x) <= W for x in hl) and not any(x.startswith(("+", "|")) for x in hl)
          and all(o in " ".join(hl) for o in ("--host", "--connect", "--name", "--bind", "--status", "--help")))
    import contextlib
    cap = io.StringIO()
    with contextlib.redirect_stdout(cap):
        local_view(Node("display only, not a key", "r", parse_addr(ME_RECEIVE), out=lambda *_: None), PORT, socket.AF_INET6)
    shown = cap.getvalue()
    check("the polynomial address and taps are always shown, the algebra only with --status",
          "176.0.0.0.0.0.0.1" in shown and "64.63.61.60.0" in shown and "x^64" not in shown and "Self-check" not in shown)
    global STATUS
    STATUS = True
    cap = io.StringIO()
    with contextlib.redirect_stdout(cap):
        local_view(Node("display only, not a key", "r", parse_addr(ME_RECEIVE), out=lambda *_: None), PORT, socket.AF_INET6)
    STATUS = False
    check("--status adds the algebra and the self-check", "x^64+x^63+x^61+x^60+1" in cap.getvalue() and "Self-check" in cap.getvalue())
    check("the screen carries no parentheses without --status", "(" not in shown and ")" not in shown)
    src_text = open(__file__, encoding="utf-8").read()
    check("no colour codes: no escape character and no SGR sequence in the source", chr(27) not in src_text and ("\\" + "x1b[") not in src_text)
    check("same_host reads zero compression", same_host(("2345:0:0:0:0:0:0:1", 1), ("2345::1", 2)) and not same_host(("2345::1", 1), ("2345::2", 1)))
    ps = ping_stats("192.0.0.1.2.3.4.5", 4, 3, [1.0, 2.0, 3.0])
    check("ping stats read like Windows ping", ps[1] == "    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),"
          and ps[3] == "    Minimum = 1ms, Maximum = 3ms, Average = 2ms")
    check("reply line reads like Windows ping", reply_line("192.0.0.172.16.0.2.2", 32, 2.4, 64) == "Reply from 192.0.0.172.16.0.2.2: bytes=32 time=2ms TTL=64"
          and "time<1ms" in reply_line("x", 32, 0.2, 64))
    check("ping stats: all lost has no rtt line", len(ping_stats("x", 2, 0, [])) == 2 and "100% loss" in ping_stats("x", 2, 0, [])[1])
    rt = receiver_totals({"strangers": 2, "declined": 4, "bad": 1, "ignored": 0, "echo": 5, "fix": 3})
    check("receiver totals carry the counters", [v.split()[0] for _, v in rt] == ["5", "3", "2", "4", "1", "0"])
    tn = Node("totals test passphrase", "r", parse_addr(ME_RECEIVE), out=lambda *_: None)
    tn.on_datagram(b"\x00" * 40, ("127.0.0.1", 9))
    check("a stranger frame is counted and answered with silence", tn.st["strangers"] == 1 and tn.st["echo"] == 0)

    # one replay window per sender, so several peers can share a key
    wb = WindowBook()
    ca, cb = (7 << 48) | 1000, (9 << 48) | 5
    ok1 = wb.check(ca); wb.commit(ca)
    ok2 = wb.check(cb); wb.commit(cb)
    check("window book: two senders interleave, a replay in either is refused",
          ok1 and ok2 and not wb.check(ca) and not wb.check(cb) and wb.check(ca + 1) and wb.check((7 << 48) | 999))
    wb2 = WindowBook(cap=3)
    for k in range(5):
        wb2.commit((k << 48) | 1)
    check("window book keeps only the newest senders", len(wb2.w) == 3)
    cn = Node("counter test passphrase", "c", parse_addr(ME_CONNECT), out=lambda *_: None)
    cs = [cn.ctr() for _ in range(2000)]
    check("counter: strictly increasing, sender id on top, no reuse", all(b > a for a, b in zip(cs, cs[1:])) and len({c >> 48 for c in cs}) == 1)
    check("counter: 40 bit milliseconds since 2026 fit", ((int(time.time() * 1000) - EPOCH_MS) << 8) < (1 << 48))
    check("time text", time_text(0) == "time<1ms" and time_text(-30) == "time<1ms" and time_text(2) == "time=2ms" and time_text(9000) == "time=?")
    # DECLINE holds the receiver for the first peer, ACCEPT lets a second one in
    ra = Node("join test passphrase", "r", parse_addr(ME_RECEIVE), out=lambda *_: None)
    rb = Node("join test passphrase", "r", parse_addr(ME_RECEIVE), out=lambda *_: None, accept=True)
    p1 = Node("join test passphrase", "c", parse_addr(ME_CONNECT), out=lambda *_: None)
    p2 = Node("join test passphrase", "c", parse_addr(ME_CONNECT), out=lambda *_: None)
    w1, _ = p1.ping(parse_addr(ME_RECEIVE), 1, 8)
    w2, _ = p2.ping(parse_addr(ME_RECEIVE), 1, 8)
    got = [ra.on_datagram(w1, ("198.51.100.1", 4000)), ra.on_datagram(w2, ("198.51.100.2", 4000)),
           ra.on_datagram(p1.ping(parse_addr(ME_RECEIVE), 2, 8)[0], ("198.51.100.1", 4001))]
    check("DECLINE: the first peer is served, a second host gets silence, the first one's new port still works",
          got[0] is not None and got[1] is None and got[2] is not None and ra.st["declined"] == 1)
    got = [rb.on_datagram(w1, ("198.51.100.1", 4000)), rb.on_datagram(w2, ("198.51.100.2", 4000))]
    check("ACCEPT: two peers sharing one key are both served", got[0] is not None and got[1] is not None and rb.st["declined"] == 0)
    check("a replayed frame is still refused while ACCEPT is on", rb.on_datagram(w1, ("198.51.100.1", 4000)) is None and rb.st["bad"] == 1)
    global HIDE6
    HIDE6 = True
    lines = []
    hn = Node("hide test passphrase", "r", parse_addr(ME_RECEIVE), out=lines.append)
    hp = Node("hide test passphrase", "c", parse_addr(ME_CONNECT), out=lambda *_: None)
    hn.on_datagram(hp.ping(parse_addr(ME_RECEIVE), 1, 32)[0], ("2345:6789::5", 4000))
    HIDE6 = False
    check("--hide6: no ipv6 address in the receiver's lines", lines and not any("2345" in x or "[" in x for x in lines))
    cap = io.StringIO()
    with contextlib.redirect_stdout(cap):
        creator()
    check("--creator prints the logo, the line and the link", "Knowledge is free" in cap.getvalue() and "https://t.me/V3RDAD" in cap.getvalue() and "█" in cap.getvalue())
    cap = io.StringIO()
    with contextlib.redirect_stdout(cap):
        banner("RECEIVE")
    bl = [x for x in cap.getvalue().splitlines() if x.strip()]
    lead = len(bl[0]) - len(bl[0].lstrip())
    centred = all(abs((len(x) - len(x.lstrip())) + len(x.strip()) / 2.0 - (lead + BW / 2.0)) <= 1 for x in bl[1:-1])
    check("banner: 36 wide, bars on top and bottom, titles centred", bl[0].strip() == "#" * BW and bl[-1].strip() == "$" * BW and centred)

    # users: the directory, the packing, and a host with real sessions over loopback
    d = Directory("V3RDAD", parse_addr(ME_HOST))
    t0 = 1000.0
    k1, k2, k3 = ("198.51.100.1", 1), ("198.51.100.2", 1), ("198.51.100.3", 1)
    r1, r2 = d.login("alice", k1, t0), d.login("bob", k2, t0)
    check("directory: the host is .2.1, the users get .2.2 and .2.3",
          d.host_rec["addr"][6:] == [2, 1] and r1[1]["addr"][6:] == [2, 2] and r2[1]["addr"][6:] == [2, 3])
    check("directory: names are checked, ADMIN and the host's alias are taken",
          [d.login(n, k3, t0)[1] for n in ("", "a b", "x" * 17, "admin", "v3rdad")] == [1, 1, 1, 1, 2])
    check("directory: a name that is online elsewhere is refused, the same carrier may log in again",
          d.login("alice", k3, t0 + 1) == ("err", 2) and d.login("alice", k1, t0 + 1)[0] == "ok")
    check("directory: one carrier, one name", d.login("carol", k1, t0 + 2) == ("err", 5))
    check("directory: keepalives that stop turn a user offline", [x["name"] for x in d.sweep(t0 + 100)] == ["alice", "bob"])
    check("directory: a returning name keeps its address", d.login("alice", k3, t0 + 101)[1]["addr"][6:] == [2, 2])
    rows = d.rows(t0 + 101)
    check("directory: rows put the ADMIN first with the online flags", [x[0] for x in rows] == [ADMIN, USER, USER] and [x[1] for x in rows] == [True, True, False])
    check("directory: IPv7 is inactive for everyone while nobody is bound on Ethernet, the host included",
          [x[4] for x in rows] == [False, False, False])
    alice = d.users["alice"]
    check("users and welcome survive packing", unpack_users(pack_users(rows)) == rows
          and unpack_welcome(pack_welcome(r1[1], d.host_rec)) == (r1[1]["addr"], USER, d.host_rec["addr"], "V3RDAD"))
    tl = table_lines(rows)
    rows_all = rows + [(USER, True, [192, 0, 0, 172, 16, 0, 2, 9], "x" * 16, True)]
    check("table: no border, one width, the columns as pasted, names only in ALIAS",
          len(tl) == 4 and len({len(x) for x in tl}) == 1
          and tl[0] == "Rank   |  Connected?  |  Tree    |  ALIAS             |  iPv7      |"
          and tl[1] == "ADMIN  |  Yes         |  #2_1    |  V3RDAD            |  inactive  |"
          and tl[2].startswith("USER   |  Yes         |  #2_2    |  alice") and tl[2].endswith("|  inactive  |")
          and tl[3].startswith("USER   |  No          |  #2_3    |  bob"))
    starts = lambda x: [len(c) - len(c.lstrip()) for c in x.split("|")[:-1]]      # where each cell's text begins
    check("table: Rank has no left border, and every value starts under the first letter of its header",
          all(starts(x) == starts(tl[0]) == [0, 2, 2, 2, 2] for x in tl)
          and all(starts(x) == [0, 2, 2, 2, 2] for x in table_lines(rows_all)))
    d.set_eth(alice, True)
    rows_e = d.rows(t0 + 180)
    last = lambda x: x.strip().strip("|").split("|")[-1].strip()      # the last cell of a table line
    check("directory: a user moved to Ethernet is active, and it survives packing",
          [x[4] for x in rows_e] == [False, True, False] and unpack_users(pack_users(rows_e)) == rows_e
          and [last(x) for x in table_lines(rows_e)[1:4]] == ["inactive", "active", "inactive"])
    d.set_eth(d.host_rec, True)
    check("directory: the host is active when it is bound on Ethernet too", d.rows(t0 + 180)[0][4] is True)
    d.set_eth(d.host_rec, False)
    d.set_eth(alice, False)
    check("directory: back on UDP the user is inactive again, and a new login starts on UDP",
          not d.active(d.users["alice"]) and d.login("alice", k3, t0 + 200)[1]["eth"] is False)
    import collections
    cn = Node(TEST_KEY, "c", parse_addr("192.0.0.172.16.0.2.5"), out=lambda *_: None)
    got = [[] for _ in range(4)]

    def spin(i):
        for _ in range(20000):
            got[i].append(cn.ctr())
    sys.setswitchinterval(1e-6)
    ths = [threading.Thread(target=spin, args=(i,)) for i in range(4)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    sys.setswitchinterval(0.005)
    check("counter: four threads sealing at once never get the same frame counter (a repeat is a GCM nonce reuse)",
          len(collections.Counter(c for g in got for c in g)) == 80000)
    check("status banner: three lines, the middle one says ONLINE", len(status_banner()) == 3 and "######ONLINE#####" in status_banner()[1])

    hs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    hs.bind(("127.0.0.1", 0))
    hs.settimeout(0.2)
    host = HostNode("V3RDAD", parse_addr(ME_HOST), out=lambda *_: None)
    hstop = threading.Event()

    def hloop():
        while not hstop.is_set():
            try:
                data, src = hs.recvfrom(4096)
            except socket.timeout:
                continue
            host.handle(data, src, hs.sendto)
    hthread = threading.Thread(target=hloop, daemon=True)
    hthread.start()
    hp = hs.getsockname()[1]
    sa, sb, sc = (Session("127.0.0.1", hp, n, socket.AF_INET) for n in ("alice", "bob", "alice"))
    check("users: two sessions log in and get .2.2 and .2.3", (sa.login(), sb.login()) == (("ok", None), ("ok", None))
          and sa.me[6:] == [2, 2] and sb.me[6:] == [2, 3] and sa.host_name == "V3RDAD")
    check("users: a second alice is denied", sc.login() == ("denied", DENY[2]))
    sc.close()
    check("users: ListUsers shows the ADMIN, alice and bob online",
          [(x[0], x[1], x[3]) for x in sa.list_users()] == [(ADMIN, True, "V3RDAD"), (USER, True, "alice"), (USER, True, "bob")])
    check("users: the list carries IPv7 inactive for everyone while nobody is on Ethernet", [x[4] for x in sa.list_users()] == [False, False, False])
    host.dir.set_eth(host.dir.users["bob"], True)                    # bob moves to the Ethernet path
    got = sa.list_users()
    check("users: a user bound on Ethernet is listed as active over the wire", [(x[3], x[1], x[4]) for x in got] == [("V3RDAD", True, False), ("alice", True, False), ("bob", True, True)])
    logs = []
    host.out = logs.append                                           # the host's own log, to look for names in it
    res = sb.ping(sb.host_addr, 2, 32, 0.05)
    check("users: ping the host, TTL 64", len(res) == 2 and all(x["kind"] == "reply" and x["ttl"] == 64 and x["n"] == 32 for x in res))
    res = sb.ping(sa.me, 2, 32, 0.05)
    check("users: ping a user through the host, TTL 63 and the reply is from that user",
          len(res) == 2 and all(x["kind"] == "reply" and x["ttl"] == 63 and x["src"] == sa.me for x in res))
    check("users: the host relayed 4 frames and alice answered 2", host.st["forwarded"] == 4 and sa.answered == 2)
    res = sb.ping(parse_addr("192.0.0.172.16.0.2.99"), 1, 32, 0.05)
    check("users: an address nobody has gives FIX, destination host unreachable", res[0]["kind"] == "fix" and res[0]["fix"] == parse_addr(ME_HOST))
    sd = Session("127.0.0.1", hp, "carol", socket.AF_INET)
    sd.login()
    sd.close()                                                       # a login and a logout, for the host's log
    time.sleep(0.3)
    host.out = lambda *_: None
    check("host log: it shows TP/IX addresses and no name at all", len(logs) > 5
          and not any(n in " ".join(logs) for n in ("alice", "bob", "carol", "V3RDAD")))
    lines = []
    command(sb, "Ping nobody", lines.append)
    check("terminal: an unknown name gets the Windows sentence, without the name", lines == ["Ping request could not find that host. Please check the name and try again."])
    lines = []
    command(sb, "Ping alice 1", lines.append)
    check("terminal: pinging a name prints only the TP/IX address", lines[0] == "\nPinging %s with 32 bytes of data:" % dotted(sa.me)
          and not any("alice" in x for x in lines))
    lines = []
    command(sb, "listusers", lines.append)
    check("terminal: ListUsers prints the table, no border, and it is the only place with names",
          len(lines) == 6 and lines[0] == "\n" + dotted(sb.host_addr) and lines[1].startswith("Rank   |  Connected?  |")
          and "alice" in lines[3] and lines[3].endswith("|"))
    check("terminal: Quit ends the session, a blank line does nothing", command(sb, "quit") is False and command(sb, "   ") is True)
    stranger = Node(TEST_KEY, "c", parse_addr("192.0.0.172.16.0.2.77"), out=lambda *_: None)
    cl2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cl2.settimeout(1)
    cl2.sendto(stranger.ping(parse_addr(ME_HOST), 1, 8)[0], ("127.0.0.1", hp))
    got = stranger.open(cl2.recvfrom(4096)[0], "x")
    check("users: a frame without a login is told to log in first", got is not None and got["proto"] == OP_DENIED and got["payload"][0] == 4)
    cl2.close()
    sb.close()
    time.sleep(0.3)
    check("users: after Bye the user shows offline", [(x[3], x[1]) for x in sa.list_users()] == [("V3RDAD", True), ("alice", True), ("bob", False), ("carol", False)])
    sa.close()
    hstop.set()
    hthread.join(1)
    hs.close()

    # the terminal's own bytes (node, from IPv7_INET.js n7wire for 192.42.95.15)
    hdr = bytes.fromhex("70090400000000340000000000000000c00000c02a5f010fc00000c02a5f010f0001b363")
    icmp = bytes.fromhex("0800074d495000014950763774657374")
    a = v4to7([192, 42, 95, 15])
    check("icmp echo == the terminal's bytes", icmp_build(8, 0x4950, 1, b"IPv7test") == icmp)
    check("tp/ix header == the terminal's bytes", tpix_build(a, a, icmp) == hdr + icmp)
    p = tpix_parse(hdr + icmp)
    check("tp/ix parse", "err" not in p and p["ttl"] == 64 and p["dst"] == a and p["proto"] == 1 and p["csum"] == 0xB363)
    bad_ck = bytearray(hdr + icmp)
    bad_ck[20] ^= 1
    check("tp/ix bad checksum rejected", "err" in tpix_parse(bytes(bad_ck)))
    check("tp/ix bad length rejected", "err" in tpix_parse(hdr + icmp + b"x"))
    check("icmp parse + bad checksum", icmp_parse(icmp)["seq"] == 1 and "err" in icmp_parse(icmp[:-1] + b"u"))

    # lfsr, against the terminal's values
    s = 0x0123456789ABCDEF
    check("lfsr jump 9      == terminal", lfsr_jump(s, 9) == 0x968acf13579bde03)
    check("lfsr jump 1e6    == terminal", lfsr_jump(s, 1000000) == 0x273a648ea9a9ce94)
    check("lfsr shl8        == terminal", lfsr_shl8(s) == 0x93456789abcdef01)
    check("lfsr shr8        == terminal", lfsr_shr8(s) == 0x8b9123456789abcd)
    check("shl8 == 8 steps == jump(8)", lfsr_shl8(s) == _eight(s) == lfsr_jump(s, 8))
    check("shr8(shl8(x)) == x", all(lfsr_shr8(lfsr_shl8(x)) == x for x in (1, s, (1 << 64) - 1, 0x8000000000000000)))
    check("unstep(step(x)) == x", all(lfsr_unstep(lfsr_step(x)) == x for x in (1, s, (1 << 64) - 1)))
    now, seed = 1_800_000_000, 0xDEADBEEF12345678
    check("drift +7 / -3 / 0", [find_drift(seed, lfsr_jump(seed, now + d), now) for d in (7, -3, 0)] == [7, -3, 0])
    check("drift out of range is None", find_drift(seed, lfsr_jump(seed, now + 500), now, 100) is None)

    # replay window
    w = Window(2048)
    ok = w.check(5)
    w.commit(5)
    check("window: new ok, replay refused", ok and not w.check(5) and w.check(4) and w.check(6))
    w.commit(6 + (1 << 55))
    check("window: a jump of 2^55 stays small and old ones are gone", w.bm == 1 and not w.check(5) and w.check(7 + (1 << 55)))

    if not HAVE_CRYPTO:
        print("SKIP aes / aa / network checks: pip install cryptography")
    else:
        e = AESGCM(bytes(16)).encrypt(bytes(12), b"", None)
        check("AES-GCM known answer (spec test case 1)", e.hex() == "58e2fccefa7e3061367f1d57a4e7455a")
        c = Cipher(algorithms.AES(bytes(range(16))), modes.ECB()).encryptor()
        check("AES-128 known answer (FIPS-197)", (c.update(bytes.fromhex("00112233445566778899aabbccddeeff")) + c.finalize()).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a")
        keys = Keys(bytes((i * 7 + 3) & 255 for i in range(32)))
        w0 = aa_seal(keys, bytes([0x5E, 0x1F, 0x7A, 1]), 1, 0, 0, b"")
        w1 = aa_seal(keys, bytes([1, 2, 3, 4]), 2, 0, 0, bytes(range(36)), xa=bytes([1, 2, 3, 4, 5, 6, 7, 8]), hops=3)
        check("AA frame 1 byte-for-byte == the terminal's", w0.hex() == "5e1f7a0173fcb2ea03033e4b3305171bd283b2e3a10e99ca7011a0cc658d7c98")
        check("AA frame 2 (xa + hops) byte-for-byte == the terminal's", w1.hex() == "01020304e5182098b8ca2d964b87704ddcb81b2c8015e46c5016e9b128c2dc741162395bac350ae1f9a6cdd6d5b4b633b2f1759eaf109f70ebf69310d1f2bd8f063f8b5ed104a11eab77b6aec6")
        r = aa_open(keys, w1, Window())
        check("AA open reads xa, hops and payload", "err" not in r and r["xa"] == bytes(range(1, 9)) and r["hops"] == 3 and r["payload"] == bytes(range(36)))
        f = aa_seal(keys, b"\1\1\1\1", 3, 0, 0, b"hi", hops=1, extra=bytes([9, 8, 7, 6, 5, 4]), extra_flags=0x20)
        r = aa_open(keys, f)
        check("AA skips a newer node's unknown slot", "err" not in r and r["skipped"] == 6 and r["payload"] == b"hi")
        win = Window()
        a1, a2 = aa_open(keys, w1, win), aa_open(keys, w1, win)
        flip = bytearray(w1)
        flip[20] ^= 1
        check("AA replay / flipped bit / wrong key refused", "err" not in a1 and a2.get("err") == "replay"
              and aa_open(keys, bytes(flip)).get("err") == "tag" and aa_open(Keys(bytes(32)), w1).get("err") == "tag")

        # two nodes over real UDP on loopback
        a_node, b_node = Node("t-key", "r", parse_addr(ME_RECEIVE), out=lambda *_: None), Node("t-key", "c", parse_addr(ME_CONNECT), out=lambda *_: None)
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        srv.settimeout(0.3)
        port, stop = srv.getsockname()[1], threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    data, src = srv.recvfrom(4096)
                except socket.timeout:
                    continue
                rep = a_node.on_datagram(data, src)
                if rep:
                    srv.sendto(rep, src)
        t = threading.Thread(target=serve, daemon=True)
        t.start()
        cl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cl.settimeout(1)

        def ask(node, dst, seq=1, size=8):
            wire, _ = node.ping(dst, seq, size)
            cl.sendto(wire, ("127.0.0.1", port))
            try:
                return node.on_reply(cl.recvfrom(4096)[0])
            except socket.timeout:
                return None
        r = ask(b_node, parse_addr(ME_RECEIVE))
        check("udp: echo answered, ttl 64, clock in step", r is not None and r["m"]["seq"] == 1 and r["h"]["ttl"] == 64 and r["drift"] == 0)
        r = ask(b_node, parse_addr(ME_RECEIVE), 2, 1388)
        check("udp: a 1388 B payload fits one frame", r is not None and len(r["m"]["data"]) == 1388)
        r = ask(b_node, parse_addr("192.0.0.172.16.0.2.99"), 3)
        check("udp: wrong TP/IX address -> FIX 04 with the right one", r is not None and r.get("fix") == FIX_NOT_HERE and r["fix_addr"] == parse_addr(ME_RECEIVE))
        r = ask(b_node, [192, 0, 0, 127, 0, 0, 1, 1], 4)
        check("udp: loopback TP/IX is accepted as mine", r is not None and "m" in r)
        cl.sendto(b"GET / HTTP/1.1\r\n\r\n", ("127.0.0.1", port))
        stranger = Node("other-key", "c", parse_addr(ME_CONNECT), out=lambda *_: None)
        wire, _ = stranger.ping(parse_addr(ME_RECEIVE), 1, 8)
        cl.sendto(wire, ("127.0.0.1", port))
        try:
            cl.recvfrom(4096)
            quiet = False
        except socket.timeout:
            quiet = True
        check("udp: strangers (junk, wrong key) get silence", quiet)
        wire, _ = b_node.ping(parse_addr(ME_RECEIVE), 9, 8)
        cl.sendto(wire, ("127.0.0.1", port))
        cl.recvfrom(4096)
        cl.sendto(wire, ("127.0.0.1", port))
        try:
            cl.recvfrom(4096)
            quiet = False
        except socket.timeout:
            quiet = True
        check("udp: a replayed frame gets silence", quiet)
        stop.set()
        t.join(1)
    # --- hardening: the runtime Command: prompt is a closed allowlist. A user (or anyone who
    # gets hold of the client) should not be able to type their way into a hidden logging or
    # debug command: anything not on the documented list must be refused the same way as any
    # other typo, never silently accepted.
    class _DummySess:
        lost = False

        def list_users(self):
            return []
    import contextlib as _cl3
    import io as _io3
    out_lines = []
    for word in ("log", "debug", "verbose", "trace", "showlog", "getlog", "setlog", "loglevel"):
        buf = _io3.StringIO()
        with _cl3.redirect_stdout(buf):
            keep_going = command(_DummySess(), word, out=print)
        out_lines.append((word, buf.getvalue()))
    check("a logging/debug-style word typed at Command: is refused like any unknown command",
          all("is not a command" in txt for _, txt in out_lines) and keep_going is True)
    buf = _io3.StringIO()
    with _cl3.redirect_stdout(buf):
        command(_DummySess(), "help", out=print)
    import re as _re2
    scrubbed = _re2.sub(r"log(ging|ged)?\s*(in|out)?", "", buf.getvalue().lower())
    check("Help itself never hints at a logging or debug command (beyond 'log in'/'log out')",
          not any(w in scrubbed for w in ("log", "debug", "verbose", "trace")))

    print("\n%d checks, %d failed" % (n, bad))
    return 1 if bad else 0


def _raises(f):
    try:
        f()
    except ValueError:
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description="IPv7 users: nicknames over TP/IX, a test version", add_help=False)
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--hide6", action="store_true")
    ap.add_argument("--creator", action="store_true")
    ap.add_argument("--host", nargs="?", const=PORT, type=int, metavar="PORT")
    ap.add_argument("--connect", nargs="+", metavar=("HOST", "PORT"))
    ap.add_argument("--name")
    ap.add_argument("--bind")
    ap.add_argument("-4", dest="v4", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    global STATUS, HIDE6
    STATUS, HIDE6 = args.status, args.hide6
    try:
        if args.help:
            for line in help_lines():
                print(line)
            return 0
        if args.creator:
            return creator()
        if args.selftest:
            return selftest()
        if args.host is not None:
            args.port = args.host
            return host_main(args)
        if args.connect:
            args.host, args.port = args.connect[0], int(args.connect[1]) if len(args.connect) > 1 else PORT
            return connect_main(args)
        node = Node("display only, not a key", "r", parse_addr(ME_HOST)) if HAVE_CRYPTO else None
        banner("[TP/IX]")
        if node:
            local_view(node, PORT, socket.AF_INET6)
        else:
            print("$ pip install cryptography   needed for --host and --connect")
        return 0
    except ValueError as e:
        print("$ %s" % e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
