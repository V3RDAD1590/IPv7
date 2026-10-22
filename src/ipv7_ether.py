#!/usr/bin/env python3
"""ipv7_ether.py: the raw Ethernet carrier for IPv7, through Npcap (spec sections 12, 12a, 18).

    python ipv7_ether.py --devices              list the network devices Npcap can open
    python ipv7_ether.py --selftest             checks with no network (and, on Linux as root,
                                                real frames over the loopback device)

What it is: a second path for a session that already exists. The session frame (the "AA" frame,
sealed, with its own label and counter) is put in an Ethernet frame and sent to one link address.
Nothing here makes keys or opens a session: the bind runs over UDP only (section 12 item 11).

Ethernet frame on the wire:
    dst 6 | src 6 | EtherType 2 | length 2 | AA frame | random fill to the 60 B minimum
The 2-byte length is needed because Ethernet pads short frames and an AA frame has no length of
its own. The fill is random bytes, never zeros. The EtherType defaults to 0x88B6.

Rules the carrier enforces (section 18):
  - unicast only: a destination or source with the multicast bit set, which includes the
    broadcast address, is refused on send and dropped on receive;
  - frames from our own link address, to another address, of another EtherType, or too short,
    are dropped and counted;
  - the AA frame is at most 1498 B.

Npcap is installed by the user and is never bundled or installed by this program. It is loaded
at run time from C:\\Windows\\System32\\Npcap, so nothing extra is needed to build an exe.
Without Npcap, `npcap_present()` is False and the program keeps working over UDP only.

This is an unaudited prototype: it should not protect anyone whose safety depends on it.
"""
import argparse
import ctypes
import ctypes.util
import os
import socket
import struct
import subprocess
import sys
import threading
import time

MARK_STEP, MARK_OK, MARK_BAD = "|_", "*_", "-_"

DEFAULT_ETHERTYPE = 0x88B6
PRESET_ETHERTYPES = (0x88B5, 0x88B6)           # IEEE local experimental 1 and 2
XTTP_ETHERTYPE = 0x88B5
WELL_KNOWN = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN", 0x88A8: "VLAN",
              0x8847: "MPLS", 0x8848: "MPLS", 0x88CC: "LLDP", 0x88E5: "MACsec",
              0x8809: "slow protocols", 0x88F7: "PTP", 0x8863: "PPPoE", 0x8864: "PPPoE",
              0x888E: "802.1X", 0x22F0: "AVB"}
HEAD = 16                                       # dst 6 | src 6 | type 2 | length 2
MIN_FRAME = 60                                  # without the FCS
MTU = 1500
MAX_AA = MTU - 2                                # 1498
MIN_AA = 34                                     # label 10 + counter 8 + tag 16


class CarrierError(Exception):
    pass


class NpcapMissing(CarrierError):
    pass


# ---------------------------------------------------------------- EtherType and link addresses
def check_ethertype(value):
    """-> (ok, message). A custom value is refused below 0x0600 and for well-known types.
    A value equal to the XTTP one is allowed with a warning."""
    if not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        return False, "an EtherType is a number from 0 to 65535"
    if value < 0x0600:
        return False, "0x%04X is below 0x0600: those numbers are 802.3 lengths" % value
    if value in WELL_KNOWN:
        return False, "0x%04X is %s: pick another number" % (value, WELL_KNOWN[value])
    if value == XTTP_ETHERTYPE:
        return True, "0x%04X is also used by XTTP" % value
    return True, ""


def parse_ethertype(text):
    """'0x88B6', '88b6' or 'default' -> int. Raises CarrierError when it is not allowed."""
    t = text.strip().lower()
    if t in ("", "default"):
        return DEFAULT_ETHERTYPE
    try:
        v = int(t, 16)
    except ValueError:
        raise CarrierError("not a number: %r" % text)
    ok, msg = check_ethertype(v)
    if not ok:
        raise CarrierError(msg)
    return v


def parse_mac(text):
    p = text.replace("-", ":").split(":")
    if len(p) != 6 or any(len(x) != 2 for x in p):
        raise CarrierError("a link address looks like 02:00:5E:10:20:30")
    try:
        return bytes(int(x, 16) for x in p)
    except ValueError:
        raise CarrierError("a link address looks like 02:00:5E:10:20:30")


def fmt_mac(b):
    return ":".join("%02X" % x for x in b)


def is_multicast_mac(b):
    """Group bit set: multicast and broadcast. Never used by this carrier."""
    return bool(b[0] & 1)


def random_mac():
    """A random locally administered unicast address (section 12 item 9)."""
    b = bytearray(os.urandom(6))
    b[0] = (b[0] & 0xFE) | 0x02
    return bytes(b)


def link_address(policy, real=None):
    """policy 'random' (default), 'real' (needs the adapter's own address) or an explicit address.
    A random source address usually works on wired and virtual links; a Wi-Fi access point
    normally drops frames from an address that did not associate, so use 'real' there."""
    p = (policy or "random").strip().lower()
    if p == "random":
        return random_mac()
    if p == "real":
        if real is None or len(real) != 6:
            raise CarrierError("the adapter's own link address is not known")
        return bytes(real)
    m = parse_mac(policy)
    if is_multicast_mac(m):
        raise CarrierError("a link address cannot be a multicast or broadcast address")
    return m


# ---------------------------------------------------------------- the frame
def build_frame(dst, src, ethertype, aa, fill=os.urandom):
    if is_multicast_mac(dst):
        raise CarrierError("unicast only: %s is a multicast or broadcast address" % fmt_mac(dst))
    if is_multicast_mac(src):
        raise CarrierError("the source link address cannot be a multicast address")
    if len(dst) != 6 or len(src) != 6:
        raise CarrierError("link addresses are 6 bytes")
    if not MIN_AA <= len(aa) <= MAX_AA:
        raise CarrierError("an AA frame here is %d to %d bytes, got %d" % (MIN_AA, MAX_AA, len(aa)))
    f = dst + src + struct.pack(">HH", ethertype, len(aa)) + aa
    if len(f) < MIN_FRAME:
        f += fill(MIN_FRAME - len(f))
    return f


def parse_frame(frame, mac, ethertype):
    """-> (source link address, AA frame) or (None, reason). `mac` is our own address."""
    if len(frame) < HEAD + MIN_AA:
        return None, "short"
    dst, src = frame[:6], frame[6:12]
    et, n = struct.unpack(">HH", frame[12:16])
    if et != ethertype:
        return None, "type"
    if dst != mac:
        return None, "dst"                       # includes broadcast and multicast
    if is_multicast_mac(src):
        return None, "multicast"
    if src == mac:
        return None, "own"
    if not MIN_AA <= n <= MAX_AA or n > len(frame) - HEAD:
        return None, "length"
    return src, frame[HEAD:HEAD + n]


# ---------------------------------------------------------------- Npcap through ctypes
class _timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _pkthdr(ctypes.Structure):
    _fields_ = [("ts", _timeval), ("caplen", ctypes.c_uint32), ("len", ctypes.c_uint32)]


class _bpf_program(ctypes.Structure):
    _fields_ = [("bf_len", ctypes.c_uint), ("bf_insns", ctypes.c_void_p)]


class _pcap_if(ctypes.Structure):
    pass


_pcap_if._fields_ = [("next", ctypes.POINTER(_pcap_if)), ("name", ctypes.c_char_p),
                     ("description", ctypes.c_char_p), ("addresses", ctypes.c_void_p),
                     ("flags", ctypes.c_uint32)]


def load_pcap():
    """Open Npcap's wpcap.dll (Windows) or libpcap (elsewhere, for tests). Raises NpcapMissing."""
    try:
        if os.name == "nt":
            root = os.environ.get("SystemRoot", r"C:\Windows")
            d = os.path.join(root, "System32", "Npcap")
            if os.path.isdir(d):
                if hasattr(os, "add_dll_directory"):
                    os.add_dll_directory(d)
                return _bind_pcap(ctypes.CDLL(os.path.join(d, "wpcap.dll")))
            return _bind_pcap(ctypes.CDLL("wpcap.dll"))
        name = ctypes.util.find_library("pcap")
        if not name:
            raise OSError("libpcap not found")
        return _bind_pcap(ctypes.CDLL(name))
    except OSError as e:
        raise NpcapMissing("Npcap was not found (%s). Install it yourself from npcap.com; "
                           "IPv7 keeps working over UDP without it." % e)


def _bind_pcap(lib):
    c = ctypes
    lib.pcap_open_live.argtypes = [c.c_char_p, c.c_int, c.c_int, c.c_int, c.c_char_p]
    lib.pcap_open_live.restype = c.c_void_p
    lib.pcap_close.argtypes = [c.c_void_p]
    lib.pcap_close.restype = None
    lib.pcap_sendpacket.argtypes = [c.c_void_p, c.c_char_p, c.c_int]
    lib.pcap_sendpacket.restype = c.c_int
    lib.pcap_next_ex.argtypes = [c.c_void_p, c.POINTER(c.POINTER(_pkthdr)),
                                 c.POINTER(c.POINTER(c.c_ubyte))]
    lib.pcap_next_ex.restype = c.c_int
    lib.pcap_compile.argtypes = [c.c_void_p, c.POINTER(_bpf_program), c.c_char_p, c.c_int,
                                 c.c_uint32]
    lib.pcap_compile.restype = c.c_int
    lib.pcap_setfilter.argtypes = [c.c_void_p, c.POINTER(_bpf_program)]
    lib.pcap_setfilter.restype = c.c_int
    lib.pcap_freecode.argtypes = [c.POINTER(_bpf_program)]
    lib.pcap_freecode.restype = None
    lib.pcap_geterr.argtypes = [c.c_void_p]
    lib.pcap_geterr.restype = c.c_char_p
    lib.pcap_datalink.argtypes = [c.c_void_p]
    lib.pcap_datalink.restype = c.c_int
    lib.pcap_findalldevs.argtypes = [c.POINTER(c.POINTER(_pcap_if)), c.c_char_p]
    lib.pcap_findalldevs.restype = c.c_int
    lib.pcap_freealldevs.argtypes = [c.POINTER(_pcap_if)]
    lib.pcap_freealldevs.restype = None
    try:
        lib.pcap_setdirection.argtypes = [c.c_void_p, c.c_int]
        lib.pcap_setdirection.restype = c.c_int
    except AttributeError:
        pass                                                   # optional: software filter covers it
    return lib


def npcap_present():
    try:
        load_pcap()
        return True
    except NpcapMissing:
        return False


def pcap_devices(lib=None):
    """-> list of (device name, description)."""
    lib = lib or load_pcap()
    err = ctypes.create_string_buffer(256)
    head = ctypes.POINTER(_pcap_if)()
    if lib.pcap_findalldevs(ctypes.byref(head), err) != 0:
        raise CarrierError("could not list devices: %s" % err.value.decode(errors="replace"))
    out, p = [], head
    while p:
        d = p.contents
        out.append(((d.name or b"").decode(errors="replace"),
                    (d.description or b"").decode(errors="replace")))
        p = d.next
    if head:
        lib.pcap_freealldevs(head)
    return out


class PcapBackend:
    """Sends and receives whole Ethernet frames on one device through Npcap or libpcap."""

    SNAPLEN, TIMEOUT_MS = 2048, 50

    def __init__(self, device, mac, ethertype, lib=None):
        self.lib = lib or load_pcap()
        err = ctypes.create_string_buffer(256)
        # promiscuous mode on: frames for a link address the adapter does not own must reach us
        self.h = self.lib.pcap_open_live(device.encode(), self.SNAPLEN, 1, self.TIMEOUT_MS, err)
        if not self.h:
            raise CarrierError("could not open %s: %s" % (device, err.value.decode(errors="replace")))
        self.closed = False
        self.send_lock = threading.Lock()
        if self.lib.pcap_datalink(self.h) != 1:
            self.close()
            raise CarrierError("%s is not an Ethernet device" % device)
        if hasattr(self.lib, "pcap_setdirection"):
            self.lib.pcap_setdirection(self.h, 1)               # incoming only; ignore a failure
        prog = _bpf_program()
        expr = ("ether proto 0x%04x and ether dst %s" % (ethertype, fmt_mac(mac).lower())).encode()
        if self.lib.pcap_compile(self.h, ctypes.byref(prog), expr, 1, 0xFFFFFFFF) != 0 \
                or self.lib.pcap_setfilter(self.h, ctypes.byref(prog)) != 0:
            msg = self.lib.pcap_geterr(self.h)
            self.close()
            raise CarrierError("could not set the filter: %s" % (msg or b"").decode(errors="replace"))
        self.lib.pcap_freecode(ctypes.byref(prog))
        self.filter = expr.decode()

    def send(self, frame):
        with self.send_lock:
            if self.closed:
                raise CarrierError("closed")
            if self.lib.pcap_sendpacket(self.h, bytes(frame), len(frame)) != 0:
                raise CarrierError("send failed: %s" % (self.lib.pcap_geterr(self.h) or b"").decode(errors="replace"))

    def recv(self, timeout=0.1):
        end = time.time() + timeout
        hdr = ctypes.POINTER(_pkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        while not self.closed:
            r = self.lib.pcap_next_ex(self.h, ctypes.byref(hdr), ctypes.byref(data))
            if r == 1:
                return ctypes.string_at(data, hdr.contents.caplen)
            if r < 0:
                raise CarrierError("receive failed: %s" % (self.lib.pcap_geterr(self.h) or b"").decode(errors="replace"))
            if time.time() >= end:
                return None
        return None

    def close(self):
        """Stop the receiving thread first, then close."""
        if not self.closed:
            self.closed = True
            self.lib.pcap_close(self.h)


class PacketSocketBackend:
    """Linux only (AF_PACKET). Used by the tests and on Linux; the same interface as PcapBackend."""

    def __init__(self, ifname, mac, ethertype):
        if not hasattr(socket, "AF_PACKET"):
            raise CarrierError("packet sockets exist only on Linux")
        try:
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype))
            self.s.bind((ifname, ethertype))
        except PermissionError:
            raise CarrierError("raw sockets need root")
        self.closed = False

    def send(self, frame):
        self.s.send(frame)

    def recv(self, timeout=0.1):
        self.s.settimeout(timeout)
        while True:
            try:
                data, addr = self.s.recvfrom(4096)
            except (socket.timeout, BlockingIOError):
                return None
            except OSError:
                return None
            if addr[2] == socket.PACKET_OUTGOING:
                continue                                    # our own copy
            return data

    def close(self):
        if not self.closed:
            self.closed = True
            self.s.close()


# ---------------------------------------------------------------- the carrier
class EtherCarrier:
    """AA frames in, AA frames out, over one Ethernet device. Thread safe for one sender thread
    and one receiver thread. The session counter lives in the session, not here."""

    def __init__(self, backend, mac, ethertype=DEFAULT_ETHERTYPE):
        ok, msg = check_ethertype(ethertype)
        if not ok:
            raise CarrierError(msg)
        if len(mac) != 6 or is_multicast_mac(mac):
            raise CarrierError("our link address must be a 6-byte unicast address")
        self.backend, self.mac, self.ethertype = backend, bytes(mac), ethertype
        self.stats = {"sent": 0, "received": 0, "short": 0, "type": 0, "dst": 0, "multicast": 0,
                      "own": 0, "length": 0}

    def send(self, dst, aa):
        self.backend.send(build_frame(dst, self.mac, self.ethertype, aa))
        self.stats["sent"] += 1

    def recv(self, timeout=0.1):
        """-> (source link address, AA frame) or None. Anything that breaks a rule is counted."""
        frame = self.backend.recv(timeout)
        if frame is None:
            return None
        src, aa = parse_frame(frame, self.mac, self.ethertype)
        if src is None:
            self.stats[aa] += 1
            return None
        self.stats["received"] += 1
        return src, aa

    def serve(self, handler, stop):
        """Call handler(src, aa) for every good frame until the `stop` Event is set."""
        while not stop.is_set():
            r = self.recv(0.1)
            if r is not None:
                handler(*r)

    def close(self):
        self.backend.close()


def open_carrier(device, mac_policy="random", ethertype=DEFAULT_ETHERTYPE, lib=None):
    """Open Npcap on `device` (a name from pcap_devices) and return a carrier."""
    real = adapter_mac(device)
    mac = link_address(mac_policy, real)
    lib = lib or load_pcap()
    return EtherCarrier(PcapBackend(device, mac, ethertype, lib), mac, ethertype)


# ---------------------------------------------------------------- the adapter's own address
def parse_getmac(text):
    """Windows `getmac /fo csv /v /nh` -> {GUID in lower case: link address bytes}."""
    import csv
    import io
    out = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 4:
            continue
        mac, transport = row[2].strip(), row[3]
        if "{" not in transport or len(mac.replace("-", "")) != 12:
            continue
        guid = transport[transport.index("{"):transport.index("}") + 1].lower()
        try:
            out[guid] = parse_mac(mac)
        except CarrierError:
            pass
    return out


def parse_netadapter(text):
    """PowerShell `Get-NetAdapter` lines 'GUID,MAC' -> {GUID in lower case: link address bytes}."""
    out = {}
    for line in text.splitlines():
        g, _, m = line.strip().partition(",")
        g = g.strip().lower()
        if not g.startswith("{") or not m.strip():
            continue
        try:
            out[g] = parse_mac(m.strip())
        except CarrierError:
            pass
    return out


_PS = ("Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
       "ForEach-Object { $_.InterfaceGuid + ',' + $_.MacAddress }")


def adapter_mac(device):
    """The adapter's own link address for a device name, or None when it cannot be found."""
    try:
        if os.name == "nt":
            if "{" not in device:
                return None
            guid = device[device.index("{"):device.index("}") + 1].lower()
            for cmd, parser in ((["powershell", "-NoProfile", "-Command", _PS], parse_netadapter),
                                (["getmac", "/fo", "csv", "/v", "/nh"], parse_getmac)):
                try:
                    txt = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
                except (OSError, subprocess.SubprocessError):
                    continue
                mac = parser(txt).get(guid)
                if mac is not None:
                    return mac
            return None
        with open("/sys/class/net/%s/address" % device) as f:
            return parse_mac(f.read().strip())
    except (OSError, subprocess.SubprocessError, CarrierError):
        return None


# ---------------------------------------------------------------- command line and selftest
def selftest():
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    def raises(fn, exc=CarrierError):
        try:
            fn()
        except exc:
            return True
        return False

    a_mac, b_mac = parse_mac("02:00:00:00:00:0a"), parse_mac("02:00:00:00:00:0b")
    aa = os.urandom(120)

    check("EtherType default is 0x88B6", DEFAULT_ETHERTYPE == 0x88B6 and parse_ethertype("default") == 0x88B6)
    check("the two presets and a custom value are allowed",
          all(check_ethertype(v)[0] for v in (0x88B5, 0x88B6, 0x9000)))
    check("0x88B5 warns that XTTP uses it", "XTTP" in check_ethertype(0x88B5)[1])
    check("values below 0x0600 and well-known types are refused",
          not check_ethertype(0x05FF)[0] and not check_ethertype(0x0800)[0] and not check_ethertype(0x86DD)[0]
          and not check_ethertype(0x8100)[0] and not check_ethertype(0x88CC)[0] and not check_ethertype(70000)[0])
    check("parse_ethertype takes 0x88b6, 88b6 and refuses junk",
          parse_ethertype("0x88b6") == 0x88B6 and parse_ethertype("9000") == 0x9000
          and raises(lambda: parse_ethertype("zzz")) and raises(lambda: parse_ethertype("0x0800")))
    check("a random link address is unicast and locally administered",
          all(not is_multicast_mac(m) and m[0] & 2 for m in (random_mac() for _ in range(200))))
    check("random link addresses differ", len({random_mac() for _ in range(50)}) == 50)
    check("link address policies", link_address("random") != link_address("random")
          and link_address("real", a_mac) == a_mac and link_address("02:11:22:33:44:55") == parse_mac("02-11-22-33-44-55")
          and raises(lambda: link_address("real")) and raises(lambda: link_address("ff:ff:ff:ff:ff:ff"))
          and raises(lambda: link_address("01:00:5e:00:00:01")) and raises(lambda: parse_mac("nope")))
    check("is_multicast_mac: broadcast and group bit", is_multicast_mac(b"\xff" * 6)
          and is_multicast_mac(parse_mac("01:00:5e:00:00:01")) and not is_multicast_mac(a_mac))

    f = build_frame(b_mac, a_mac, 0x88B6, aa)
    check("frame layout: dst, src, type, length, then the AA frame",
          f[:6] == b_mac and f[6:12] == a_mac and f[12:14] == b"\x88\xb6" and f[14:16] == b"\x00\x78"
          and f[16:136] == aa and len(f) == 136)
    check("parse gives back the sender and the AA frame", parse_frame(f, b_mac, 0x88B6) == (a_mac, aa))
    short = build_frame(b_mac, a_mac, 0x88B6, os.urandom(40))
    check("short frames are filled to 60 B with random bytes, and the length hides the fill",
          len(short) == 60 and parse_frame(short, b_mac, 0x88B6)[1] == short[16:56])
    fills = {build_frame(b_mac, a_mac, 0x88B6, bytes(40))[56:60] for _ in range(20)}
    check("the fill is never a run of zeros", len(fills) > 15 and bytes(4) not in fills)
    check("the largest AA frame (1498 B) fits one Ethernet payload",
          len(build_frame(b_mac, a_mac, 0x88B6, bytes(1498))) == 1514)
    check("1499 B and 33 B are refused", raises(lambda: build_frame(b_mac, a_mac, 0x88B6, bytes(1499)))
          and raises(lambda: build_frame(b_mac, a_mac, 0x88B6, bytes(33))))
    check("send to broadcast or multicast is refused", raises(lambda: build_frame(b"\xff" * 6, a_mac, 0x88B6, aa))
          and raises(lambda: build_frame(parse_mac("33:33:00:00:00:01"), a_mac, 0x88B6, aa)))
    check("a multicast source is refused", raises(lambda: build_frame(b_mac, parse_mac("01:00:5e:00:00:01"), 0x88B6, aa)))
    bc = bytearray(f); bc[:6] = b"\xff" * 6
    check("a received broadcast is dropped", parse_frame(bytes(bc), b_mac, 0x88B6) == (None, "dst"))
    mc = bytearray(f); mc[6] |= 1
    check("a received frame from a multicast source is dropped", parse_frame(bytes(mc), b_mac, 0x88B6) == (None, "multicast"))
    check("a frame to another address is dropped", parse_frame(f, parse_mac("02:00:00:00:00:0c"), 0x88B6) == (None, "dst"))
    check("a frame of another EtherType is dropped", parse_frame(f, b_mac, 0x88B5) == (None, "type"))
    check("our own frame is dropped", parse_frame(build_frame(a_mac, a_mac, 0x88B6, aa), a_mac, 0x88B6) == (None, "own"))
    check("a truncated frame is dropped", parse_frame(f[:100], b_mac, 0x88B6) == (None, "length")
          and parse_frame(f[:20], b_mac, 0x88B6) == (None, "short"))
    lie = bytearray(f); lie[14:16] = b"\x05\xff"
    check("a length that lies is dropped", parse_frame(bytes(lie), b_mac, 0x88B6) == (None, "length"))
    check("a carrier refuses a bad EtherType or link address",
          raises(lambda: EtherCarrier(None, a_mac, 0x0800)) and raises(lambda: EtherCarrier(None, b"\x01" * 6))
          and raises(lambda: EtherCarrier(None, b"\x02" * 5)))

    sample = ('"Ethernet","Intel(R) I219-V","D8-BB-C1-11-22-33","\\Device\\Tcpip_{AAAA1111-2222-3333-4444-555566667777}"\n'
              '"Wi-Fi","Wireless","A0-B1-C2-33-44-55","Media disconnected"\n'
              '"vEthernet","Hyper-V","00-15-5D-01-02-03","\\Device\\Tcpip_{BBBB1111-2222-3333-4444-555566667777}"\n')
    gm = parse_getmac(sample)
    check("getmac output is read (disconnected adapters skipped)", len(gm) == 2
          and gm["{aaaa1111-2222-3333-4444-555566667777}"] == parse_mac("D8:BB:C1:11:22:33"))

    na = parse_netadapter("{9C4AB1FB-63FC-4885-8958-3330A9659B60},A0-B1-C2-33-44-55\r\n"
                          "{AAAA},\r\ngarbage\r\n{FDD72F39-0E61-47EE-98B0-3D5BCCD0530D},10-FF-E0-BD-05-05\r\n")
    check("Get-NetAdapter output is read, disconnected adapters included",
          na["{9c4ab1fb-63fc-4885-8958-3330a9659b60}"] == parse_mac("A0:B1:C2:33:44:55") and len(na) == 2)

    class Loop:                                    # two carriers on a fake wire
        def __init__(self, wire, me):
            self.wire, self.me = wire, me
            self.q = []

        def send(self, fr):
            self.wire[1 - self.me].q.append(fr)

        def recv(self, timeout=0.1):
            return self.q.pop(0) if self.q else None

        def close(self):
            pass
    wire = [None, None]
    wire[0], wire[1] = Loop(wire, 0), Loop(wire, 1)
    ca, cb = EtherCarrier(wire[0], a_mac), EtherCarrier(wire[1], b_mac)
    ca.send(b_mac, aa)
    check("carriers pass an AA frame across a fake wire", cb.recv() == (a_mac, aa) and cb.recv() is None)
    wire[1].q.append(b"\xff" * 6 + a_mac + b"\x88\xb6\x00\x78" + aa)
    cb.recv()
    check("dropped frames are counted by reason", cb.stats["dst"] == 1 and cb.stats["received"] == 1)

    ok = _live_selftest(check)
    n = sum(results)
    print("%s%d of %d checks passed%s" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results),
                                         "" if ok else " (live frames skipped: needs Linux and root)"))
    return 0 if n == len(results) else 1


def _live_selftest(check):
    """Real frames over the Linux loopback device with two packet sockets. -> False if skipped."""
    if not hasattr(socket, "AF_PACKET") or not os.path.exists("/sys/class/net/lo"):
        return False
    a_mac, b_mac = parse_mac("02:00:00:00:00:0a"), parse_mac("02:00:00:00:00:0b")
    try:
        ba = PacketSocketBackend("lo", a_mac, DEFAULT_ETHERTYPE)
        bb = PacketSocketBackend("lo", b_mac, DEFAULT_ETHERTYPE)
    except CarrierError:
        return False
    a, b = EtherCarrier(ba, a_mac), EtherCarrier(bb, b_mac)
    aa = os.urandom(300)
    a.send(b_mac, aa)
    got = None
    for _ in range(10):
        got = b.recv(0.2) or got
        if got:
            break
    check("live: a real frame goes from A to B on the wire", got == (a_mac, aa))
    check("live: A drops its own copy and B's copy of it by rule", a.recv(0.2) is None)
    big = os.urandom(1498)
    b.send(a_mac, big)
    got = None
    for _ in range(10):
        got = a.recv(0.2) or got
        if got:
            break
    check("live: a 1498 B AA frame arrives whole", got == (b_mac, big))
    s2 = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s2.bind(("lo", 0))
    s2.send(b"\xff" * 6 + a_mac + b"\x88\xb6\x00\x78" + os.urandom(120) + bytes(0))
    time.sleep(0.2)
    before = b.stats["received"]
    r = b.recv(0.3)
    check("live: a broadcast frame on the wire is not delivered", r is None and b.stats["received"] == before)
    s2.close()
    stop, seen = threading.Event(), []
    t = threading.Thread(target=b.serve, args=(lambda s, f: seen.append(f), stop))
    t.start()
    for i in range(20):
        a.send(b_mac, bytes([i]) * 60)
    time.sleep(0.5)
    stop.set()
    t.join()
    check("live: serve() hands over 20 of 20 frames in order", seen == [bytes([i]) * 60 for i in range(20)])
    a.close()
    b.close()
    return True


def main():
    ap = argparse.ArgumentParser(description="IPv7 Ethernet carrier (Npcap).")
    ap.add_argument("--devices", action="store_true", help="list devices Npcap can open")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.devices:
        try:
            devs = pcap_devices()
        except CarrierError as e:
            print("%s%s" % (MARK_BAD, e))
            return 1
        for name, desc in devs:
            mac = adapter_mac(name)
            print("%s%s  %s  %s" % (MARK_STEP, name, fmt_mac(mac) if mac else "no address", desc))
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
