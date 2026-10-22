#!/usr/bin/env python3
"""ipv7_path.py: moving a session between paths (spec sections 12a, 17, 18).

A session is identified by its label and keys, never by an address. The path is only where the
frames go now. Either end may start a move. Four sealed, unicast-only messages do it:

    PATH       carrier 1 | link 6 | ip 16 | port 2          the mover says where it is moving to
    CHALLENGE  nonce 16 | seen ip 16 | seen port 2 | seen link 6
    RESPONSE   nonce 16 | link 6
    ACK        carrier 1

All four are sealed under the session keys with the session's one locked counter (they travel
inside the same AA frames as data: class byte 3, then the operation byte, then the fields).
Nothing here sends anything itself: PathManager.receive() and the begin/tick calls return a list
of (destination, frame) pairs, and the program sends each on the carrier named by the destination.

The host never changes a route on PATH alone (section 17 item 3): it sends a CHALLENGE to the new
address, the mover answers from there, and only then does the route change. The old path is
revoked the instant the new one is validated.

This is an unaudited prototype: it should not protect anyone whose safety depends on it.
"""
import collections
import ipaddress
import os
import struct
import time

MARK_STEP, MARK_OK, MARK_BAD = "|_", "*_", "-_"

PATH_CLASS = 3
OP_PATH, OP_CHALLENGE, OP_RESPONSE, OP_ACK = 1, 2, 3, 4
CARRIER_UDP, CARRIER_ETH = 1, 2

FIELDS = {
    OP_PATH: [("carrier", 1), ("link", 6), ("ip", 16), ("port", 2)],
    OP_CHALLENGE: [("nonce", 16), ("seen_ip", 16), ("seen_port", 2), ("seen_link", 6)],
    OP_RESPONSE: [("nonce", 16), ("link", 6)],
    OP_ACK: [("carrier", 1)],
}
NAMES = {OP_PATH: "PATH", OP_CHALLENGE: "CHALLENGE", OP_RESPONSE: "RESPONSE", OP_ACK: "ACK"}
SIZES = {op: sum(w for _, w in f) for op, f in FIELDS.items()}

CHALLENGE_TTL = 10.0         # a challenge is good for 10 s (O33, a guess)
RETRY_AFTER = 3.0            # resend a PATH or RESPONSE after 3 s
MAX_TRIES = 3                # three attempts, then the session stays on the old path (O33)
QUIET = 60.0                 # silence on Ethernet before the client goes back to UDP (section 16)
UNVALIDATED_GAP = 5.0        # one challenge per unvalidated source per 5 s
MAX_PENDING = 4              # challenges outstanding at once

Addr = collections.namedtuple("Addr", "carrier ip port link")
_V4 = b"\0" * 10 + b"\xff\xff"


def udp_addr(ip, port):
    return Addr(CARRIER_UDP, str(ip), int(port), b"")


def eth_addr(link, ethertype):
    return Addr(CARRIER_ETH, "", int(ethertype), bytes(link))


def addr_text(a):
    if a.carrier == CARRIER_ETH:
        return "ethernet %s" % ":".join("%02X" % x for x in a.link)
    return "udp %s:%d" % (a.ip, a.port)


# ---------------------------------------------------------------- the linear messages
def encode_ip(ip):
    if not ip:
        return bytes(16)
    a = ipaddress.ip_address(ip)
    return _V4 + a.packed if a.version == 4 else a.packed


def decode_ip(b):
    if b == bytes(16):
        return ""
    if b[:12] == _V4:
        return str(ipaddress.IPv4Address(b[12:]))
    return str(ipaddress.IPv6Address(b))


def pack(op, **v):
    out = [bytes([PATH_CLASS, op])]
    for name, width in FIELDS[op]:
        x = v[name]
        if isinstance(x, int):
            x = x.to_bytes(width, "big")
        if len(x) != width:
            raise ValueError("%s.%s must be %d bytes" % (NAMES[op], name, width))
        out.append(x)
    return b"".join(out)


def unpack(plain):
    """-> (op, fields) or None when this is not a well-formed path message."""
    if len(plain) < 2 or plain[0] != PATH_CLASS or plain[1] not in FIELDS:
        return None
    op = plain[1]
    if len(plain) != 2 + SIZES[op]:
        return None
    out, off = {}, 2
    for name, width in FIELDS[op]:
        out[name] = plain[off:off + width]
        off += width
    return op, out


def is_path_message(plain):
    return len(plain) >= 1 and plain[0] == PATH_CLASS


# ---------------------------------------------------------------- policy and checks
class Policy:
    """What the user allows. Ethernet is off unless the user turned it on (section 16 item 2)."""

    def __init__(self, allow_ethernet=False, ethertype=0x88B6, my_link=None, allow_loopback=False):
        self.allow_ethernet, self.ethertype = allow_ethernet, ethertype
        self.my_link, self.allow_loopback = my_link, allow_loopback


def unicast_udp(ip, port, allow_loopback=False):
    """A unicast IP address with a real port. Multicast, broadcast and unspecified are refused."""
    if not ip or not 1 <= port <= 65535:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_multicast or a.is_unspecified or (a.is_loopback and not allow_loopback):
        return False
    if a.version == 4 and (a == ipaddress.IPv4Address("255.255.255.255")):
        return False
    return True


def unicast_link(link):
    return len(link) == 6 and not link[0] & 1 and link != bytes(6)


class PathManager:
    """Path state of one session at one end.

    session   a Session from ipv7_bind (tx and rx Directions, one locked counter each)
    role      'user' or 'host': only the user goes back to UDP after 60 s of silence
    remote    Addr where frames to the other end go now
    The caller opens each received frame with session.rx.open(), then hands the plaintext and
    the Addr it came from to receive()."""

    def __init__(self, session, role, remote, policy=None, clock=time.time):
        self.session, self.role, self.clock = session, role, clock
        self.policy = policy or Policy()
        self.remote = remote
        self.udp_remote = remote if remote.carrier == CARRIER_UDP else None
        self.revoked = set()
        self.pending = {}                 # nonce -> dict(target, t)           (answering side)
        self.recent = {}                  # source -> time of last unvalidated challenge
        self.validated = None             # (nonce, target) of the last move this end approved
        self.move = None                  # our own PATH waiting for a CHALLENGE
        self.awaiting = None              # our RESPONSE waiting for an ACK
        self.last_rx = clock()
        self.events = []
        self.stats = {"refused": 0, "ignored": 0, "revoked": 0, "challenges": 0}

    # -- helpers
    def _event(self, text):
        self.events.append((self.clock(), text))

    def _seal(self, dest, op, **fields):
        return dest, self.session.tx.seal(pack(op, **fields))

    def _target_ok(self, a):
        if a.carrier == CARRIER_UDP:
            return unicast_udp(a.ip, a.port, self.policy.allow_loopback)
        if a.carrier == CARRIER_ETH:
            return (self.policy.allow_ethernet and unicast_link(a.link)
                    and a.port == self.policy.ethertype)
        return False

    def _challenge(self, target, nonce=None):
        nonce = nonce or os.urandom(16)
        self.pending[nonce] = {"target": target, "t": self.clock()}
        self.stats["challenges"] += 1
        if target.carrier == CARRIER_ETH:
            seen = dict(seen_ip=bytes(16), seen_port=target.port, seen_link=target.link)
        else:
            seen = dict(seen_ip=encode_ip(target.ip), seen_port=target.port, seen_link=bytes(6))
        return self._seal(target, OP_CHALLENGE, nonce=nonce, **seen)

    # -- the mover
    def begin_move_ethernet(self):
        """Ask to move to Ethernet. The PATH goes on the current path."""
        p = self.policy
        if not p.allow_ethernet or not p.my_link or not unicast_link(p.my_link):
            self.stats["refused"] += 1
            return []
        if self.move or self.awaiting or self.remote.carrier == CARRIER_ETH:
            return []
        self.move = {"carrier": CARRIER_ETH, "tries": 1, "sent": self.clock(), "dest": self.remote}
        return [self._seal(self.remote, OP_PATH, carrier=CARRIER_ETH, link=p.my_link,
                           ip=bytes(16), port=p.ethertype)]

    def begin_move_udp(self, ip=None, port=None):
        """Move to UDP. With an address, the PATH names it and goes on the current path. Without
        one (the old path is silent, or we do not know our public address) the PATH goes by UDP to
        the other end's UDP address, which then challenges the address it sees."""
        if self.move or self.awaiting or self.udp_remote is None:
            return []
        if ip:
            if not unicast_udp(ip, port or 0, self.policy.allow_loopback):
                self.stats["refused"] += 1
                return []
            if Addr(CARRIER_UDP, ip, port, b"") == self.remote:
                return []
            dest, fields = self.remote, dict(carrier=CARRIER_UDP, link=bytes(6), ip=encode_ip(ip), port=port)
        else:
            dest, fields = self.udp_remote, dict(carrier=CARRIER_UDP, link=bytes(6), ip=bytes(16), port=0)
        self.move = {"carrier": CARRIER_UDP, "tries": 1, "sent": self.clock(), "dest": dest, "fields": fields}
        return [self._seal(dest, OP_PATH, **fields)]

    # -- receiving
    def receive(self, src, plain):
        """src: the Addr the frame came from. plain: the opened payload.
        -> (data payload or None, [(destination Addr, sealed frame), ...])."""
        msg = unpack(plain) if is_path_message(plain) else None
        if src in self.revoked:
            # A revoked path carries no data, even with a valid tag. The four path messages are
            # still read, because that is how a client returns to a path it left: each is gated
            # by its own state (a pending nonce, an awaited ACK) and the route changes only when
            # a challenge has been answered.
            if msg is None:
                self.stats["revoked"] += 1
                return None, []
        now = self.clock()
        if is_path_message(plain) and msg is None:
            self.stats["ignored"] += 1
            return None, []
        outs = []
        if src == self.remote:
            self.last_rx = now
        elif not (self.awaiting and src == self.awaiting["dest"]) and not (msg and msg[0] != OP_PATH):
            outs += self._unvalidated(src, now, msg)
        if msg is None:
            return plain, outs
        op, f = msg
        if op == OP_PATH:
            outs += self._on_path(src, f)
        elif op == OP_CHALLENGE:
            outs += self._on_challenge(src, f)
        elif op == OP_RESPONSE:
            outs += self._on_response(src, f)
        elif op == OP_ACK:
            self._on_ack(src, f)
        return None, outs

    def _unvalidated(self, src, now, msg):
        """A genuine frame from an address we have not validated: one small challenge, no more
        than one per source per 5 s. A PATH from that source is handled by _on_path instead."""
        if msg and msg[0] == OP_PATH:
            return []
        if not self._target_ok(src):
            self.stats["refused"] += 1
            return []
        if now - self.recent.get(src, -1e9) < UNVALIDATED_GAP or len(self.pending) >= MAX_PENDING:
            return []
        self.recent[src] = now
        return [self._challenge(src)]

    def _on_path(self, src, f):
        carrier = f["carrier"][0]
        ip, port, link = decode_ip(f["ip"]) if f["ip"] != bytes(16) else "", struct.unpack(">H", f["port"])[0], f["link"]
        if carrier == CARRIER_ETH:
            if ip or not unicast_link(link):
                self.stats["refused"] += 1
                return []
            target = eth_addr(link, port)
        elif carrier == CARRIER_UDP:
            if link != bytes(6):
                self.stats["refused"] += 1
                return []
            if ip:
                target = udp_addr(ip, port)
            elif port == 0 and src.carrier == CARRIER_UDP:
                target = src                         # the address this PATH arrived from
            else:
                self.stats["refused"] += 1
                return []
        else:
            self.stats["refused"] += 1
            return []
        if not self._target_ok(target):
            self.stats["refused"] += 1
            return []
        if target == self.remote:
            self.stats["ignored"] += 1
            return []                                # the path already in use
        for nonce, p in self.pending.items():        # a repeated PATH: the same challenge again
            if p["target"] == target and self.clock() - p["t"] < CHALLENGE_TTL:
                return [self._challenge(target, nonce)]
        if len(self.pending) >= MAX_PENDING:
            self.stats["ignored"] += 1
            return []
        return [self._challenge(target)]

    def _on_challenge(self, src, f):
        seen_port = struct.unpack(">H", f["seen_port"])[0]
        if src.carrier == CARRIER_ETH:
            # The other end says which link address it saw us on. It must be ours: a relay
            # that forwards the challenge from another machine fails here.
            if not self.policy.allow_ethernet or f["seen_link"] != self.policy.my_link:
                self.stats["refused"] += 1
                self._event("!NO MATCH! the challenge names another link address")
                return []
            link = self.policy.my_link
        else:
            link = bytes(6)
            self._event("seen as %s:%d" % (decode_ip(f["seen_ip"]), seen_port))
        self.move = None
        self.awaiting = {"dest": src, "sent": self.clock(), "tries": 1, "nonce": f["nonce"], "link": link}
        return [self._seal(src, OP_RESPONSE, nonce=f["nonce"], link=link)]

    def _on_response(self, src, f):
        if self.validated and f["nonce"] == self.validated[0] and src == self.validated[1] and src == self.remote:
            return [self._seal(src, OP_ACK, carrier=src.carrier)]     # our ACK was lost: again
        p = self.pending.get(f["nonce"])
        if p is None or src != p["target"] or self.clock() - p["t"] > CHALLENGE_TTL:
            self.stats["ignored"] += 1
            return []
        if src.carrier == CARRIER_ETH and f["link"] != src.link:
            self.stats["ignored"] += 1
            return []
        old = self.remote
        self.remote = src
        self.validated = (f["nonce"], src)
        self.pending.clear()
        self.revoked.discard(src)
        if old != src:
            self.revoked.add(old)                    # instantly
        if src.carrier == CARRIER_UDP:
            self.udp_remote = src
        self.last_rx = self.clock()
        self._event("moved to %s - !MATCH!" % addr_text(src))
        return [self._seal(src, OP_ACK, carrier=src.carrier)]

    def _on_ack(self, src, f):
        a = self.awaiting
        if a is None or src != a["dest"] or f["carrier"][0] != src.carrier:
            self.stats["ignored"] += 1
            return
        old = self.remote
        self.remote = src
        self.awaiting = None
        self.revoked.discard(src)
        if old != src:
            self.revoked.add(old)
        if src.carrier == CARRIER_UDP:
            self.udp_remote = src
        self.last_rx = self.clock()
        self._event("moved to %s - !MATCH!" % addr_text(src))

    # -- time
    def tick(self):
        """Call about once a second. -> list of (destination, frame) to send."""
        now, outs = self.clock(), []
        for n in [n for n, p in self.pending.items() if now - p["t"] > CHALLENGE_TTL]:
            del self.pending[n]
        for s in [s for s, t in self.recent.items() if now - t > 4 * UNVALIDATED_GAP]:
            del self.recent[s]
        m = self.move
        if m and now - m["sent"] > RETRY_AFTER:
            if m["tries"] >= MAX_TRIES:
                self.move = None
                self._event("!NO MATCH! the move to %s got no challenge: staying on %s" % (
                    "ethernet" if m["carrier"] == CARRIER_ETH else "udp", addr_text(self.remote)))
            else:
                m["tries"] += 1
                m["sent"] = now
                if m["carrier"] == CARRIER_ETH:
                    outs.append(self._seal(m["dest"], OP_PATH, carrier=CARRIER_ETH, link=self.policy.my_link,
                                           ip=bytes(16), port=self.policy.ethertype))
                else:
                    outs.append(self._seal(m["dest"], OP_PATH, **m["fields"]))
        a = self.awaiting
        if a and now - a["sent"] > RETRY_AFTER:
            if a["tries"] >= MAX_TRIES:
                self.awaiting = None
                self._event("!NO MATCH! no ACK from %s: staying on %s" % (addr_text(a["dest"]), addr_text(self.remote)))
            else:
                a["tries"] += 1
                a["sent"] = now
                outs.append(self._seal(a["dest"], OP_RESPONSE, nonce=a["nonce"], link=a["link"]))
        if (self.role == "user" and self.remote.carrier == CARRIER_ETH and not self.move
                and not self.awaiting and now - self.last_rx > QUIET):
            self._event("ethernet silent for %d s: going back to UDP" % QUIET)
            self.last_rx = now
            outs += self.begin_move_udp()
        return outs


# ---------------------------------------------------------------- selftest
def selftest():
    from ipv7_bind import Session, ReplayWindow  # noqa: F401  (the real session frames)
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    now = [1_800_000_000.0]
    clock = lambda: now[0]                                      # noqa: E731
    ETY = 0x88B6
    L_USER, L_HOST = bytes.fromhex("02000000000a"), bytes.fromhex("02000000000b")

    class Node:
        def __init__(self, role, okm, ip, port, link, allow_eth=True, loop=True):
            self.role, self.ip, self.port, self.link = role, ip, port, link
            self.sess = Session(role, okm, bytes(8), bytes(16), "n", b"", b"")
            self.mgr = None
            self.data = []

        def addr(self, carrier):
            return udp_addr(self.ip, self.port) if carrier == CARRIER_UDP else eth_addr(self.link, ETY)

    class Net:
        def __init__(self, user, host):
            self.user, self.host, self.drop, self.log, self.q = user, host, None, [], []

        def owner(self, dest):
            for n in (self.user, self.host):
                if dest.carrier == CARRIER_UDP and (n.ip, n.port) == (dest.ip, dest.port):
                    return n
                if dest.carrier == CARRIER_ETH and n.link == dest.link:
                    return n
            return None

        def send(self, sender, outs):
            for dest, frame in outs:
                self.q.append((sender, dest, frame))

        def run(self, limit=200):
            n = 0
            while self.q and n < limit:
                n += 1
                sender, dest, frame = self.q.pop(0)
                if self.drop and self.drop(sender, dest, frame):
                    continue
                to = self.owner(dest)
                if to is None:
                    continue
                self.deliver(sender, to, dest.carrier, frame)

        def deliver(self, sender, to, carrier, frame):
            plain = to.sess.rx.open(frame)
            if plain is None:
                return None
            src = sender.addr(carrier)
            data, outs = to.mgr.receive(src, plain)
            if data is not None:
                to.data.append((src, data))
            self.send(to, outs)
            return data

    def make(allow_eth=True, user_ip="203.0.113.9", host_ip="198.51.100.1"):
        okm = os.urandom(168)
        u = Node("user", okm, user_ip, 40000, L_USER)
        h = Node("host", okm, host_ip, 7000, L_HOST)
        pol = lambda link: Policy(allow_ethernet=allow_eth, ethertype=ETY, my_link=link, allow_loopback=True)  # noqa
        u.mgr = PathManager(u.sess, "user", h.addr(CARRIER_UDP), pol(L_USER), clock)
        h.mgr = PathManager(h.sess, "host", u.addr(CARRIER_UDP), pol(L_HOST), clock)
        return u, h, Net(u, h)

    def say(sender, net, text=b"x"):
        net.send(sender, [(sender.mgr.remote, sender.sess.tx.seal(b"\x01" + text))])
        net.run()

    check("message sizes: PATH 25, CHALLENGE 40, RESPONSE 22, ACK 1",
          (SIZES[OP_PATH], SIZES[OP_CHALLENGE], SIZES[OP_RESPONSE], SIZES[OP_ACK]) == (25, 40, 22, 1))
    for op in FIELDS:
        vals = {n: os.urandom(w) for n, w in FIELDS[op]}
        o, f = unpack(pack(op, **vals))
        check("%s packs and unpacks at its offsets" % NAMES[op], o == op and f == vals)
    check("a wrong length, class or operation is not a path message",
          unpack(b"\x03\x01abc") is None and unpack(b"\x04\x01" + bytes(25)) is None
          and unpack(b"\x03\x09" + bytes(25)) is None and unpack(b"") is None)
    check("addresses round-trip, IPv4 as v4-mapped", decode_ip(encode_ip("203.0.113.9")) == "203.0.113.9"
          and decode_ip(encode_ip("2001:db8::7")) == "2001:db8::7" and encode_ip("") == bytes(16))
    check("unicast rules for IP", not unicast_udp("224.0.0.1", 5) and not unicast_udp("255.255.255.255", 5)
          and not unicast_udp("ff02::1", 5) and not unicast_udp("0.0.0.0", 5) and not unicast_udp("203.0.113.9", 0)
          and not unicast_udp("203.0.113.9", 70000) and not unicast_udp("127.0.0.1", 5) and unicast_udp("203.0.113.9", 5)
          and unicast_udp("2001:db8::1", 5) and not unicast_udp("nonsense", 5))
    check("unicast rules for link addresses", not unicast_link(b"\xff" * 6) and not unicast_link(bytes.fromhex("01005e000001"))
          and not unicast_link(bytes(6)) and unicast_link(L_USER) and not unicast_link(b"\x02" * 5))

    # --- the user moves from UDP to Ethernet
    u, h, net = make()
    say(u, net, b"before")
    check("data flows on UDP first", h.data and h.data[-1][1].endswith(b"before"))
    c0 = u.sess.tx.ctr
    net.send(u, u.mgr.begin_move_ethernet())
    net.run()
    check("host remote is now the user's link address, user remote the host's",
          h.mgr.remote == eth_addr(L_USER, ETY) and u.mgr.remote == eth_addr(L_HOST, ETY))
    check("four messages used the session counter (PATH from user, RESPONSE from user)",
          u.sess.tx.ctr == c0 + 2 and h.sess.tx.ctr >= 2)
    check("both ends logged the move with !MATCH!", any("!MATCH!" in e[1] for e in u.mgr.events)
          and any("!MATCH!" in e[1] for e in h.mgr.events))
    say(u, net, b"on ethernet")
    say(h, net, b"back")
    check("data flows both ways over Ethernet", h.data[-1][1].endswith(b"on ethernet") and u.data[-1][1].endswith(b"back")
          and h.data[-1][0].carrier == CARRIER_ETH)
    # old path revoked at once
    fr = u.sess.tx.seal(b"\x01old path")
    net.deliver(u, h, CARRIER_UDP, fr)
    check("a valid frame on the revoked UDP path is dropped at the host", not h.data[-1][1].endswith(b"old path")
          and h.mgr.stats["revoked"] == 1)
    fr = h.sess.tx.seal(b"\x01old path")
    net.deliver(h, u, CARRIER_UDP, fr)
    check("and at the user", not u.data[-1][1].endswith(b"old path") and u.mgr.stats["revoked"] == 1)

    # --- fallback to UDP after 60 s of silence
    now[0] += 61
    outs = u.mgr.tick()
    net.send(u, outs)
    net.run()
    check("after 61 s of silence the user goes back to UDP and both ends agree",
          u.mgr.remote.carrier == CARRIER_UDP and h.mgr.remote == udp_addr(u.ip, u.port)
          and u.mgr.remote == udp_addr(h.ip, h.port))
    fr = u.sess.tx.seal(b"\x01eth after fallback")
    net.deliver(u, h, CARRIER_ETH, fr)
    check("Ethernet is revoked after the fallback", not h.data[-1][1].endswith(b"eth after fallback"))
    say(u, net, b"udp again")
    check("data flows on UDP again", h.data[-1][1].endswith(b"udp again"))

    # --- the host starts the move (either end)
    u, h, net = make()
    net.send(h, h.mgr.begin_move_ethernet())
    net.run()
    check("the host can start a move: Ethernet validated", u.mgr.remote == eth_addr(L_HOST, ETY)
          and h.mgr.remote == eth_addr(L_USER, ETY))

    # --- the user may stay on UDP only
    u, h, net = make(allow_eth=False)
    check("a user who has not allowed Ethernet cannot start a move", u.mgr.begin_move_ethernet() == [])
    u2, h2, net2 = make()
    u2.mgr.policy.allow_ethernet = False
    net2.send(h2, h2.mgr.begin_move_ethernet())
    net2.run()
    check("a host's PATH to a user who stays on UDP is ignored: no challenge, no move",
          u2.mgr.remote.carrier == CARRIER_UDP and h2.mgr.remote.carrier == CARRIER_UDP and not u2.mgr.awaiting
          and u2.mgr.stats["refused"] >= 1)

    # --- refused targets
    u, h, net = make()
    def path_to(sender, receiver, net, **kw):
        fields = dict(carrier=CARRIER_ETH, link=L_USER, ip=bytes(16), port=ETY)
        fields.update(kw)
        fr = sender.sess.tx.seal(pack(OP_PATH, **fields))
        before = receiver.mgr.stats["challenges"]
        net.deliver(sender, receiver, CARRIER_UDP, fr)
        net.q.clear()
        return receiver.mgr.stats["challenges"] - before
    bad = {
        "broadcast link": dict(link=b"\xff" * 6),
        "multicast link": dict(link=bytes.fromhex("01005e000001")),
        "zero link": dict(link=bytes(6)),
        "link with an IP": dict(ip=encode_ip("203.0.113.9")),
        "wrong EtherType": dict(port=0x88B5),
        "IPv4 multicast": dict(carrier=CARRIER_UDP, link=bytes(6), ip=encode_ip("224.0.0.251"), port=5000),
        "IPv4 broadcast": dict(carrier=CARRIER_UDP, link=bytes(6), ip=encode_ip("255.255.255.255"), port=5000),
        "IPv6 multicast": dict(carrier=CARRIER_UDP, link=bytes(6), ip=encode_ip("ff02::1"), port=5000),
        "UDP with a link": dict(carrier=CARRIER_UDP, link=L_USER, ip=encode_ip("203.0.113.50"), port=5000),
        "UDP port zero with an IP": dict(carrier=CARRIER_UDP, link=bytes(6), ip=encode_ip("203.0.113.50"), port=0),
        "unknown carrier": dict(carrier=9),
    }
    for name, kw in bad.items():
        check("PATH refused: %s" % name, path_to(u, h, net, **kw) == 0)
    check("a PATH for the path already in use is ignored",
          path_to(u, h, net, carrier=CARRIER_UDP, link=bytes(6), ip=encode_ip(u.ip), port=u.port) == 0)
    check("a good PATH earns exactly one challenge", path_to(u, h, net) == 1)

    # --- UDP to UDP with a named address (privacy rotation)
    u, h, net = make()
    u.ip, u.port = "2001:db8::77", 41000
    net.send(u, u.mgr.begin_move_udp("2001:db8::77", 41000))
    net.run()
    check("a move to a new named UDP address validates", h.mgr.remote == udp_addr("2001:db8::77", 41000)
          and u.mgr.remote == udp_addr(h.ip, h.port))
    fr = u.sess.tx.seal(b"\x01old")
    old_user = udp_addr("203.0.113.9", 40000)
    h.mgr.receive(old_user, b"\x01old")
    check("the old UDP address is revoked", h.mgr.stats["revoked"] == 1)

    # --- a frame from a new source address (adapter swap, NAT change): no PATH needed
    u, h, net = make()
    u.ip, u.port = "203.0.113.200", 52000
    say(u, net, b"from a new place")
    check("a genuine frame from a new address is delivered and earns one challenge, then the move completes",
          h.data[-1][1].endswith(b"from a new place") and h.mgr.remote == udp_addr("203.0.113.200", 52000))

    # --- an attacker copies a genuine frame and sends it from elsewhere
    u, h, net = make()
    mal = Node("user", os.urandom(168), "192.0.2.66", 6666, bytes.fromhex("020000000066"))
    genuine = u.sess.tx.seal(b"\x01copied")
    plain = h.sess.rx.open(genuine)
    data, outs = h.mgr.receive(udp_addr("192.0.2.66", 6666), plain)
    check("a copied frame earns one small challenge to the copier", len(outs) == 1 and outs[0][0] == udp_addr("192.0.2.66", 6666)
          and len(outs[0][1]) == 2 + SIZES[OP_CHALLENGE] + 34)
    check("the host route does not change", h.mgr.remote == udp_addr(u.ip, u.port))
    more = [h.mgr.receive(udp_addr("192.0.2.66", 6666), b"\x01again")[1] for _ in range(50)]
    check("fifty more frames from that source earn no more challenges", sum(len(o) for o in more) == 0)
    nonce = list(h.mgr.pending)[0]
    forged = mal.sess.tx.seal(pack(OP_RESPONSE, nonce=nonce, link=bytes(6)))
    check("the copier cannot answer: a RESPONSE under other keys does not open", h.sess.rx.open(forged) is None)
    # even a RESPONSE sealed properly but sent from the wrong address is refused
    resp = u.sess.tx.seal(pack(OP_RESPONSE, nonce=nonce, link=bytes(6)))
    d2, o2 = h.mgr.receive(udp_addr("192.0.2.77", 1), h.sess.rx.open(resp))
    check("a RESPONSE from a different address than the challenged one is refused",
          h.mgr.remote == udp_addr(u.ip, u.port) and o2 == [])

    # --- relayed challenge on Ethernet
    u, h, net = make()
    outs = u.mgr.begin_move_ethernet()
    plain = h.sess.rx.open(outs[0][1])
    _, couts = h.mgr.receive(u.addr(CARRIER_UDP), plain)
    cframe = couts[0][1]
    # a relay on another machine forwards the challenge: the user sees it came to a different link
    u.mgr.policy.my_link = bytes.fromhex("020000000099")
    d, r = u.mgr.receive(eth_addr(L_HOST, ETY), u.sess.rx.open(cframe))
    check("a challenge that names another link address gets no answer: !NO MATCH!", r == []
          and any("!NO MATCH!" in e[1] for e in u.mgr.events) and u.mgr.remote.carrier == CARRIER_UDP)

    # --- timing, repeats, loss
    u, h, net = make()
    outs = u.mgr.begin_move_ethernet()
    plain = h.sess.rx.open(outs[0][1])
    _, couts = h.mgr.receive(u.addr(CARRIER_UDP), plain)
    now[0] += 11
    h.mgr.tick()
    cplain = u.sess.rx.open(couts[0][1])
    _, routs = u.mgr.receive(eth_addr(L_HOST, ETY), cplain)
    d3, a3 = h.mgr.receive(eth_addr(L_USER, ETY), h.sess.rx.open(routs[0][1]))
    check("an expired challenge is refused: the host does not move", h.mgr.remote.carrier == CARRIER_UDP and a3 == [])
    u, h, net = make()
    net.drop = lambda s, d, f: False
    net.send(u, u.mgr.begin_move_ethernet())
    # lose the first CHALLENGE
    sender, dest, frame = net.q.pop(0)
    to = net.owner(dest)
    net.deliver(sender, to, dest.carrier, frame)
    lost = net.q.pop(0)                                         # the CHALLENGE, thrown away
    now[0] += 4
    net.send(u, u.mgr.tick())
    net.run()
    check("a lost CHALLENGE is repaired by the repeated PATH", u.mgr.remote == eth_addr(L_HOST, ETY)
          and h.mgr.remote == eth_addr(L_USER, ETY))
    u, h, net = make()
    net.send(u, u.mgr.begin_move_ethernet())
    net.q.pop(0)                                                # the PATH never arrives
    for _ in range(4):
        now[0] += 4
        net.send(u, u.mgr.tick())
        net.q.clear()
    check("after three tries with no answer the user stays on UDP and says so",
          u.mgr.remote.carrier == CARRIER_UDP and u.mgr.move is None and any("staying on" in e[1] for e in u.mgr.events))
    check("only one move at a time", u.mgr.begin_move_ethernet() != [] and u.mgr.begin_move_ethernet() == [])
    # lost ACK: the user repeats the RESPONSE, the host answers with the ACK again
    u, h, net = make()
    net.send(u, u.mgr.begin_move_ethernet())
    while net.q:
        sender, dest, frame = net.q.pop(0)
        to = net.owner(dest)
        plain = to.sess.rx.open(frame)
        data, outs = to.mgr.receive(sender.addr(dest.carrier), plain)
        if to is u:                                             # the user sees the CHALLENGE ...
            for o in outs:
                net.q.append((to, o[0], o[1]))
        elif to is h and plain[1] == OP_RESPONSE:               # ... the host's ACK is lost
            pass
        else:
            for o in outs:
                net.q.append((to, o[0], o[1]))
    check("host moved but the user has not yet (ACK lost)", h.mgr.remote.carrier == CARRIER_ETH and u.mgr.remote.carrier == CARRIER_UDP)
    now[0] += 4
    net.send(u, u.mgr.tick())
    net.run()
    check("the repeated RESPONSE brings the ACK again and the user moves", u.mgr.remote == eth_addr(L_HOST, ETY))

    # --- caps
    u, h, net = make()
    for i in range(10):
        h.mgr.receive(udp_addr("198.51.100.%d" % (100 + i), 9000), b"\x01x")
    check("at most four challenges are outstanding", len(h.mgr.pending) == MAX_PENDING)
    now[0] += 11
    h.mgr.tick()
    check("expired challenges are cleaned up", len(h.mgr.pending) == 0)

    # --- real frames across the Ethernet carrier code
    try:
        import ipv7_ether as E
        u, h, net = make()
        outs = u.mgr.begin_move_ethernet()
        h.mgr.receive(u.addr(CARRIER_UDP), h.sess.rx.open(outs[0][1]))
        _, couts = h.mgr.receive(u.addr(CARRIER_UDP), h.sess.rx.open(u.sess.tx.seal(pack(OP_PATH, carrier=CARRIER_ETH, link=L_USER, ip=bytes(16), port=ETY))))
        fr = E.build_frame(L_USER, L_HOST, ETY, couts[0][1])
        src, aa = E.parse_frame(fr, L_USER, ETY)
        check("a sealed CHALLENGE fits an Ethernet frame and comes out intact", src == L_HOST and aa == couts[0][1] and len(fr) == 16 + 76)
    except ImportError:
        pass

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    print(__doc__)
