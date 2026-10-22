#!/usr/bin/env python3
"""ipv7_bind.py: the IPv7 secure bind (spec sections 3, 4, 5, 7, 14, 16).

Transport-agnostic: nothing here opens a socket. A host or client object takes one received
datagram and returns the datagrams to send back. The caller moves the bytes (UDP today).

  HELLO     nonce 16                                           user -> host
  COOKIE    cookie 16 = AES-CMAC(rotating key, address, port, nonce)   host -> user (stateless)
  HELLO2    cookie | nonce | suite | ML-KEM-1024 key | RSA-4096 modulus      user -> host
  ACCEPT    ML-KEM ct | RSA-OAEP ct | nonce | sealed{ host signature }       host -> user
  FINISHED  sealed{ invite ticket }                                           user -> host
  READY     sealed{ TP/IX address | uuid | resumption ticket }               host -> user

and, for a user coming back with the resumption ticket READY gave them (spec section 7), the
same HELLO/COOKIE round followed by one exchange in place of HELLO2..READY:

  RESUME    cookie | nonce | suite | fresh ML-KEM-1024 key | resumption ticket | binder   user -> host
  RESUMED   ML-KEM ct | nonce | sealed{ TP/IX address | uuid | next resumption ticket }   host -> user

The binder is AES-CMAC under a key derived from the resumption secret, over everything before
it, so only the holder of that secret can resume; the host proves it is the same host by
sealing RESUMED under keys that mix the fresh ML-KEM secret with that same resumption secret
(which came out of the full hybrid bind, so the classical secret is carried forward and no new
RSA key is needed). Each resumption bumps the invite's generation: the ticket just used is
dead, RESUMED carries the next one. One live session per invite: a resumed session replaces
the old one.

Messages are fixed lists of name:width fields, cut into chunks `type:1 id:2 seq:1 data`
(1190 B of data per chunk). A message of two or more chunks gets one XOR parity chunk, so one
lost chunk is rebuilt without a retry. Nothing is padded with zeros: tickets are sized to fill
the datagram and their spare room is random-looking ciphertext.

PATH lives in `ipv7_path.py`. This is an unaudited prototype: it should not protect anyone
whose safety depends on it.
"""
import base64
import hashlib
import os
import struct
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import cmac, hashes, serialization as S
from cryptography.hazmat.primitives.asymmetric import mlkem, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------- sizes and types
CHUNK_DATA = 1190            # data bytes per chunk (spec section 14)
CHUNK_HEAD = 4               # type 1, id 2, seq 1
SUITE_V1 = 1                 # ML-KEM-1024 + RSA-4096 OAEP + AES-256-GCM + HKDF-SHA256
MLKEM_PK, MLKEM_CT, RSA_N = 1568, 1568, 512
SIG_FIELD = 664              # sealed signature field: siglen 2 | OpenPGP signature | random fill
TAG = 16
FRAME_LIMIT = 1 << 24        # frames per direction before the session must re-bind
TICKET_NONCE = 12

HELLO, COOKIE, HELLO2, ACCEPT, FINISHED, READY, RESUME, RESUMED = 1, 2, 3, 4, 5, 6, 7, 8

INVITE_TICKET = CHUNK_DATA - TAG                 # 1174: what FINISHED seals
ADDR_LEN, UUID_LEN, NAME_MAX = 8, 16, 32
RESUME_TICKET = INVITE_TICKET - ADDR_LEN - UUID_LEN   # 1150: what READY seals after address, uuid
SITES_MAX = 512
BINDER = 16                                      # AES-CMAC tag closing a RESUME

MESSAGES = {
    HELLO: ("HELLO", [("nonce", 16)]),
    COOKIE: ("COOKIE", [("cookie", 16)]),
    HELLO2: ("HELLO2", [("cookie", 16), ("nonce", 16), ("suite", 2), ("mlkem_pk", MLKEM_PK),
                        ("rsa_n", RSA_N)]),
    ACCEPT: ("ACCEPT", [("mlkem_ct", MLKEM_CT), ("rsa_ct", RSA_N), ("nonce", 16),
                        ("sealed", SIG_FIELD + TAG)]),
    FINISHED: ("FINISHED", [("sealed", CHUNK_DATA)]),
    READY: ("READY", [("sealed", CHUNK_DATA)]),
    RESUME: ("RESUME", [("cookie", 16), ("nonce", 16), ("suite", 2), ("mlkem_pk", MLKEM_PK),
                        ("ticket", RESUME_TICKET), ("binder", BINDER)]),
    RESUMED: ("RESUMED", [("mlkem_ct", MLKEM_CT), ("nonce", 16), ("sealed", CHUNK_DATA)]),
}
TOTAL = {t: sum(w for _, w in f) for t, (_, f) in MESSAGES.items()}

# step marks (spec section 13)
MARK_STEP, MARK_OK, MARK_BAD = "|_", "*_", "-_"


class BindError(Exception):
    """A bind check failed. `.field` names the field that failed (route, key or ticket)."""

    def __init__(self, msg, field="key"):
        Exception.__init__(self, msg)
        self.field = field


# ---------------------------------------------------------------- small helpers
def kdf(secret, salt, info, length):
    """HKDF-SHA256. Behind one function so O4 can swap it."""
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def aes_cmac(key, data):
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def aes_block(key, block):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(block) + e.finalize()


def groups(b):
    """bytes shown as groups of four genkey letters (A-Z, 2-7): 10 bytes -> 4 groups."""
    s = base64.b32encode(b).decode().rstrip("=")
    return "-".join(s[i:i + 4] for i in range(0, len(s), 4))


def ct_equal(a, b):
    import hmac
    return hmac.compare_digest(a, b)


def _oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def dotted(b):
    return ".".join(str(x) for x in b)


# ---------------------------------------------------------------- linear messages and chunks
def pack_fields(mtype, **values):
    """Join the named fields of a message in order. Every width is checked."""
    name, fields = MESSAGES[mtype]
    out = []
    for fname, width in fields:
        v = values[fname]
        if len(v) != width:
            raise ValueError("%s.%s must be %d bytes, got %d" % (name, fname, width, len(v)))
        out.append(v)
    return b"".join(out)


def unpack_fields(mtype, data):
    name, fields = MESSAGES[mtype]
    if len(data) != TOTAL[mtype]:
        raise ValueError("%s must be %d bytes" % (name, TOTAL[mtype]))
    out, off = {}, 0
    for fname, width in fields:
        out[fname] = data[off:off + width]
        off += width
    return out


def n_chunks(mtype):
    return -(-TOTAL[mtype] // CHUNK_DATA)


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def to_chunks(mtype, mid, data):
    """Cut a message into datagram payloads, plus one parity chunk when there are two or more."""
    if len(data) != TOTAL[mtype]:
        raise ValueError("wrong message length")
    n = n_chunks(mtype)
    pieces = [data[i * CHUNK_DATA:(i + 1) * CHUNK_DATA] for i in range(n)]
    out = [struct.pack(">BHB", mtype, mid, i) + p for i, p in enumerate(pieces)]
    if n > 1:
        par = bytes(CHUNK_DATA)
        for p in pieces:
            par = _xor(par, p.ljust(CHUNK_DATA, b"\0"))      # zero-extension is for the XOR only
        out.append(struct.pack(">BHB", mtype, mid, n) + par)
    return out


def parse_chunk(dgram):
    """-> (type, id, seq, data), or None when the datagram is not a well-formed chunk."""
    if len(dgram) < CHUNK_HEAD:
        return None
    mtype, mid, seq = struct.unpack(">BHB", dgram[:CHUNK_HEAD])
    if mtype not in TOTAL:
        return None
    n = n_chunks(mtype)
    data = dgram[CHUNK_HEAD:]
    if seq < n:
        want = CHUNK_DATA if seq < n - 1 else TOTAL[mtype] - CHUNK_DATA * (n - 1)
    elif seq == n and n > 1:
        want = CHUNK_DATA                                     # parity
    else:
        return None
    if len(data) != want:
        return None
    return mtype, mid, seq, data


class Reassembler:
    """Collects chunks per (key, type, id). One missing data chunk is rebuilt from parity.
    Bounded: at most `cap` partial messages, each dropped after `ttl` seconds, and at most
    `per_source` for any one key (peer), so no single sender can own the table.

    Full is not a refusal: when the table is full the OLDEST partial is evicted to make room.
    Refusing new partials instead (as this used to) was a cheap denial of service found by
    `ipv7_attack.attack_resume_wire` (section 33): every finished multi-chunk message left its
    trailing parity chunk behind as a fresh, empty partial that lived for the whole `ttl`, so 64
    HELLO2s or RESUMEs in 30 seconds -- from anyone, no cookie needed, since this runs before the
    cookie check -- blocked every honest bind for the next 30 seconds. Two fixes: the trailing
    parity chunk of a message that just completed (`recent`) opens no partial at all (a resend's
    DATA chunks still do, so the READY-lost and RESUMED-lost resends keep working), and a full
    table evicts its oldest entry rather than turning the newcomer away. An honest message's
    chunks arrive within a millisecond of each other, so to push one out an attacker now has to
    land `cap` new partials inside that millisecond, every millisecond, instead of 64 chunks per
    half minute."""

    def __init__(self, cap=64, ttl=30.0, clock=time.time, per_source=4, remember=5.0):
        self.cap, self.ttl, self.clock = cap, ttl, clock
        self.per_source, self.remember = per_source, remember
        self.parts = {}
        self.recent = {}                 # (key, type, id) of messages completed lately -> when

    def _evict(self, key, now):
        """Make room for a new partial from `key`: that source's oldest if it is at its own
        limit, else the table's oldest if the table is full."""
        mine = [k for k in self.parts if k[0] == key]
        if len(mine) >= self.per_source:
            del self.parts[min(mine, key=lambda k: self.parts[k][0])]
        elif len(self.parts) >= self.cap:
            del self.parts[min(self.parts, key=lambda k: self.parts[k][0])]

    def feed(self, key, dgram):
        """-> (type, id, message bytes) when a message is complete, else None."""
        p = parse_chunk(dgram)
        if p is None:
            return None
        mtype, mid, seq, data = p
        n = n_chunks(mtype)
        if n == 1:
            return mtype, mid, data
        now = self.clock()
        for k in [k for k, v in self.parts.items() if now - v[0] > self.ttl]:
            del self.parts[k]
        if self.recent:
            for k in [k for k, t in self.recent.items() if now - t > self.remember]:
                del self.recent[k]
        k = (key, mtype, mid)
        if k not in self.parts:
            if seq == n and k in self.recent:                     # the trailing parity chunk of a
                return None                                       # message that just completed:
            self._evict(key, now)                                 # not the start of a new one
            self.parts[k] = (now, {})                             # (a resend's data chunks are)
        got = self.parts[k][1]
        got[seq] = data
        have = [i for i in range(n) if i in got]
        if len(have) == n:
            msg = b"".join(got[i] for i in range(n))
        elif len(have) == n - 1 and n in got:                # one data chunk lost, parity present
            lost = [i for i in range(n) if i not in got][0]
            rebuilt = got[n]
            for i in have:
                rebuilt = _xor(rebuilt, got[i].ljust(CHUNK_DATA, b"\0"))
            if lost == n - 1:
                rebuilt = rebuilt[:TOTAL[mtype] - CHUNK_DATA * (n - 1)]
            got[lost] = rebuilt
            msg = b"".join(got[i] for i in range(n))
        else:
            return None
        del self.parts[k]
        if len(self.recent) >= 4 * self.cap:
            del self.recent[min(self.recent, key=self.recent.get)]
        self.recent[k] = now
        return mtype, mid, msg


# ---------------------------------------------------------------- cookie (stateless)
class CookieMaker:
    """cookie = AES-CMAC(key of the minute, address, port, nonce). The host stores nothing.
    A cookie is good in the minute it was made and the next one."""

    def __init__(self, master=None, clock=time.time):
        self.master = master or os.urandom(16)
        self.clock = clock

    def _key(self, minute):
        return aes_cmac(self.master, b"cookie key" + struct.pack(">Q", minute))

    @staticmethod
    def _peer(peer):
        return ("%s|%d" % (peer[0], peer[1])).encode()

    def make(self, peer, nonce, minute=None):
        m = int(self.clock() // 60) if minute is None else minute
        return aes_cmac(self._key(m), self._peer(peer) + nonce)

    def check(self, peer, nonce, cookie):
        m = int(self.clock() // 60)
        good = False
        for mm in (m, m - 1):                                   # no early exit: same work either way
            good |= ct_equal(self.make(peer, nonce, mm), cookie)
        return good


# ---------------------------------------------------------------- handshake keys
def transcript(cookie, nonce_u, suite, pk, n, mlkem_ct, rsa_ct, nonce_h):
    return hashlib.sha256(b"IPv7-bind-1" + cookie + nonce_u + suite + pk + n
                          + mlkem_ct + rsa_ct + nonce_h).digest()


def transcript_resume(resume_msg, mlkem_ct, nonce_h):
    """The whole RESUME message (binder included) plus the host's ciphertext and nonce: everything
    either side sent before RESUMED's sealed part, under its own context string so a resumption
    transcript can never collide with a bind's."""
    return hashlib.sha256(b"IPv7-resume-1" + resume_msg + mlkem_ct + nonce_h).digest()


def make_binder(resumption_secret, head):
    """AES-CMAC over everything in RESUME before the binder, under a key derived from the
    resumption secret (spec section 7): proves the sender holds the secret that goes with the
    ticket, without ever sending it. A copied ticket alone cannot make one."""
    return aes_cmac(kdf(resumption_secret, b"IPv7 resume", b"binder", 32), b"IPv7 resume binder" + head)


def pinned_cert(host_cert, pin):
    """The host's certificate, checked against the fingerprint the user pinned (`--host-key`, or
    the one in IPv7.key). -> the pysequoia Cert, or a BindError on the 'key' field."""
    import pysequoia as P
    cert = P.Cert.from_bytes(host_cert)
    want = pin.replace(" ", "").replace("-", "").lower()
    if str(cert.fingerprint).lower() != want:
        raise BindError("the certificate does not match the pinned fingerprint", "key")
    return cert


class HsKeys:
    """Handshake sealing keys with implicit counters: only the 16 B tag goes on the wire."""

    def __init__(self, secret, t):
        okm = kdf(secret, t, b"IPv7 handshake", 72)
        self.k = {"h2u": (okm[:32], okm[32:36]), "u2h": (okm[36:68], okm[68:72])}
        self.ctr = {"h2u": 0, "u2h": 0}

    def seal(self, d, aad, data):
        key, salt = self.k[d]
        self.ctr[d] += 1
        return AESGCM(key).encrypt(salt + struct.pack(">Q", self.ctr[d]), data, aad)

    def open(self, d, aad, data):
        key, salt = self.k[d]
        self.ctr[d] += 1
        try:
            return AESGCM(key).decrypt(salt + struct.pack(">Q", self.ctr[d]), data, aad)
        except InvalidTag:
            return None


def _sig_input(t):
    return b"IPv7 bind host signature v1" + t


def sign_transcript(tsk, t):
    import pysequoia as P
    return P.sign(tsk.signer(), _sig_input(t), mode=P.SignatureMode.DETACHED, armor=False)


def verify_transcript(cert, sig, t):
    import pysequoia as P
    try:
        P.verify(_sig_input(t), store=lambda ids: [cert], signature=P.Sig.from_bytes(sig))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- session frames (spec section 5)
class ReplayWindow:
    def __init__(self, size=1024):
        self.size, self.top, self.bits = size, 0, 0

    def ok(self, c):
        if c <= 0:
            return False
        if c > self.top:
            return True
        d = self.top - c
        return d < self.size and not (self.bits >> d) & 1

    def commit(self, c):
        if c > self.top:
            shift = c - self.top
            self.bits = ((self.bits << shift) | 1) & ((1 << self.size) - 1)
            self.top = c
        else:
            self.bits |= 1 << (self.top - c)


class SessionExpired(Exception):
    pass


class Direction:
    """One direction of a session: keys, the one locked counter, the label, the replay window.
    Every carrier (UDP, Ethernet) of a session shares this one counter, so a nonce is never reused."""

    def __init__(self, material):
        self.aead, self.mask = material[:32], material[32:48]
        self.salt, self.label_key = material[48:52], material[52:68]
        self.label = aes_block(self.label_key, bytes(16))[:10]
        self.ctr = 0
        self.lock = threading.Lock()
        self.window = ReplayWindow()

    def label_text(self):
        return groups(self.label)

    def seal(self, payload):
        with self.lock:
            if self.ctr + 1 >= FRAME_LIMIT:
                raise SessionExpired("2^24 frames sent: bind again")
            self.ctr += 1
            c = self.ctr
        ct = AESGCM(self.aead).encrypt(self.salt + struct.pack(">Q", c), payload, b"AA" + self.label)
        mask = aes_block(self.mask, ct[:16])[:8]
        return self.label + _xor(struct.pack(">Q", c), mask) + ct

    def open(self, frame):
        """-> payload, or None. The replay window is committed only after the tag verifies."""
        if len(frame) < 10 + 8 + TAG or frame[:10] != self.label:
            return None
        ct = frame[18:]
        c = struct.unpack(">Q", _xor(frame[10:18], aes_block(self.mask, ct[:16])[:8]))[0]
        if not self.window.ok(c):
            return None
        try:
            pt = AESGCM(self.aead).decrypt(self.salt + struct.pack(">Q", c), ct, b"AA" + self.label)
        except InvalidTag:
            return None
        self.window.commit(c)
        return pt


class Session:
    """Both directions, from one end's point of view."""

    def __init__(self, role, okm, address, uuid, name, resumption_ticket, resumption_secret):
        u2h, h2u = Direction(okm[:68]), Direction(okm[68:136])
        self.tx, self.rx = (u2h, h2u) if role == "user" else (h2u, u2h)
        self.role, self.address, self.uuid, self.name = role, address, uuid, name
        self.resumption_ticket, self.resumption_secret = resumption_ticket, resumption_secret


def session_material(secret, t3):
    return kdf(secret, t3, b"IPv7 session", 136 + 32)


# ---------------------------------------------------------------- tickets and the invite book
def _check_name(name):
    b = name.encode("utf-8")
    if not 1 <= len(b) <= NAME_MAX:
        raise ValueError("a name is 1 to %d bytes" % NAME_MAX)
    return b


class TicketSealer:
    """Tickets are sealed with the host's ticket key: nonce 12 | ciphertext | tag 16, with fixed
    field offsets inside and random-looking fill after them. Nothing is padded with zeros."""

    HEAD = struct.Struct(">BB8sI8s16sB32sH")   # ver kind inv_id gen expiry uuid namelen name sites_len

    def __init__(self, key):
        self.key = key

    def seal(self, size, kind, inv_id, gen, expiry, uuid, name, sites=b"", secret=b""):
        nb = _check_name(name)
        if len(sites) > SITES_MAX:
            raise ValueError("sites list too long")
        plain = self.HEAD.pack(1, kind, inv_id, gen, struct.pack(">Q", int(expiry)), uuid, len(nb),
                               nb.ljust(32, b"\0"), len(sites))
        # fixed layout after the head: sites 512 | secret 32 | fill (random)
        plain += sites + os.urandom(SITES_MAX - len(sites)) + (secret or os.urandom(32))
        room = size - TICKET_NONCE - TAG
        plain += os.urandom(room - len(plain))
        nonce = os.urandom(TICKET_NONCE)
        return nonce + AESGCM(self.key).encrypt(nonce, plain, b"IPv7 ticket %d" % kind)

    def open(self, ticket, kind):
        """-> dict, or None when the ticket is not ours, was changed, or is the wrong kind."""
        if len(ticket) < TICKET_NONCE + TAG + self.HEAD.size + SITES_MAX + 32:
            return None
        try:
            plain = AESGCM(self.key).decrypt(ticket[:TICKET_NONCE], ticket[TICKET_NONCE:],
                                             b"IPv7 ticket %d" % kind)
        except InvalidTag:
            return None
        ver, k, inv_id, gen, expiry, uuid, nl, nb, sl = self.HEAD.unpack(plain[:self.HEAD.size])
        if ver != 1 or k != kind or nl > NAME_MAX or sl > SITES_MAX:
            return None
        off = self.HEAD.size
        sites = plain[off:off + sl]
        secret = plain[off + SITES_MAX:off + SITES_MAX + 32]
        return {"kind": k, "invite_id": inv_id, "generation": gen,
                "expiry": struct.unpack(">Q", expiry)[0], "uuid": uuid,
                "name": nb[:nl].decode("utf-8"), "sites": sites.decode("utf-8") if sites else "",
                "secret": secret}


class InviteBook:
    """The host's small table per invite id: expiry, generation, live session.
    The invite makes generation 1; each resumption makes the next. Only the newest generation works."""

    def __init__(self, ticket_key=None, clock=time.time):
        self.ticket_key = ticket_key or os.urandom(32)
        self.sealer = TicketSealer(self.ticket_key)
        self.clock = clock
        self.rows = {}
        self.lock = threading.Lock()

    def make_invite(self, name, days, sites=()):
        """Made offline by the host. `days` has no default."""
        if not days or days <= 0:
            raise ValueError("an invite needs an expiry in days, more than zero")
        _check_name(name)
        text = ",".join(sites).encode("utf-8")
        inv_id, uuid = os.urandom(8), os.urandom(16)
        expiry = int(self.clock() + days * 86400)
        with self.lock:
            self.rows[inv_id] = {"expiry": expiry, "generation": 0, "uuid": uuid, "name": name}
        return self.sealer.seal(INVITE_TICKET, 1, inv_id, 0, expiry, uuid, name, text), expiry

    def redeem(self, ticket):
        """Open an invite ticket for the bind. -> info dict or None. One use: generation 0 -> 1."""
        info = self.sealer.open(ticket, 1)
        if info is None or info["expiry"] <= self.clock():
            return None
        with self.lock:
            row = self.rows.get(info["invite_id"])
            if row is None or row.get("revoked") or row["generation"] != 0 or row["expiry"] != info["expiry"]:
                return None
            row["generation"] = 1
        info["generation"] = 1
        return info

    def make_resumption(self, info, secret):
        """The ticket READY (or RESUMED) hands the user for coming back: the invite's id, the
        generation it is good for, the same expiry, uuid and name, the sites the invite opens
        (carried forward, so a resumed session keeps them), and the resumption secret."""
        sites = (info.get("sites") or "")
        return self.sealer.seal(RESUME_TICKET, 2, info["invite_id"], info["generation"],
                                info["expiry"], info["uuid"], info["name"],
                                sites.encode("utf-8") if isinstance(sites, str) else bytes(sites), secret)

    def open_resumption(self, ticket):
        """Look at a resumption ticket without using it: -> info (secret included) when it is ours,
        unexpired, not revoked and of the invite's CURRENT generation, else None. The host checks
        the binder with the secret in here before `advance()` spends the generation, so a forged
        or copied-and-stale RESUME can never burn the real user's ticket."""
        info = self.sealer.open(ticket, 2)
        if info is None or info["expiry"] <= self.clock():
            return None
        with self.lock:
            row = self.rows.get(info["invite_id"])
            if row is None or row.get("revoked") or row["generation"] != info["generation"]:
                return None
        return info

    def advance(self, ticket):
        """For resumption: accept only the newest generation, and issue the next."""
        info = self.sealer.open(ticket, 2)
        if info is None or info["expiry"] <= self.clock():
            return None
        with self.lock:
            row = self.rows.get(info["invite_id"])
            if row is None or row.get("revoked") or row["generation"] != info["generation"]:
                return None
            row["generation"] += 1
            info["generation"] = row["generation"]
        return info

    def revoke(self, inv_id):
        """Mark an invite row revoked, by its id (bytes, or hex as `dump()` keys it). A revoked
        invite can never redeem (generation 0) or resume (any later generation) again. This is an
        administrative kill switch, not the no-revoked-list design of spec section 7: short
        expiries are still the only thing an invite relies on by default; this exists so a host
        operator can cut one off right now, between here and that expiry. -> True if the row
        existed."""
        key = bytes.fromhex(inv_id) if isinstance(inv_id, str) else inv_id
        with self.lock:
            row = self.rows.get(key)
            if row is None:
                return False
            row["revoked"] = True
        return True

    def dump(self):
        return {k.hex(): dict(v, uuid=v["uuid"].hex()) for k, v in self.rows.items()}

    def load(self, d):
        self.rows = {bytes.fromhex(k): dict(v, uuid=bytes.fromhex(v["uuid"])) for k, v in d.items()}


# ---------------------------------------------------------------- the host side
class Throttle:
    """Slows down a source address after repeated bad cookies or tickets. Even though a cookie
    (128 bits) and a ticket (sealed with a 128-bit tag) cannot be brute-forced in any realistic
    time, this is defense in depth: it keeps a mistake elsewhere from becoming a fast attack, the
    way a weakened or disabled rate limit turned a short OTP into a crackable one. Exponential
    backoff per source address, capped, and forgotten after a long calm spell so one bad attempt
    years ago never follows a user around."""

    BASE, CAP, FORGET = 1.0, 300.0, 900.0

    def __init__(self, clock=time.time):
        self.clock = clock
        self.fails = {}                      # address -> (count, time of last failure)

    @staticmethod
    def _key(peer):
        return peer[0]                        # the address: a spoofed one never gets a cookie back

    def blocked(self, peer):
        rec = self.fails.get(self._key(peer))
        if rec is None:
            return False
        count, last = rec
        delay = min(self.CAP, self.BASE * (2 ** (count - 1)))
        return self.clock() - last < delay

    def fail(self, peer):
        k = self._key(peer)
        now = self.clock()
        count, last = self.fails.get(k, (0, 0.0))
        if now - last > self.FORGET:
            count = 0
        self.fails[k] = (count + 1, now)

    def clear(self, peer):
        self.fails.pop(self._key(peer), None)

    def purge(self):
        now = self.clock()
        for k in [k for k, (c, t) in self.fails.items() if now - t > self.FORGET]:
            del self.fails[k]


class _Pending:
    def __init__(self, now, accept_chunks, hs, t2, t3_base, secret):
        self.created, self.accept_chunks, self.hs = now, accept_chunks, hs
        self.t2, self.secret = t2, secret


class HostBind:
    """The host's bind logic. handle(peer, datagram) -> (datagrams to send, bound session or None)."""

    MAX_PENDING, PENDING_TTL, DONE_KEEP = 256, 30.0, 64

    def __init__(self, tsk, book, assign, clock=time.time, cookies=None):
        """tsk: the host's OpenPGP secret key (pysequoia Tsk). book: InviteBook.
        assign(name, uuid) -> 8-byte TP/IX address for the new session."""
        self.tsk, self.book, self.assign, self.clock = tsk, book, assign, clock
        self.cookies = cookies or CookieMaker(clock=clock)
        self.reasm = Reassembler(clock=clock)
        self.pending = {}
        self.done = {}
        self.throttle = Throttle(clock=clock)
        self.stats = {"dropped": 0, "cookie_bad": 0, "ticket_bad": 0, "bound": 0, "full": 0, "throttled": 0,
                      "resumed": 0}

    def _drop(self, why=None):
        self.stats["dropped"] += 1
        if why:
            self.stats[why] += 1
        return [], None

    def _purge(self):
        now = self.clock()
        for k in [k for k, v in self.pending.items() if now - v.created > self.PENDING_TTL]:
            del self.pending[k]
        for k in [k for k, v in self.done.items() if now - v[0] > 60]:
            del self.done[k]
        self.throttle.purge()

    def handle(self, peer, dgram):
        r = self.reasm.feed(peer, dgram)
        if r is None:
            return [], None
        mtype, mid, msg = r
        if mtype == HELLO:
            return self._hello(peer, mid, msg)
        if mtype == HELLO2:
            return self._hello2(peer, mid, msg)
        if mtype == FINISHED:
            return self._finished(peer, mid, msg)
        if mtype == RESUME:
            return self._resume(peer, mid, msg)
        return self._drop()

    def _hello(self, peer, mid, msg):
        f = unpack_fields(HELLO, msg)
        cookie = self.cookies.make(peer, f["nonce"])
        return to_chunks(COOKIE, mid, pack_fields(COOKIE, cookie=cookie)), None

    def _hello2(self, peer, mid, msg):
        if self.throttle.blocked(peer):
            return self._drop("throttled")
        f = unpack_fields(HELLO2, msg)
        if not self.cookies.check(peer, f["nonce"], f["cookie"]):
            self.throttle.fail(peer)
            return self._drop("cookie_bad")
        key = (peer, mid)
        if key in self.pending:                                   # retransmit: same answer, no new work
            return list(self.pending[key].accept_chunks), None
        if f["suite"] != struct.pack(">H", SUITE_V1):
            return self._drop()
        n = int.from_bytes(f["rsa_n"], "big")
        if n >> 4095 != 1 or not n & 1:                           # a real 4096-bit odd modulus
            return self._drop()
        self._purge()
        if len(self.pending) >= self.MAX_PENDING:
            return self._drop("full")
        try:
            pk = mlkem.MLKEM1024PublicKey.from_public_bytes(f["mlkem_pk"])
            rpk = rsa.RSAPublicNumbers(65537, n).public_key()
        except Exception:
            return self._drop()
        ss_k, mlkem_ct = pk.encapsulate()
        secret32 = os.urandom(32)
        rsa_ct = rpk.encrypt(secret32, _oaep())
        nonce_h = os.urandom(16)
        t = transcript(f["cookie"], f["nonce"], f["suite"], f["mlkem_pk"], f["rsa_n"],
                       mlkem_ct, rsa_ct, nonce_h)
        secret = ss_k + secret32
        hs = HsKeys(secret, t)
        sig = sign_transcript(self.tsk, t)
        if len(sig) > SIG_FIELD - 2:
            raise BindError("host signature is too large for the fixed field")
        field = struct.pack(">H", len(sig)) + sig
        field += os.urandom(SIG_FIELD - len(field))
        sealed = hs.seal("h2u", b"ACCEPT" + t, field)
        msg_out = pack_fields(ACCEPT, mlkem_ct=mlkem_ct, rsa_ct=rsa_ct, nonce=nonce_h, sealed=sealed)
        chunks = to_chunks(ACCEPT, mid, msg_out)
        t2 = hashlib.sha256(t + sealed).digest()
        self.pending[key] = _Pending(self.clock(), chunks, hs, t2, None, secret)
        return list(chunks), None

    def _finished(self, peer, mid, msg):
        key = (peer, mid)
        digest = hashlib.sha256(msg).digest()
        d = self.done.get(key)
        if d is not None and d[1] == digest:                      # READY was lost: send it again
            return list(d[2]), None
        if self.throttle.blocked(peer):
            return self._drop("throttled")
        p = self.pending.get(key)
        if p is None:
            return self._drop()
        f = unpack_fields(FINISHED, msg)
        ticket = p.hs.open("u2h", b"FINISHED" + p.t2, f["sealed"])
        if ticket is None:
            self.throttle.fail(peer)
            return self._drop("ticket_bad")
        info = self.book.redeem(ticket)
        if info is None:
            self.throttle.fail(peer)
            return self._drop("ticket_bad")
        self.throttle.clear(peer)
        del self.pending[key]
        t3 = hashlib.sha256(p.t2 + msg).digest()
        okm = session_material(p.secret, t3)
        res_secret = okm[136:168]
        r_ticket = self.book.make_resumption(info, res_secret)
        try:
            address = self.assign(info["name"], info["uuid"])
        except BindError:                                         # "the host is full": the serve
            return self._drop("full")                             # loop must not die over it
        if len(address) != ADDR_LEN:
            raise BindError("assign() must return an 8-byte TP/IX address", "route")
        sealed = p.hs.seal("h2u", b"READY" + t3, address + info["uuid"] + r_ticket)
        chunks = to_chunks(READY, mid, pack_fields(READY, sealed=sealed))
        self._remember(key, digest, chunks)
        sess = Session("host", okm, address, info["uuid"], info["name"], r_ticket, res_secret)
        sess.sites = info["sites"]
        sess.peer = peer
        sess.resumed = False
        self.stats["bound"] += 1
        return list(chunks), sess

    def _remember(self, key, digest, chunks):
        """Keep the answer to a completed FINISHED or RESUME for a while, so a resend of the very
        same message (the answer was lost) gets the very same answer, without the invite's
        generation ever being spent twice."""
        if len(self.done) >= self.DONE_KEEP:
            self.done.pop(min(self.done, key=lambda k: self.done[k][0]))
        self.done[key] = (self.clock(), digest, chunks)

    def _resume(self, peer, mid, msg):
        """Spec section 7. The checks run in an order that spends nothing until everything that
        can be checked has been: the cookie (address proof), then the ticket opens and is of the
        invite's current generation, then the binder (the sender holds the secret inside that
        ticket), then the fresh ML-KEM key parses -- and only then `advance()` moves the
        generation on, so no forgery, replay or damaged copy can burn the real user's ticket."""
        key = (peer, mid)
        digest = hashlib.sha256(msg).digest()
        d = self.done.get(key)
        if d is not None and d[1] == digest:                      # RESUMED was lost: send it again
            return list(d[2]), None
        if self.throttle.blocked(peer):
            return self._drop("throttled")
        f = unpack_fields(RESUME, msg)
        if not self.cookies.check(peer, f["nonce"], f["cookie"]):
            self.throttle.fail(peer)
            return self._drop("cookie_bad")
        if f["suite"] != struct.pack(">H", SUITE_V1):
            return self._drop()
        info = self.book.open_resumption(f["ticket"])
        if info is None:
            self.throttle.fail(peer)
            return self._drop("ticket_bad")
        if not ct_equal(make_binder(info["secret"], msg[:-BINDER]), f["binder"]):
            self.throttle.fail(peer)
            return self._drop("ticket_bad")
        try:
            pk = mlkem.MLKEM1024PublicKey.from_public_bytes(f["mlkem_pk"])
        except Exception:
            return self._drop()
        self._purge()
        info = self.book.advance(f["ticket"])                     # the ticket just shown is now dead
        if info is None:
            return self._drop("ticket_bad")
        ss_k, mlkem_ct = pk.encapsulate()
        nonce_h = os.urandom(16)
        t = transcript_resume(msg, mlkem_ct, nonce_h)
        secret = ss_k + info["secret"]                            # fresh ML-KEM + the carried-forward secret
        hs = HsKeys(secret, t)
        okm = session_material(secret, t)
        res_secret = okm[136:168]
        r_ticket = self.book.make_resumption(info, res_secret)   # for the generation after this one
        try:
            address = self.assign(info["name"], info["uuid"])
        except BindError:
            return self._drop("full")
        if len(address) != ADDR_LEN:
            raise BindError("assign() must return an 8-byte TP/IX address", "route")
        sealed = hs.seal("h2u", b"RESUMED" + t, address + info["uuid"] + r_ticket)
        chunks = to_chunks(RESUMED, mid, pack_fields(RESUMED, mlkem_ct=mlkem_ct, nonce=nonce_h, sealed=sealed))
        self.throttle.clear(peer)
        self._remember(key, digest, chunks)
        sess = Session("host", okm, address, info["uuid"], info["name"], r_ticket, res_secret)
        sess.sites = info["sites"]
        sess.peer = peer
        sess.resumed = True
        self.stats["bound"] += 1
        self.stats["resumed"] += 1
        return list(chunks), sess


# ---------------------------------------------------------------- the client side
class ClientBind:
    """The user's bind logic. Call start(), then feed every received datagram to receive().
    Each call returns the datagrams to send. When `session` is set the bind is done; when
    `error` is set it failed and `error.field` says which field (route, key or ticket)."""

    def __init__(self, host_cert, pin, invite_ticket, peer=None, rsa_key=None, progress=None,
                 clock=time.time):
        """host_cert: the host's public OpenPGP certificate bytes (from IPv7.key).
        pin: the host fingerprint the user pinned. The certificate must match it.
        progress(step) is called at each step: hello, cookie, keygen, hello2, accept, finished,
        ready -- the console's own loading display hangs off it."""
        if len(invite_ticket) != INVITE_TICKET:
            raise ValueError("an invite ticket is %d bytes" % INVITE_TICKET)
        self.cert = pinned_cert(host_cert, pin)
        self.pin = pin.replace(" ", "").replace("-", "").lower()
        self.ticket = invite_ticket
        self.rsa_key = rsa_key
        self.progress = progress or (lambda text: None)
        self.reasm = Reassembler(clock=clock)
        self.mid = struct.unpack(">H", os.urandom(2))[0]
        self.nonce = os.urandom(16)
        self.state = "new"
        self.session = None
        self.error = None
        self.cookie = None
        self.cookie_peer_note = "unverified"
        self.last = []

    def start(self):
        self.state = "hello"
        self.last = to_chunks(HELLO, self.mid, pack_fields(HELLO, nonce=self.nonce))
        self.progress("hello")
        return list(self.last)

    def resend(self):
        return list(self.last)

    def _fail(self, text, field):
        self.error = BindError(text, field)
        self.state = "failed"
        return []

    def receive(self, dgram):
        if self.state in ("done", "failed"):
            return []
        r = self.reasm.feed("host", dgram)
        if r is None:
            return []
        mtype, mid, msg = r
        if mid != self.mid:
            return []
        if mtype == COOKIE and self.state == "hello":
            return self._on_cookie(msg)
        if mtype == ACCEPT and self.state == "hello2":
            return self._on_accept(msg)
        if mtype == READY and self.state == "finished":
            return self._on_ready(msg)
        return []

    def _on_cookie(self, msg):
        self.cookie = unpack_fields(COOKIE, msg)["cookie"]
        self.progress("cookie")
        self.progress("keygen")
        if self.rsa_key is None:
            self.rsa_key = rsa.generate_private_key(65537, 4096)
        self.mlkem = mlkem.MLKEM1024PrivateKey.generate()
        self.pk = self.mlkem.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
        self.n = self.rsa_key.public_key().public_numbers().n.to_bytes(RSA_N, "big")
        self.suite = struct.pack(">H", SUITE_V1)
        m = pack_fields(HELLO2, cookie=self.cookie, nonce=self.nonce, suite=self.suite,
                        mlkem_pk=self.pk, rsa_n=self.n)
        self.state = "hello2"
        self.last = to_chunks(HELLO2, self.mid, m)
        self.progress("hello2")
        return list(self.last)

    def _on_accept(self, msg):
        f = unpack_fields(ACCEPT, msg)
        if f["nonce"] == bytes(16):
            return []
        try:
            ss_k = self.mlkem.decapsulate(f["mlkem_ct"])
            secret32 = self.rsa_key.decrypt(f["rsa_ct"], _oaep())
        except Exception:
            return self._fail("key exchange failed", "key")
        t = transcript(self.cookie, self.nonce, self.suite, self.pk, self.n,
                       f["mlkem_ct"], f["rsa_ct"], f["nonce"])
        secret = ss_k + secret32
        hs = HsKeys(secret, t)
        field = hs.open("h2u", b"ACCEPT" + t, f["sealed"])
        if field is None:
            return self._fail("ACCEPT did not open", "key")
        (sl,) = struct.unpack(">H", field[:2])
        if sl > SIG_FIELD - 2 or not verify_transcript(self.cert, field[2:2 + sl], t):
            return self._fail("host signature does not match the pinned key", "route")
        self.rsa_key = None                                       # the ephemeral RSA key is destroyed
        self.progress("accept")
        t2 = hashlib.sha256(t + f["sealed"]).digest()
        sealed = hs.seal("u2h", b"FINISHED" + t2, self.ticket)
        fin = pack_fields(FINISHED, sealed=sealed)
        self.hs, self.secret, self.t2, self.fin = hs, secret, t2, fin
        self.state = "finished"
        self.last = to_chunks(FINISHED, self.mid, fin)
        self.progress("finished")
        return list(self.last)

    def _on_ready(self, msg):
        f = unpack_fields(READY, msg)
        t3 = hashlib.sha256(self.t2 + self.fin).digest()
        plain = self.hs.open("h2u", b"READY" + t3, f["sealed"])
        if plain is None:
            return self._fail("READY did not open", "ticket")
        address, uuid = plain[:ADDR_LEN], plain[ADDR_LEN:ADDR_LEN + UUID_LEN]
        r_ticket = plain[ADDR_LEN + UUID_LEN:]
        okm = session_material(self.secret, t3)
        self.session = Session("user", okm, address, uuid, None, r_ticket, okm[136:168])
        self.state = "done"
        self.secret = None
        self.progress("ready")
        return []

    resumed = False

    def result_line(self, show=dotted):
        return _result_line(self, show)


def _result_line(client, show=dotted):
    """Console line of spec section 13, shared by a bind and a resumption. No secret is printed:
    the ticket only says found (or resumed)."""
    if client.session is not None:
        return "route %s | key %s | ticket %s - !MATCH!" % (
            show(client.session.address), client.session.rx.label_text(),
            "resumed" if client.resumed else "found")
    bad = client.error.field if client.error else "key"
    return "route %s | key %s | ticket %s - !NO MATCH! (%s)" % ("?", "?", "?", bad)


class ClientResume:
    """The user coming back (spec section 7): HELLO/COOKIE as for a bind, then RESUME in place of
    HELLO2, answered by RESUMED in place of ACCEPT and READY. The same interface as `ClientBind`
    -- start(), resend(), receive(), .session, .error, result_line() -- so whatever drives one
    drives the other without knowing which it has.

    The host is authenticated by the RESUMED seal opening at all: its keys mix the fresh ML-KEM
    secret with the resumption secret, which only the host that issued the ticket can read out
    of it (the ticket is sealed under that host's ticket key). An impostor with a copied ticket
    cannot answer, so the client gets no session from one, and sends it nothing it did not
    already have."""

    resumed = True

    def __init__(self, resumption_ticket, resumption_secret, progress=None, clock=time.time):
        if len(resumption_ticket) != RESUME_TICKET:
            raise ValueError("a resumption ticket is %d bytes" % RESUME_TICKET)
        if len(resumption_secret) != 32:
            raise ValueError("a resumption secret is 32 bytes")
        self.ticket, self.secret_r = resumption_ticket, resumption_secret
        self.progress = progress or (lambda text: None)
        self.reasm = Reassembler(clock=clock)
        self.mid = struct.unpack(">H", os.urandom(2))[0]
        self.nonce = os.urandom(16)
        self.state, self.session, self.error, self.last = "new", None, None, []

    def start(self):
        self.state = "hello"
        self.last = to_chunks(HELLO, self.mid, pack_fields(HELLO, nonce=self.nonce))
        self.progress("hello")
        return list(self.last)

    def resend(self):
        return list(self.last)

    def _fail(self, text, field):
        self.error = BindError(text, field)
        self.state = "failed"
        return []

    def receive(self, dgram):
        if self.state in ("done", "failed"):
            return []
        r = self.reasm.feed("host", dgram)
        if r is None:
            return []
        mtype, mid, msg = r
        if mid != self.mid:
            return []
        if mtype == COOKIE and self.state == "hello":
            return self._on_cookie(msg)
        if mtype == RESUMED and self.state == "resume":
            return self._on_resumed(msg)
        return []

    def _on_cookie(self, msg):
        self.cookie = unpack_fields(COOKIE, msg)["cookie"]
        self.progress("cookie")
        self.mlkem = mlkem.MLKEM1024PrivateKey.generate()      # fresh: a replayed RESUME earns nothing
        self.pk = self.mlkem.public_key().public_bytes(S.Encoding.Raw, S.PublicFormat.Raw)
        self.suite = struct.pack(">H", SUITE_V1)
        head = self.cookie + self.nonce + self.suite + self.pk + self.ticket
        self.resume_msg = head + make_binder(self.secret_r, head)
        self.state = "resume"
        self.last = to_chunks(RESUME, self.mid, self.resume_msg)
        self.progress("resume")
        return list(self.last)

    def _on_resumed(self, msg):
        f = unpack_fields(RESUMED, msg)
        try:
            ss_k = self.mlkem.decapsulate(f["mlkem_ct"])
        except Exception:
            return self._fail("key exchange failed", "key")
        t = transcript_resume(self.resume_msg, f["mlkem_ct"], f["nonce"])
        secret = ss_k + self.secret_r
        hs = HsKeys(secret, t)
        plain = hs.open("h2u", b"RESUMED" + t, f["sealed"])
        if plain is None:
            return self._fail("RESUMED did not open: not the host this session came from", "route")
        address, uuid = plain[:ADDR_LEN], plain[ADDR_LEN:ADDR_LEN + UUID_LEN]
        r_ticket = plain[ADDR_LEN + UUID_LEN:]
        okm = session_material(secret, t)
        self.session = Session("user", okm, address, uuid, None, r_ticket, okm[136:168])
        self.state = "done"
        self.secret_r = None
        self.progress("ready")
        return []

    def result_line(self, show=dotted):
        return _result_line(self, show)


def run_pair(client, host, peer=("203.0.113.9", 40000), drop=None):
    """Drive a client and a host against each other in memory. `drop(i, direction, dgram)` -> True
    drops a datagram. Returns (client, host session)."""
    to_host, to_user, i, hsess = client.start(), [], 0, None
    for _ in range(40):
        if not to_host and not to_user:
            break
        out_u = []
        for d in to_host:
            i += 1
            if drop and drop(i, "u2h", d):
                continue
            out, s = host.handle(peer, d)
            out_u += out
            hsess = s or hsess
        to_host = []
        for d in out_u:
            i += 1
            if drop and drop(i, "h2u", d):
                continue
            to_host += client.receive(d)
        to_user = []
    return client, hsess


# ---------------------------------------------------------------- selftest
def selftest(full=False):
    import pysequoia as P
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    def raises(fn, exc=Exception):
        try:
            fn()
        except exc:
            return True
        return False

    now = [1_800_000_000.0]
    clock = lambda: now[0]                                      # noqa: E731
    suite = P.CipherSuite.RSA4k if full else P.CipherSuite.RSA2k
    print(MARK_STEP + "making a host key (%s) and two ephemeral RSA-4096 keys ..." % ("RSA-4096" if full else "RSA-2048"))
    tsk = P.Tsk.generate("IPv7 test host", cipher_suite=suite, profile=P.Profile.RFC9580)
    cert = bytes(tsk.extract_certificate())
    pin = str(tsk.extract_certificate().fingerprint)
    rsa_a, rsa_b = rsa.generate_private_key(65537, 4096), rsa.generate_private_key(65537, 4096)
    peer = ("203.0.113.9", 40000)
    counter = [0]

    def assign(name, uuid):
        counter[0] += 1
        return bytes([172, 16, 0, counter[0], 1, 0, 0, 2])

    def world(days=30, name="Alice", sites=("xag",)):
        book = InviteBook(clock=clock)
        host = HostBind(tsk, book, assign, clock=clock)
        ticket, _ = book.make_invite(name, days, sites)
        return book, host, ticket

    def client(ticket, key=None):
        return ClientBind(cert, pin, ticket, rsa_key=key or rsa_a, clock=clock)

    # --- messages and chunks
    check("HELLO2 is 2114 B and ACCEPT 2776 B", TOTAL[HELLO2] == 2114 and TOTAL[ACCEPT] == 2776)
    check("invite ticket 1174 B and resumption ticket 1150 B fill the datagram",
          INVITE_TICKET == 1174 and RESUME_TICKET == 1150
          and INVITE_TICKET + TAG == CHUNK_DATA and ADDR_LEN + UUID_LEN + RESUME_TICKET == INVITE_TICKET)
    m = pack_fields(HELLO2, cookie=b"c" * 16, nonce=b"n" * 16, suite=b"\0\1", mlkem_pk=b"k" * 1568,
                    rsa_n=b"r" * 512)
    check("fields come back at their offsets", unpack_fields(HELLO2, m)["rsa_n"] == b"r" * 512
          and unpack_fields(HELLO2, m)["suite"] == b"\0\1")
    check("a wrong field width is refused", raises(lambda: pack_fields(HELLO, nonce=b"x"), ValueError))
    for mt in (HELLO2, ACCEPT):
        data = os.urandom(TOTAL[mt])
        ch = to_chunks(mt, 7, data)
        check("%s: %d chunks plus parity, in order" % (MESSAGES[mt][0], n_chunks(mt)),
              len(ch) == n_chunks(mt) + 1 and all(parse_chunk(c) for c in ch))
        ok = True
        for lost in range(len(ch)):
            r = Reassembler()
            res = None
            for i, c in enumerate(ch):
                if i != lost:
                    res = r.feed("p", c) or res
            ok &= res is not None and res[2] == data
        check("%s: any one lost chunk is rebuilt (last and parity included)" % MESSAGES[mt][0], ok)
        r, res = Reassembler(), None
        for c in ch[2:]:                                      # only the parity chunk (HELLO2) or last data + parity (ACCEPT)
            res = r.feed("p", c) or res
        check("%s: two lost chunks are not rebuilt" % MESSAGES[mt][0], res is None)
        r, res = Reassembler(), None
        for c in [ch[0], ch[0]] + ch[1:]:
            res = r.feed("p", c) or res
        check("%s: a duplicate chunk does no harm" % MESSAGES[mt][0], res is not None and res[2] == data)
    check("short, long and unknown chunks are dropped",
          parse_chunk(b"") is None and parse_chunk(b"\x63\0\0\0" + bytes(16)) is None
          and parse_chunk(to_chunks(HELLO, 1, bytes(16))[0] + b"x") is None
          and parse_chunk(to_chunks(HELLO, 1, bytes(16))[0][:-1]) is None
          and parse_chunk(struct.pack(">BHB", HELLO2, 1, 9) + bytes(1190)) is None)
    r = Reassembler(cap=2, per_source=8)
    for mid in range(5):
        r.feed("p", to_chunks(HELLO2, mid, bytes(TOTAL[HELLO2]))[0])
    check("partial messages are capped, the oldest evicted first", len(r.parts) == 2
          and {k[2] for k in r.parts} == {3, 4})
    r = Reassembler(cap=64, per_source=3)
    for mid in range(6):
        r.feed("one source", to_chunks(HELLO2, mid, bytes(TOTAL[HELLO2]))[0])
    check("one source gets at most per_source partials, its own oldest evicted first",
          len(r.parts) == 3 and {k[2] for k in r.parts} == {3, 4, 5})
    r = Reassembler(cap=3)
    good = to_chunks(HELLO2, 77, os.urandom(TOTAL[HELLO2]))
    for i in range(3):                                            # three strangers fill the table
        r.feed("stranger%d" % i, to_chunks(HELLO2, i, bytes(TOTAL[HELLO2]))[0])
    res = None
    for c in good:
        res = r.feed("honest", c) or res
    check("a full table does not refuse an honest message: its chunks arrive together and complete",
          res is not None and res[1] == 77)
    r = Reassembler(cap=64)
    full = to_chunks(HELLO2, 5, os.urandom(TOTAL[HELLO2]))
    for c in full:
        r.feed("p", c)
    check("the trailing parity chunk of a message that just completed leaves no partial behind "
          "(the leak that let 64 HELLO2s block every bind for 30 s)", len(r.parts) == 0)
    res = None
    for c in full:                                                # the whole message sent again
        res = r.feed("p", c) or res
    check("... but a full resend of that message still reassembles (READY-lost / RESUMED-lost paths)",
          res is not None and res[1] == 5 and len(r.parts) == 0)
    check("every chunk fits one datagram", all(len(c) <= CHUNK_HEAD + CHUNK_DATA
                                                  for c in to_chunks(ACCEPT, 1, bytes(TOTAL[ACCEPT]))))

    # --- cookie
    cm = CookieMaker(clock=clock)
    n0 = os.urandom(16)
    c0 = cm.make(peer, n0)
    check("cookie: same address, port and nonce is good", cm.check(peer, n0, c0))
    check("cookie: other address refused", not cm.check(("203.0.113.10", 40000), n0, c0))
    check("cookie: other port refused", not cm.check((peer[0], 40001), n0, c0))
    check("cookie: other nonce refused", not cm.check(peer, os.urandom(16), c0))
    check("cookie: a flipped bit is refused", not cm.check(peer, n0, bytes([c0[0] ^ 1]) + c0[1:]))
    now[0] += 60
    check("cookie: still good in the next minute", cm.check(peer, n0, c0))
    now[0] += 120
    check("cookie: refused after two more minutes", not cm.check(peer, n0, c0))
    check("cookie: a restarted host (new key) refuses old cookies", not CookieMaker(clock=clock).check(peer, n0, cm.make(peer, n0)))
    now[0] = 1_800_000_000.0

    # --- a full bind
    book, host, ticket = world()
    c = client(ticket)
    steps = []
    c, hs = run_pair(c, host, peer, drop=lambda i, d, x: steps.append((d, len(x))) and False)
    check("bind completes on both sides", c.session is not None and hs is not None)
    check("both ends agree on address and uuid", c.session.address == hs.address and c.session.uuid == hs.uuid
          and c.session.address == bytes([172, 16, 0, 1, 1, 0, 0, 2]))
    check("the host sees the invite's name and sites", hs.name == "Alice" and hs.sites == "xag")
    check("user transmit label equals host receive label, and the two directions differ",
          c.session.tx.label == hs.rx.label and c.session.rx.label == hs.tx.label
          and c.session.tx.label != c.session.rx.label)
    check("label shows as 4 groups of 4 letters", len(c.session.rx.label_text().split("-")) == 4
          and all(len(g) == 4 for g in c.session.rx.label_text().split("-"))
          and all(ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-" for ch in c.session.rx.label_text()))
    fr = c.session.tx.seal(b"hello host")
    check("frame: user to host opens", hs.rx.open(fr) == b"hello host")
    fr2 = hs.tx.seal(b"hello user")
    check("frame: host to user opens", c.session.rx.open(fr2) == b"hello user")
    check("frame: replay refused", hs.rx.open(fr) is None)
    bad = bytearray(c.session.tx.seal(b"x")); bad[25] ^= 1
    check("frame: a flipped bit refused", hs.rx.open(bytes(bad)) is None)
    f3 = c.session.tx.seal(b"counter")
    check("frame: the counter is masked on the wire",
          struct.unpack(">Q", f3[10:18])[0] != c.session.tx.ctr)
    check("frame: overhead is 34 B", len(f3) == len(b"counter") + 34)
    check("frame: a frame of the wrong direction is refused", c.session.rx.open(f3) is None)
    line = c.result_line()
    check("console line ends !MATCH! and shows the label", line.endswith("- !MATCH!")
          and c.session.rx.label_text() in line and "ticket found" in line)
    check("no key material or ticket in the console line",
          ticket.hex() not in line and c.session.rx.aead.hex() not in line)
    sizes = [n for d, n in steps]
    check("COOKIE reply is no larger than HELLO", sizes[1] <= sizes[0])
    check("FINISHED and READY each fill exactly one datagram",
          (CHUNK_HEAD + CHUNK_DATA) in sizes)
    check("ephemeral RSA key dropped after the bind", c.rsa_key is None and c.secret is None)

    # --- counter under threads
    d = c.session.tx
    seen, lk = [], threading.Lock()

    def worker():
        for _ in range(500):
            f = d.seal(b"t")
            with lk:
                seen.append(f[10:18])
    ths = [threading.Thread(target=worker) for _ in range(4)]
    [t.start() for t in ths]; [t.join() for t in ths]
    check("four threads never share a counter", len(set(seen)) == len(seen) == 2000)
    d.ctr = FRAME_LIMIT - 2
    d.seal(b"last")
    check("a session ends after 2^24 frames", raises(lambda: d.seal(b"more"), SessionExpired))
    w = ReplayWindow(8)
    w.commit(10)
    check("replay window: old, repeated and new", not w.ok(10) and not w.ok(2) and w.ok(9) and w.ok(11) and not w.ok(0))

    # --- tickets
    book, host, ticket = world()
    check("the same invite twice gives different bytes", book.make_invite("Alice", 30)[0] != ticket)
    runs = [len(x) for x in __import__("re").findall(b"\0+", ticket)]
    check("no zero fill in a ticket", (max(runs) if runs else 0) < 8)
    check("days is required and must be above zero", raises(lambda: book.make_invite("A", 0), ValueError)
          and raises(lambda: book.make_invite("A", None), ValueError))
    check("a name over 32 bytes or empty is refused", raises(lambda: book.make_invite("x" * 33, 1), ValueError)
          and raises(lambda: book.make_invite("", 1), ValueError))
    check("a 32-byte name works", book.make_invite("n" * 32, 1)[0] is not None)
    check("sites are limited to 512 B", raises(lambda: book.make_invite("A", 1, ["s" * 600]), ValueError))
    bad = bytearray(ticket); bad[100] ^= 1
    check("a changed ticket is refused", book.redeem(bytes(bad)) is None)
    other = InviteBook(clock=clock)
    check("a ticket from another host is refused", other.redeem(ticket) is None)
    check("the resumption kind does not open as an invite", book.sealer.open(ticket, 2) is None)
    info = book.redeem(ticket)
    check("invite redeems once (generation 0 to 1)", info is not None and info["generation"] == 1
          and book.redeem(ticket) is None)
    r1 = book.make_resumption(info, b"S" * 32)
    check("resumption ticket opens and keeps the invite's expiry",
          book.sealer.open(r1, 2)["expiry"] == info["expiry"] and book.sealer.open(r1, 2)["secret"] == b"S" * 32)
    n2 = book.advance(r1)
    check("resumption makes generation 2", n2 is not None and n2["generation"] == 2)
    check("the older copy of a resumption ticket is dead", book.advance(r1) is None)
    dump = book.dump()
    book2 = InviteBook(ticket_key=book.ticket_key, clock=clock)
    book2.load(dump)
    check("invite book survives dump and load", book2.rows == book.rows)
    book3, host3, t3 = world(days=1)
    now[0] += 86400 + 1
    check("an expired invite is refused", book3.redeem(t3) is None)
    now[0] = 1_800_000_000.0

    # --- revoke (an admin kill switch, not the no-revoked-list default design)
    book4, host4, t4 = world(name="Carol")
    inv_id4 = next(iter(book4.rows))
    check("revoke on an unknown id does nothing and says so", book4.revoke(os.urandom(8)) is False)
    check("revoke on a real id succeeds", book4.revoke(inv_id4) is True)
    check("a revoked invite cannot redeem, even though it was never used", book4.redeem(t4) is None)
    book5, host5, t5 = world(name="Dave")
    info5 = book5.redeem(t5)
    r5 = book5.make_resumption(info5, b"S" * 32)
    inv_id5 = next(iter(book5.rows))
    check("a revoked invite's already-issued resumption ticket is cut off too",
          book5.advance(r5) is not None and book5.revoke(inv_id5) and book5.advance(book5.make_resumption(info5, b"S" * 32)) is None)
    book6 = InviteBook(ticket_key=book4.ticket_key, clock=clock)
    book6.load(book4.dump())
    check("a reloaded book keeps the revoked flag, and the id round-trips through dump()'s hex keys",
          book6.rows[inv_id4]["revoked"] is True and book6.revoke(inv_id4.hex()) is True)

    # --- refused binds
    book, host, ticket = world()
    c1, hs1 = run_pair(client(ticket), host, peer)
    c2, hs2 = run_pair(client(ticket, rsa_b), host, ("203.0.113.10", 40001))
    check("a used invite cannot bind a second device", c1.session is not None and c2.session is None
          and hs2 is None and host.stats["ticket_bad"] >= 1)
    check("the second device gets no READY and no session", c2.state == "finished" and c2.session is None)
    book, host, ticket = world()
    other_book = InviteBook(clock=clock)
    foreign, _ = other_book.make_invite("Eve", 30)
    ce, hse = run_pair(client(foreign), host, peer)
    check("a ticket from another host does not bind", ce.session is None and hse is None)
    check("wrong pin is refused before any packet", raises(lambda: ClientBind(cert, "ab" * 32, ticket), BindError))
    tsk2 = P.Tsk.generate("Impostor", cipher_suite=P.CipherSuite.RSA2k, profile=P.Profile.RFC9580)
    imp_host = HostBind(tsk2, book, assign, clock=clock)
    ci, hsi = run_pair(client(ticket), imp_host, peer)
    check("a host with another key is caught: !NO MATCH! on the route, no ticket sent",
          ci.session is None and ci.error is not None and ci.error.field == "route"
          and "!NO MATCH!" in ci.result_line() and hsi is None and ticket not in b"".join(ci.last))
    check("the invite stays unused after an impostor", book.rows and all(r["generation"] == 0 for r in book.rows.values()))

    # --- loss and damage
    for n_drop in range(1, 12):
        book, host, ticket = world()
        counts = {"u2h": 0, "h2u": 0}
        seq = []

        def drop(i, d, x, n_drop=n_drop):
            seq.append(i)
            return i == n_drop
        cc, hh = run_pair(client(ticket), host, peer, drop=drop)
        if cc.session is None:
            # a lost single-chunk message needs a resend by the caller
            for _ in range(3):
                res = cc.resend()
                if not res:
                    break
                outs = []
                for d_ in res:
                    o, s = host.handle(peer, d_)
                    outs += o
                    hh = s or hh
                for d_ in outs:
                    cc.receive(d_)
                if cc.session is not None:
                    break
        if not (cc.session is not None and cc.session.address == (hh.address if hh else None)):
            check("one lost datagram (number %d) is survived" % n_drop, False)
            break
    else:
        check("any one lost datagram of the first 11 is survived (parity or resend)", True)

    book, host, ticket = world()
    cc = client(ticket)
    out = cc.start()
    ck, _ = host.handle(peer, out[0])
    hello2 = cc.receive(ck[0])
    acc = []
    for d_ in hello2:
        o, _ = host.handle(peer, d_)
        acc += o
    fin = []
    for d_ in acc:
        fin += cc.receive(d_)
    ready, hsess = host.handle(peer, fin[0])
    before = dict(book.rows)
    check("READY lost: the user resends FINISHED and the host answers again without using the invite twice",
          hsess is not None and cc.session is None)
    again, s2 = host.handle(peer, cc.resend()[0])
    for d_ in again:
        cc.receive(d_)
    check("the bind completes from the resend", cc.session is not None and s2 is None
          and book.rows == before and host.stats["bound"] == 1)
    book, host, ticket = world()
    cc = client(ticket)
    o, _ = host.handle(peer, cc.start()[0])
    h2 = cc.receive(o[0])
    first, again = [], []
    for d_ in h2:
        first += host.handle(peer, d_)[0]
    for d_ in h2:
        again += host.handle(peer, d_)[0]
    check("HELLO2 sent twice gets the very same ACCEPT chunks, no new key work",
          first and set(again) <= set(first) and len(host.pending) == 1)

    # flipped bits in each ACCEPT chunk are caught
    allok = True
    for target in range(4):
        book, host, ticket = world()
        cc = client(ticket)
        o, _ = host.handle(peer, cc.start()[0])
        h2 = cc.receive(o[0])
        acc = []
        for d_ in h2:
            oo, _ = host.handle(peer, d_)
            acc += oo
        if target < len(acc):
            b = bytearray(acc[target]); b[CHUNK_HEAD + 5] ^= 1
            acc[target] = bytes(b)
        for d_ in acc:
            cc.receive(d_)
        allok &= cc.session is None
    check("a flipped bit in any ACCEPT chunk stops the bind", allok)

    # cookie, flood and strangers
    book, host, ticket = world()
    cc = client(ticket)
    o, _ = host.handle(peer, cc.start()[0])
    h2 = cc.receive(o[0])
    res = []
    for d_ in h2:
        res += host.handle(("198.51.100.7", 40000), d_)[0]
    check("HELLO2 from another address gets nothing", res == [] and host.stats["cookie_bad"] >= 1)
    check("a stray FINISHED from a stranger is dropped",
          host.handle(("198.51.100.7", 1), to_chunks(FINISHED, 5, os.urandom(1190))[0]) == ([], None))
    check("a garbage datagram is dropped", host.handle(peer, b"\xffgarbage") == ([], None))
    book, host, ticket = world()
    host.MAX_PENDING = 3
    cc = client(ticket)
    o, _ = host.handle(peer, cc.start()[0])
    h2 = cc.receive(o[0])
    msg = b"".join(parse_chunk(x)[3] for x in h2[:2])
    for mid in range(10, 15):
        for ch in to_chunks(HELLO2, mid, msg):
            host.handle(peer, ch)
    check("pending binds are capped", len(host.pending) == 3 and host.stats["full"] == 2)
    now[0] += 31
    host.handle(peer, to_chunks(HELLO2, 99, msg)[0])
    for ch in to_chunks(HELLO2, 99, msg)[1:]:
        host.handle(peer, ch)
    check("old pending binds time out", all(now[0] - p.created < 31 for p in host.pending.values()))
    now[0] = 1_800_000_000.0

    # key separation and a fresh run
    b1, h1, t1 = world(); b2, h2_, t2 = world()
    ca, _ = run_pair(client(t1), h1, peer)
    cb, _ = run_pair(client(t2, rsa_b), h2_, peer)
    check("two binds give different labels and keys", ca.session.rx.label != cb.session.rx.label
          and ca.session.rx.aead != cb.session.rx.aead and ca.session.rx.aead != ca.session.tx.aead)
    b4, h4, t4 = world()
    c4 = ClientBind(cert, pin, t4, clock=clock)
    c4, hs4 = run_pair(c4, h4, peer)
    check("the default path makes its own RSA-4096 key", c4.session is not None)

    # --- throttle (the GitHub-style lesson: a weakened rate limit turns a small guess into a win)
    th = Throttle(clock=clock)
    peer_a, peer_b = ("203.0.113.50", 1), ("203.0.113.51", 1)
    check("a fresh address is never blocked", not th.blocked(peer_a))
    th.fail(peer_a)
    now[0] += 0.01
    check("right after a failure the address is blocked for the backoff window", th.blocked(peer_a))
    after_one = Throttle.BASE
    now[0] += after_one
    check("the backoff for one failure lifts after its window", not th.blocked(peer_a))
    th.fail(peer_a)
    now[0] += after_one
    check("a second failure (within the window) doubles the backoff: still blocked after the 1st window", th.blocked(peer_a))
    check("a different address is never affected by another's failures", not th.blocked(peer_b))
    now[0] += Throttle.CAP
    check("blocking never exceeds the cap: it eventually lifts even after repeated failures", not th.blocked(peer_a))
    for _ in range(10):
        th.fail(peer_a)
    now[0] += Throttle.CAP + 1
    check("even after 10 failures, the cap still lifts the block (never permanent)", not th.blocked(peer_a))
    now[0] += Throttle.FORGET + 1
    th.fail(peer_a)
    check("a long calm spell forgets the history: the next failure starts over at count 1",
          th.fails[peer_a[0]][0] == 1)
    th.clear(peer_a)
    check("clear() removes the record entirely", peer_a[0] not in th.fails)
    now[0] = 1_800_000_000.0

    # a real attacker trying forged FINISHED messages against one real pending bind, repeatedly
    book, host, ticket = world()
    peer = ("203.0.113.61", 2)
    cc = client(ticket, rsa_a)
    o, _ = host.handle(peer, cc.start()[0])
    h2 = cc.receive(o[0])
    acc = []
    for d_ in h2:
        oo, _ = host.handle(peer, d_)
        acc += oo
    fin = []
    for d_ in acc:
        fin += cc.receive(d_)
    check("the client reached FINISHED, ready to send it", cc.state == "finished" and fin)
    tries, blocked_at = 0, None
    for i in range(10):
        bad_fin = bytearray(fin[0])
        bad_fin[CHUNK_HEAD + 3 + i % 50] ^= 1
        before = host.stats["throttled"]
        host.handle(peer, bytes(bad_fin))
        tries += 1
        if host.stats["throttled"] > before and blocked_at is None:
            blocked_at = i
        now[0] += 0.001
    check("repeated forged FINISHED from one address gets throttled well before 10 tries",
          blocked_at is not None and blocked_at < 5)
    check("the throttle never blocks a different, honest address",
          not host.throttle.blocked(("203.0.113.62", 2)))
    now[0] = 1_800_000_000.0

    # --- resumption (section 7): coming back without a new invite
    peer, peer2 = ("203.0.113.9", 40000), ("198.51.100.20", 51000)
    book, host, ticket = world()
    c1, hs1 = run_pair(client(ticket), host, peer)
    inv_id = next(iter(book.rows))
    check("after the bind the invite is at generation 1 and both ends hold the same resumption ticket",
          book.rows[inv_id]["generation"] == 1 and len(c1.session.resumption_ticket) == RESUME_TICKET
          and len(c1.session.resumption_secret) == 32
          and c1.session.resumption_ticket == hs1.resumption_ticket
          and c1.session.resumption_secret == hs1.resumption_secret)
    check("RESUME is 2768 B and RESUMED 2774 B: three chunks each, the answer no larger than the request plus a datagram",
          TOTAL[RESUME] == 2768 and TOTAL[RESUMED] == 2774 and n_chunks(RESUME) == 3 and n_chunks(RESUMED) == 3)
    r1 = ClientResume(c1.session.resumption_ticket, c1.session.resumption_secret, clock=clock)
    r1, hr1 = run_pair(r1, host, peer2)                     # back from another address and port
    check("a resumption completes: a session at both ends, no RSA key made, no invite spent",
          r1.session is not None and hr1 is not None and hr1.resumed and r1.resumed
          and host.stats["resumed"] == 1 and host.stats["bound"] == 2 and not hasattr(r1, "rsa_key"))
    check("frames flow both ways over the resumed session",
          hr1.rx.open(r1.session.tx.seal(b"hi")) == b"hi" and r1.session.rx.open(hr1.tx.seal(b"yo")) == b"yo")
    check("the resumed session has its own keys and labels, nothing shared with the first",
          r1.session.rx.label != c1.session.rx.label and r1.session.rx.aead != c1.session.rx.aead
          and r1.session.tx.aead != c1.session.tx.aead)
    check("the generation moved to 2 and RESUMED carried the next ticket, the invite's sites with it",
          book.rows[inv_id]["generation"] == 2 and r1.session.resumption_ticket != c1.session.resumption_ticket
          and hr1.sites == "xag" and book.sealer.open(r1.session.resumption_ticket, 2)["generation"] == 2
          and book.sealer.open(r1.session.resumption_ticket, 2)["sites"] == "xag")
    check("the result line says the ticket was resumed, with !MATCH!",
          "ticket resumed - !MATCH!" in r1.result_line() and "ticket found - !MATCH!" in c1.result_line())
    r_old = ClientResume(c1.session.resumption_ticket, c1.session.resumption_secret, clock=clock)
    r_old, hr_old = run_pair(r_old, host, peer2)
    check("the ticket just used (generation 1) is dead: a copy of it gets nothing and counts as ticket_bad",
          r_old.session is None and hr_old is None and host.stats["ticket_bad"] >= 1
          and book.rows[inv_id]["generation"] == 2)
    now[0] += Throttle.CAP + 1
    r_forge = ClientResume(r1.session.resumption_ticket, b"X" * 32, clock=clock)
    r_forge, hr_f = run_pair(r_forge, host, ("203.0.113.70", 5))
    check("a copied CURRENT ticket without its secret (a bad binder) is refused and spends nothing",
          r_forge.session is None and hr_f is None and book.rows[inv_id]["generation"] == 2)
    r2 = ClientResume(r1.session.resumption_ticket, r1.session.resumption_secret, clock=clock)
    r2, hr2 = run_pair(r2, host, peer2)
    check("the real user's next resumption still works after that forgery (generation 3)",
          r2.session is not None and hr2 is not None and book.rows[inv_id]["generation"] == 3)
    tsk_imp = P.Tsk.generate("Impostor2", cipher_suite=P.CipherSuite.RSA2k, profile=P.Profile.RFC9580)
    imp = HostBind(tsk_imp, InviteBook(clock=clock), assign, clock=clock)
    r3 = ClientResume(r2.session.resumption_ticket, r2.session.resumption_secret, clock=clock)
    r3, hr3 = run_pair(r3, imp, peer2)
    check("a host with another ticket key cannot open the ticket: no session anywhere, nothing spent",
          r3.session is None and hr3 is None and book.rows[inv_id]["generation"] == 3)
    stolen_key_host = HostBind(tsk_imp, book, assign, clock=clock)    # same book and ticket key, other PGP key
    r3b = ClientResume(r2.session.resumption_ticket, r2.session.resumption_secret, clock=clock)
    r3b, hr3b = run_pair(r3b, stolen_key_host, peer2)
    check("a resumption trusts the ticket key, not the PGP key: a host holding the same ticket key answers",
          r3b.session is not None and hr3b is not None)
    book.revoke(inv_id)
    r4 = ClientResume(r3b.session.resumption_ticket, r3b.session.resumption_secret, clock=clock)
    r4, hr4 = run_pair(r4, host, peer2)
    check("a revoked invite cannot resume", r4.session is None and hr4 is None)
    now[0] = 1_800_000_000.0
    book, host, ticket = world(days=1)
    c5, _ = run_pair(client(ticket), host, peer)
    now[0] += 2 * 86400
    r5 = ClientResume(c5.session.resumption_ticket, c5.session.resumption_secret, clock=clock)
    r5, hr5 = run_pair(r5, host, peer2)
    check("a resumption ticket never outlives its invite: refused after the expiry", r5.session is None and hr5 is None)
    now[0] = 1_800_000_000.0
    book, host, ticket = world()
    c6, _ = run_pair(client(ticket), host, peer)
    inv6 = next(iter(book.rows))
    r6 = ClientResume(c6.session.resumption_ticket, c6.session.resumption_secret, clock=clock)
    o, _ = host.handle(peer2, r6.start()[0])
    rs = r6.receive(o[0])
    first, hs6 = [], None
    for d_ in rs:
        oo, s = host.handle(peer2, d_)
        first += oo
        hs6 = s or hs6
    again = []
    for d_ in r6.resend():
        oo, s = host.handle(peer2, d_)
        again += oo
        hs6_again = s
    check("RESUMED lost: the user resends RESUME and gets the very same RESUMED, the generation moving once",
          hs6 is not None and first and set(again) <= set(first) and book.rows[inv6]["generation"] == 2)
    for d_ in again:
        r6.receive(d_)
    check("the resumption completes from the resent answer", r6.session is not None and r6.session.address == hs6.address
          and r6.session.rx.open(hs6.tx.seal(b"ok")) == b"ok")
    check("a stray RESUME from a stranger is dropped",
          host.handle(("198.51.100.7", 1), to_chunks(RESUME, 5, os.urandom(TOTAL[RESUME]))[0]) == ([], None))
    check("a resumption secret or ticket of the wrong size is refused before any packet",
          raises(lambda: ClientResume(b"x" * 10, b"s" * 32), ValueError)
          and raises(lambda: ClientResume(c6.session.resumption_ticket, b"s" * 31), ValueError))

    if full:
        sig = sign_transcript(tsk, os.urandom(32))
        check("an RSA-4096 OpenPGP signature (%d B) fits the fixed field" % len(sig), len(sig) <= SIG_FIELD - 2)

    ok = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if ok == len(results) else MARK_BAD, ok, len(results)))
    return 0 if ok == len(results) else 1


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        sys.exit(selftest(full="--full" in sys.argv))
    print(__doc__)
