#!/usr/bin/env python3
"""ipv7_relay.py: the request and response layer for name links (spec section 9, open item O5),
shared by both ends and content-free -- the message formats, the chunk size, and the client
side's `SiteFetch` state machine (numbered chunks, a window, retries over the unreliable
carrier). The host side that answers these (the site table, the upstream fetch) is host-only
and lives in `ipv7_sites.py`; the local gateway that drives this from a browser lives in
`ipv7_gateway.py`. Neither is imported here.

One page fetch, on the wire, all of it inside already-sealed session frames:

    user -> host   SITE_REQ    req 4 | method 1 | name_len 1 | path_len 2 | name | path | header lines
    host -> user   SITE_META   req 4 | status 2 | total 4 | chunks 4 | header lines
    user -> host   SITE_FETCH  req 4 | first 4 | count 2            (repeated, windowed)
    host -> user   SITE_CHUNK  req 4 | seq 4 | data                 (one per chunk asked for)
    user -> host   SITE_DONE   req 4                                (the host may forget it)
    host -> user   SITE_ERR    req 4 | code 2 | text                (a request it cannot serve)
    host -> user   SITE_WAIT   req 4                                (asking the site now: keep waiting)

The pull design: the host keeps the finished response for a short while and sends only the
chunks it is asked for, so retries are the client's business (it is the one that wants the
page) and the host never has to track what was lost. A chunk that never arrives is simply asked
for again; after enough silence the fetch fails with 504 and the browser shows that.
"""
import struct
import threading
import time

APP_SITE_REQ, APP_SITE_META, APP_SITE_FETCH, APP_SITE_CHUNK, APP_SITE_DONE, APP_SITE_ERR = 5, 0x85, 6, 0x86, 7, 0x87
APP_SITE_WAIT = 0x88          # host -> user: "asking the site now" (req 4): the client waits as long as the host does
SITE_OPS = (APP_SITE_REQ, APP_SITE_META, APP_SITE_FETCH, APP_SITE_CHUNK, APP_SITE_DONE, APP_SITE_ERR, APP_SITE_WAIT)

CHUNK = 1100                 # data bytes per SITE_CHUNK: 34 B frame + 1 op + 8 head + 1100 = 1143 B datagram
WINDOW = 32                  # chunks asked for before waiting for any of them (~35 KB in flight)
BATCH_MAX = 64               # the most chunks one SITE_FETCH may ask for (the host caps it too)
NAME_MAX, PATH_MAX = 255, 900
METHODS = {"GET": 0, "HEAD": 1}
METHOD_NAMES = {0: "GET", 1: "HEAD"}
META_HEAD = struct.Struct(">IHII")
REQ_RETRIES, REQ_TIMEOUT = 4, 2.5          # SITE_REQ resent this often before "no answer"
WAIT_TIMEOUT = 35.0                        # after SITE_WAIT: how long the host may take to answer the site
CHUNK_RETRIES = 8                          # one chunk asked for this many times before giving up


REQ_HEADERS = ("cookie", "if-none-match", "if-modified-since", "accept", "accept-language")   # what may go upstream
RESP_HEADERS = ("content-type", "last-modified", "etag", "cache-control", "expires", "location",
                "content-disposition", "content-language", "vary", "set-cookie")                # what may come back


def pack_req(req_id, method, name, path, headers=()):
    nb, pb = name.encode("utf-8"), path.encode("utf-8")
    if not nb or len(nb) > NAME_MAX:
        raise ValueError("site name too long or empty")
    if len(pb) > PATH_MAX:
        raise ValueError("path too long")
    lines = "".join("%s: %s\r\n" % (k, v) for k, v in headers if k.lower() in REQ_HEADERS)
    return struct.pack(">IBBH", req_id, METHODS[method], len(nb), len(pb)) + nb + pb + lines.encode("latin-1", "replace")[:600]


def unpack_req(payload):
    """-> (req_id, method text, name, path, headers), or None for a malformed one"""
    if len(payload) < 8:
        return None
    req_id, m, nl, pl = struct.unpack(">IBBH", payload[:8])
    if m not in METHOD_NAMES or nl == 0 or pl > PATH_MAX or len(payload) < 8 + nl + pl:
        return None
    try:
        name = payload[8:8 + nl].decode("utf-8")
        path = payload[8 + nl:8 + nl + pl].decode("utf-8")
    except UnicodeDecodeError:
        return None
    headers = []
    for line in payload[8 + nl + pl:].decode("latin-1").split("\r\n"):
        k, sep, v = line.partition(":")
        if sep and k.strip().lower() in REQ_HEADERS:
            headers.append((k.strip(), v.strip()))
    return req_id, METHOD_NAMES[m], name, path, headers


def pack_meta(req_id, status, total, nchunks, headers):
    """headers: a list of (name, value) text pairs"""
    lines = "".join("%s: %s\r\n" % (k, v) for k, v in headers)
    return META_HEAD.pack(req_id, status, total, nchunks) + lines.encode("latin-1", "replace")


def unpack_meta(payload):
    if len(payload) < META_HEAD.size:
        return None
    req_id, status, total, nchunks = META_HEAD.unpack(payload[:META_HEAD.size])
    headers = []
    for line in payload[META_HEAD.size:].decode("latin-1").split("\r\n"):
        k, sep, v = line.partition(":")
        if sep and k.strip():
            headers.append((k.strip(), v.strip()))
    return req_id, status, total, nchunks, headers


def pack_fetch(req_id, first, count):
    return struct.pack(">IIH", req_id, first, count)


def unpack_fetch(payload):
    return struct.unpack(">IIH", payload[:10]) if len(payload) >= 10 else None


def pack_chunk(req_id, seq, data):
    return struct.pack(">II", req_id, seq) + data


def unpack_chunk(payload):
    return (struct.unpack(">II", payload[:8]) + (payload[8:],)) if len(payload) >= 8 else None


def pack_done(req_id):
    return struct.pack(">I", req_id)


def pack_err(req_id, code, text):
    return struct.pack(">IH", req_id, code) + text.encode("utf-8", "replace")[:200]


def unpack_err(payload):
    if len(payload) < 6:
        return None
    req_id, code = struct.unpack(">IH", payload[:6])
    return req_id, code, payload[6:].decode("utf-8", "replace")


def n_chunks(total):
    return -(-total // CHUNK) if total else 0


class SiteFetch:
    """One name-link fetch from the client's side: send SITE_REQ, wait for SITE_META, pull the
    chunks in a window, re-ask for the ones that never came, hand back (status, headers, body).

    `send(op, payload)` is the only thing it needs from the session. Everything that arrives
    for its req_id is fed to `on_app(op, payload)` by whoever owns the session's receive thread
    (`RelayClient` below); `tick()` is called a few times a second for the timeouts. `wait()`
    blocks the caller (a gateway handler thread) until the fetch is over."""

    def __init__(self, send, req_id, method, name, path, clock=time.time, headers=()):
        self.send, self.req_id, self.method, self.name, self.path, self.clock = send, req_id, method, name, path, clock
        self.req_headers = tuple(headers)
        self.status = self.headers = self.body = None
        self.error = None                     # (code, text) when it failed
        self.total = self.nchunks = 0
        self.got = {}
        self.inflight = {}                    # seq -> time asked
        self.asked = {}                       # seq -> times asked
        self.req_sent = 0
        self.req_at = 0.0
        self.wait_until = 0.0                 # set by SITE_WAIT: META may take this long
        self.rto = 1.0
        self.done = threading.Event()
        self.lock = threading.RLock()           # re-entrant: a reply that lands while we are sending is fine

    def start(self):
        self._send_req()

    def _send_req(self):
        self.req_sent += 1
        self.req_at = self.clock()
        self.send(APP_SITE_REQ, pack_req(self.req_id, self.method, self.name, self.path, self.req_headers))

    def _fail(self, code, text):
        self.error = (code, text)
        self.done.set()

    def _finish(self):
        body = b"".join(self.got[i] for i in range(self.nchunks)) if self.nchunks else b""
        if len(body) != self.total:
            self._fail(502, "the host sent %d bytes for a %d byte page" % (len(body), self.total))
            return
        self.body = body
        self.done.set()
        try:
            self.send(APP_SITE_DONE, pack_done(self.req_id))
        except Exception:
            pass

    def _ask(self, now):
        """Ask for missing chunks up to the window: one SITE_FETCH per contiguous run."""
        room = WINDOW - len(self.inflight)
        if room <= 0:
            return
        want = [i for i in range(self.nchunks) if i not in self.got and i not in self.inflight]
        want = want[:room]
        i = 0
        while i < len(want):
            first = want[i]
            count = 1
            while i + count < len(want) and want[i + count] == first + count and count < BATCH_MAX:
                count += 1
            for s in range(first, first + count):
                self.inflight[s] = now
                self.asked[s] = self.asked.get(s, 0) + 1
            self.send(APP_SITE_FETCH, pack_fetch(self.req_id, first, count))
            i += count

    def on_app(self, op, payload):
        with self.lock:
            if self.done.is_set():
                return
            if op == APP_SITE_META:
                m = unpack_meta(payload)
                if m is None or self.status is not None:
                    return
                _, status, total, nchunks, headers = m
                if nchunks != n_chunks(total) or total > (1 << 31):
                    self._fail(502, "the host announced an impossible page size")
                    return
                self.status, self.headers, self.total, self.nchunks = status, headers, total, nchunks
                rtt = max(0.05, self.clock() - self.req_at)
                self.rto = min(4.0, max(0.5, rtt * 3))
                if nchunks == 0:
                    self._finish()
                else:
                    self._ask(self.clock())
            elif op == APP_SITE_CHUNK:
                c = unpack_chunk(payload)
                if c is None or self.status is None:
                    return
                _, seq, data = c
                if seq >= self.nchunks or seq in self.got:
                    return
                want = CHUNK if seq < self.nchunks - 1 else self.total - CHUNK * (self.nchunks - 1)
                if len(data) != want:
                    return                                    # a damaged or foreign chunk: ask again later
                self.got[seq] = data
                at = self.inflight.pop(seq, None)
                if at is not None:
                    self.rto = min(4.0, max(0.3, 0.8 * self.rto + 0.2 * 3 * (self.clock() - at)))
                if len(self.got) == self.nchunks:
                    self._finish()
                elif len(self.inflight) <= WINDOW // 2:
                    self._ask(self.clock())
            elif op == APP_SITE_ERR:
                e = unpack_err(payload)
                if e is not None:
                    self._fail(e[1], e[2])
            elif op == APP_SITE_WAIT:
                if self.status is None:
                    self.wait_until = self.clock() + WAIT_TIMEOUT

    def tick(self):
        with self.lock:
            if self.done.is_set():
                return
            now = self.clock()
            if self.status is None:
                if self.wait_until:                           # the host said it is asking the site
                    if now >= self.wait_until:
                        self._fail(504, "the host took too long asking the site for %s" % self.name)
                    return
                if now - self.req_at >= REQ_TIMEOUT:
                    if self.req_sent >= REQ_RETRIES:
                        self._fail(504, "no answer from the host for %s" % self.name)
                    else:
                        self._send_req()
                return
            late = [s for s, at in self.inflight.items() if now - at >= self.rto]
            if not late:
                return
            for s in late:
                del self.inflight[s]
                if self.asked.get(s, 0) >= CHUNK_RETRIES:
                    self._fail(504, "chunk %d of %s never arrived" % (s, self.name))
                    return
            self.rto = min(4.0, self.rto * 1.5)
            self._ask(now)

    def wait(self, timeout=60.0):
        """-> (status, headers, body) or raises FetchError(code, text)."""
        end = self.clock() + timeout
        while not self.done.is_set():
            left = end - self.clock()
            if left <= 0:
                with self.lock:
                    if not self.done.is_set():
                        self._fail(504, "%s took too long" % self.name)
                break
            self.done.wait(min(0.25, left))
            self.tick()
        if self.error is not None:
            raise FetchError(*self.error)
        return self.status, self.headers, self.body


class FetchError(Exception):
    def __init__(self, code, text):
        Exception.__init__(self, text)
        self.code, self.text = code, text


class RelayClient:
    """Owns the live fetches of one session on the client's side: hands each arriving site
    message to the fetch it belongs to (by req_id) and numbers new ones. Thread-safe; the
    session's receive thread calls `on_app`, gateway threads call `fetch`."""

    def __init__(self, send, clock=time.time):
        self.send, self.clock = send, clock
        self.live = {}
        self.lock = threading.Lock()
        self.next_id = int(clock()) & 0xFFFF
        self.served = 0
        self.bytes = 0
        self.failed = 0

    def on_app(self, app):
        op = app[0]
        if op not in (APP_SITE_META, APP_SITE_CHUNK, APP_SITE_ERR, APP_SITE_WAIT) or len(app) < 5:
            return False
        req_id = struct.unpack(">I", app[1:5])[0]
        with self.lock:
            f = self.live.get(req_id)
        if f is not None:
            f.on_app(op, app[1:])
        return True

    def fetch(self, method, name, path, timeout=60.0, headers=()):
        with self.lock:
            self.next_id = (self.next_id + 1) & 0xFFFFFFFF
            req_id = self.next_id
            f = SiteFetch(self.send, req_id, method, name, path, self.clock, headers)
            self.live[req_id] = f
        try:
            f.start()
            status, headers, body = f.wait(timeout)
            self.served += 1
            self.bytes += len(body)
            return status, headers, body
        except FetchError:
            self.failed += 1
            raise
        finally:
            with self.lock:
                self.live.pop(req_id, None)


# ---------------------------------------------------------------- selftest
def selftest():
    import os
    import random
    results = []
    MARK_OK, MARK_BAD = "*_", "-_"

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    r = unpack_req(pack_req(7, "GET", "XAG.loky", "/a/b?c=1", [("Cookie", "s=1"), ("X-Secret", "no"), ("If-None-Match", "\"e\"")]))
    check("SITE_REQ round-trips id, method, a case-sensitive name, the path and the allowed headers only",
          r == (7, "GET", "XAG.loky", "/a/b?c=1", [("Cookie", "s=1"), ("If-None-Match", "\"e\"")]))
    check("SITE_REQ refuses an empty name and a path over the limit",
          _raises(lambda: pack_req(1, "GET", "", "/")) and _raises(lambda: pack_req(1, "GET", "x", "/" * 901)))
    check("a malformed SITE_REQ unpacks to None", unpack_req(b"\x00\x00\x00\x01\x09\x03\x00\x00ab") is None and unpack_req(b"") is None)
    m = unpack_meta(pack_meta(9, 200, 2500, 3, [("Content-Type", "text/html"), ("ETag", "\"x\"")]))
    check("SITE_META round-trips status, total, chunk count and header lines",
          m == (9, 200, 2500, 3, [("Content-Type", "text/html"), ("ETag", "\"x\"")]))
    check("SITE_FETCH / SITE_CHUNK / SITE_ERR round-trip",
          unpack_fetch(pack_fetch(1, 5, 3)) == (1, 5, 3) and unpack_chunk(pack_chunk(1, 2, b"zz")) == (1, 2, b"zz")
          and unpack_err(pack_err(4, 404, "no such site")) == (4, 404, "no such site"))
    check("n_chunks matches CHUNK", n_chunks(0) == 0 and n_chunks(1) == 1 and n_chunks(CHUNK) == 1 and n_chunks(CHUNK + 1) == 2)

    # -- a fake host answering a SiteFetch, with loss, duplicates and reordering
    class FakeHost:
        def __init__(self, body, status=200, drop=0.0, seed=1, dup=False, silent=False, err=None, slow=0.0):
            self.body, self.status, self.drop, self.dup, self.silent, self.err = body, status, drop, dup, silent, err
            self.slow, self.meta_due = slow, None
            self.rnd = random.Random(seed)
            self.pending = []
            self.reqs = self.fetches = self.chunks_sent = 0
            self.done = False
            self.client = None

        def deliver(self, op, payload):
            if self.rnd.random() < self.drop:
                return
            self.pending.append(bytes([op]) + payload)

        def flush(self):                          # the "network": replies land later, not inside send()
            if self.meta_due and self.clock() >= self.meta_due[0]:
                req_id = self.meta_due[1]
                self.meta_due = None
                self.deliver(APP_SITE_META, pack_meta(req_id, self.status, len(self.body), n_chunks(len(self.body)),
                                                      [("Content-Type", "text/plain")]))
            q, self.pending = self.pending, []
            for a in q:
                self.client.on_app(a)

        def send(self, op, payload):              # what the client "sends" lands here
            if op == APP_SITE_REQ:
                self.reqs += 1
                if self.silent:
                    return
                req_id = unpack_req(payload)[0]
                if self.err:
                    self.deliver(APP_SITE_ERR, pack_err(req_id, *self.err))
                    return
                if self.slow:                              # a host asking a slow site: WAIT now, META later
                    self.deliver(APP_SITE_WAIT, pack_done(req_id))
                    self.meta_due = (self.clock() + self.slow, req_id)
                    return
                self.deliver(APP_SITE_META, pack_meta(req_id, self.status, len(self.body), n_chunks(len(self.body)),
                                                      [("Content-Type", "text/plain")]))
            elif op == APP_SITE_FETCH:
                self.fetches += 1
                req_id, first, count = unpack_fetch(payload)
                seqs = list(range(first, first + min(count, BATCH_MAX)))
                self.rnd.shuffle(seqs)
                for s in seqs:
                    if s * CHUNK >= len(self.body):
                        continue
                    self.chunks_sent += 1
                    self.deliver(APP_SITE_CHUNK, pack_chunk(req_id, s, self.body[s * CHUNK:(s + 1) * CHUNK]))
                    if self.dup:
                        self.deliver(APP_SITE_CHUNK, pack_chunk(req_id, s, self.body[s * CHUNK:(s + 1) * CHUNK]))
            elif op == APP_SITE_DONE:
                self.done = True

    def run(body, **kw):
        t = [1000.0]
        clock = lambda: t[0]
        fh = FakeHost(body, **kw)
        fh.clock = clock
        rc = RelayClient(fh.send, clock=clock)
        fh.client = rc
        # drive wait() with a stepping clock: each Event.wait is a no-op on a fake clock, so
        # step time by hand from a patched done.wait
        orig_fetch = SiteFetch.wait

        def stepping_wait(self, timeout=60.0):
            end = clock() + timeout
            while not self.done.is_set() and clock() < end:
                fh.flush()
                t[0] += 0.3
                self.tick()
                fh.flush()
            if not self.done.is_set():
                self._fail(504, "timeout")
            if self.error is not None:
                raise FetchError(*self.error)
            return self.status, self.headers, self.body
        SiteFetch.wait = stepping_wait
        try:
            try:
                res = rc.fetch("GET", "XAG.loky", "/index.html", timeout=120.0)
                return res, fh, None
            except FetchError as e:
                return None, fh, e
        finally:
            SiteFetch.wait = orig_fetch

    body = os.urandom(CHUNK * 50 + 123)
    res, fh, err = run(body)
    check("a 50-chunk page arrives whole over a clean link, in order, and SITE_DONE is sent",
          err is None and res[0] == 200 and res[2] == body and fh.done and res[1] == [("Content-Type", "text/plain")])
    check("the window is honoured: the first fetch asks for at most WINDOW chunks", fh.fetches >= 2)
    res, fh, err = run(body, drop=0.3, seed=7)
    check("with 30% of datagrams lost (both ways) the page still arrives whole", err is None and res[2] == body)
    check("... by asking again for what was lost, never more than CHUNK_RETRIES times per chunk",
          fh.chunks_sent > 50 and fh.fetches > 2)
    res, fh, err = run(body, dup=True)
    check("duplicated chunks are ignored", err is None and res[2] == body)
    res, fh, err = run(b"")
    check("an empty body (a HEAD, a 304) completes with no chunks", err is None and res[2] == b"" and fh.fetches == 0)
    res, fh, err = run(b"hi", silent=True)
    check("a host that never answers SITE_REQ gives 504 after REQ_RETRIES tries",
          err is not None and err.code == 504 and fh.reqs == REQ_RETRIES)
    res, fh, err = run(b"hi", err=(404, "no such site"))
    check("SITE_ERR from the host becomes a FetchError with its code and text",
          err is not None and err.code == 404 and "no such site" in err.text)
    res, fh, err = run(body, drop=0.97, seed=3)
    check("a link that loses nearly everything fails with 504 instead of hanging", err is not None and err.code == 504)
    res, fh, err = run(b"slow page", slow=20.0)
    check("a host that says WAIT (a slow site behind it) is given up to WAIT_TIMEOUT: a 20 s answer still arrives, with one REQ",
          err is None and res[2] == b"slow page" and fh.reqs == 1)
    res, fh, err = run(b"never", slow=60.0)
    check("... and a site that never answers is 504 after WAIT_TIMEOUT, not forever", err is not None and err.code == 504)

    # a foreign chunk (wrong size) and a chunk for an unknown req_id are ignored
    rc = RelayClient(lambda op, p: None)
    check("a site message for an unknown req_id is swallowed, a non-site opcode is not claimed",
          rc.on_app(bytes([APP_SITE_CHUNK]) + pack_chunk(5, 0, b"x")) is True and rc.on_app(b"\x81zz") is False)

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


def _raises(fn):
    try:
        fn()
        return False
    except (ValueError, KeyError):
        return True


def main():
    return selftest() if "--selftest" in __import__("sys").argv else (print(__doc__) or 0)


if __name__ == "__main__":
    __import__("sys").exit(main())
