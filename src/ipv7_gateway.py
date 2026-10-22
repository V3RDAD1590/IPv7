#!/usr/bin/env python3
"""ipv7_gateway.py: the local gateway for name links (spec section 9), client side.

    http://localhost:8888/IPv7:NAME/path        a page of the site NAME, fetched over the session
    http://localhost:8888/                      the index: this session and the sites it opens
    http://localhost:8888/IPv7/status.json      the same, for a program (Aloha's IPv7 window)

It listens on 127.0.0.1 only. Every request is checked before anything is sent over the session
(open item O16): the `Host` header must be this gateway's own (so a DNS-rebinding page cannot
reach it by another name), a request a page on another origin made is refused (`Sec-Fetch-Site`
other than same-origin, and every OPTIONS preflight), and only GET and HEAD exist. Nothing here
ever answers with CORS headers, so a foreign page gets nothing it can read.

Root-relative links in a page (`/css/site.css`) would escape the `/IPv7:NAME/` prefix (open item
O7). Two things catch them: HTML and CSS bodies are rewritten on the way through (href, src,
action, srcset, url(...) and the like), and a request that still arrives outside the prefix is
sent back under the prefix of the page it came from (its Referer) -- which also catches links a
script builds at run time. Cookies a site sets are scoped to its own prefix, so two sites behind
the one gateway never see each other's.

Address links (`ipv7://192.0.0.172.16.0.2.2/`) are not carried by this gateway: they are a
different thing (a user's own published folder or port, relayed by the host) and are not built.
Typing one gives a plain page saying so.

The gateway is one thread per request on top of the session's `RelayClient` (`ipv7_relay.py`);
it starts after a login and stops with the session. `IPV7_GATEWAY_PORT` in the environment
moves it off 8888 for a machine where that port is taken.
"""
import http.server
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse

from ipv7_relay import FetchError, RelayClient

DEFAULT_PORT = 8888
PREFIX = "/IPv7:"
STATUS_PATH = "/IPv7/status.json"
MAX_PARALLEL = 8
ADDRESS_LINK = re.compile(r"^(\d{1,3}\.){3,}\d{1,3}$")
_ATTR = re.compile(rb"""((?:href|src|action|formaction|poster|data|background)\s*=\s*["']?)/(?!/)""", re.I)
_SRCSET = re.compile(rb"""(srcset\s*=\s*["'])([^"']*)(["'])""", re.I)
_URL = re.compile(rb"""(url\(\s*["']?)/(?!/)""", re.I)
_IMPORT = re.compile(rb"""(@import\s+["'])/(?!/)""", re.I)
_PATH_ATTR = re.compile(r";\s*path=[^;]*", re.I)
_DOMAIN_ATTR = re.compile(r";\s*domain=[^;]*", re.I)


def gateway_port():
    try:
        return int(os.environ.get("IPV7_GATEWAY_PORT", DEFAULT_PORT))
    except ValueError:
        return DEFAULT_PORT


def rewrite_html(body, name):
    """Root-relative links -> under /IPv7:NAME/. Bytes in, bytes out; no decoding, so the page's
    own charset is never touched."""
    pre = ("/IPv7:%s/" % name).encode("utf-8")
    body = _ATTR.sub(lambda m: m.group(1) + pre, body)

    def srcset(m):
        parts = []
        for cand in m.group(2).split(b","):
            c = cand.strip()
            if c.startswith(b"/") and not c.startswith(b"//"):
                c = pre + c[1:]
            parts.append(c)
        return m.group(1) + b", ".join(parts) + m.group(3)
    body = _SRCSET.sub(srcset, body)
    body = _URL.sub(lambda m: m.group(1) + pre, body)
    return body


def rewrite_css(body, name):
    pre = ("/IPv7:%s/" % name).encode("utf-8")
    body = _URL.sub(lambda m: m.group(1) + pre, body)
    return _IMPORT.sub(lambda m: m.group(1) + pre, body)


def rewrite_headers(headers, name):
    """Location under the prefix, Set-Cookie scoped to it, nothing else changed."""
    out = []
    pre = "/IPv7:%s/" % name
    for k, v in headers:
        lk = k.lower()
        if lk == "location" and v.startswith("/") and not v.startswith("//"):
            v = pre + v[1:]
        elif lk == "set-cookie":
            v = _DOMAIN_ATTR.sub("", v)
            v = _PATH_ATTR.sub("", v) + "; Path=" + pre
        out.append((k, v))
    return out


def split_link(path):
    """'/IPv7:NAME/rest?q' -> (NAME, '/rest?q'); None when it is not a name link. A link without
    the slash after the name is given as (NAME, None) so the caller can redirect to it."""
    if not path.startswith(PREFIX):
        return None
    rest = path[len(PREFIX):]
    i = rest.find("/")
    if i < 0:
        q = rest.find("?")
        name = rest if q < 0 else rest[:q]
        return urllib.parse.unquote(name), None
    name = urllib.parse.unquote(rest[:i])
    return name, rest[i:]


def referer_prefix(referer, hosts_ok):
    """The /IPv7:NAME of the page a request came from, when it came from this gateway."""
    try:
        u = urllib.parse.urlsplit(referer or "")
    except ValueError:
        return None
    if u.netloc.lower() not in hosts_ok:
        return None
    link = split_link(u.path)
    return link[0] if link else None


def _page(title, heading, text, port):
    return ("<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>%s</title>\n</head><body>\n"
            "<h1>%s</h1>\n<p>%s</p>\n<hr>\n<address>IPv7 gateway at localhost Port %d</address>\n</body></html>\n"
            % (title, heading, text, port)).encode("utf-8")


class Gateway:
    """`relay`: a RelayClient on the session. `info()`: -> a dict for the index and status.json
    (host, address, key, carrier, bound, sites). `sites`: the names the invite opens."""

    def __init__(self, relay, info, sites=(), port=None, bind="127.0.0.1", clock=time.time):
        self.relay, self.info, self.sites, self.clock = relay, info, tuple(sites), clock
        self.port = port or gateway_port()
        self.bind = bind
        self.hosts_ok = {"localhost:%d" % self.port, "127.0.0.1:%d" % self.port}
        self.server = None
        self.thread = None
        self.started = None
        self.error = None
        self.sem = threading.BoundedSemaphore(MAX_PARALLEL)
        self.stats = {"requests": 0, "served": 0, "failed": 0, "refused": 0, "redirected": 0, "dropped": 0, "errors": 0}
        self.last_error = None

    @property
    def url(self):
        return "http://localhost:%d/" % self.port

    def link(self, name):
        return "http://localhost:%d/IPv7:%s/" % (self.port, name)

    def start(self):
        """-> True when listening; False (with .error set) when the port is taken."""
        try:
            srv = _Server((self.bind, self.port), _Handler)
        except OSError as e:
            self.error = str(e)
            return False
        srv.daemon_threads = True
        srv.gateway = self
        self.server = srv
        if self.port == 0:                            # a free port was asked for (tests): learn it
            self.port = srv.server_address[1]
            self.hosts_ok = {"localhost:%d" % self.port, "127.0.0.1:%d" % self.port}
        self.started = self.clock()
        self.thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.25}, daemon=True)
        self.thread.start()
        return True

    def stop(self):
        srv, self.server = self.server, None
        if srv is not None:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass

    @property
    def running(self):
        return self.server is not None

    def status(self):
        d = {"version": 1, "gateway": "%s:%d" % (self.bind, self.port), "url": self.url,
             "uptime": int(self.clock() - self.started) if self.started else 0,
             "sites": [{"name": n, "url": self.link(n)} for n in self.sites]}
        d.update(self.stats)
        d["last_error"] = self.last_error
        try:
            d["session"] = dict(self.info() or {})
        except Exception:
            d["session"] = {}
        return d


class _Server(http.server.ThreadingHTTPServer):
    """socketserver prints a traceback to the console for any error in a request thread --
    including the one every browser causes by opening a spare connection beside the real one and
    dropping it unused (ConnectionResetError, WinError 10054). None of that is the operator's
    business: a connection error is counted and forgotten; anything else is kept, one line, for
    status.json (`last_error`) instead of the screen."""
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        exc = sys.exc_info()[1]
        gw = getattr(self, "gateway", None)
        if gw is None:
            return
        if isinstance(exc, (ConnectionError, socket.timeout, TimeoutError, OSError)):
            gw.stats["dropped"] += 1
            return
        gw.stats["errors"] += 1
        gw.last_error = "%s: %s" % (type(exc).__name__, exc)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "IPv7-gateway/1"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30                                  # an idle spare connection does not hold a thread forever

    def log_message(self, fmt, *args):            # nothing about requests is printed to the console
        pass

    # -- the methods that exist
    def do_GET(self):
        self._serve("GET")

    def do_HEAD(self):
        self._serve("HEAD")

    # -- and the ones that do not: no CORS answer, ever (O16)
    def do_OPTIONS(self):
        self.server.gateway.stats["refused"] += 1
        self._send(403, [("Content-Type", "text/html")], _page("403 Forbidden", "Forbidden",
                   "Cross-site requests are not served by this gateway.", self.server.gateway.port), "GET")

    def do_POST(self):
        self._method_gone()

    do_PUT = do_DELETE = do_PATCH = do_CONNECT = do_TRACE = do_POST

    def _method_gone(self):
        self.server.gateway.stats["refused"] += 1
        self._send(405, [("Content-Type", "text/html"), ("Allow", "GET, HEAD")],
                   _page("405 Method Not Allowed", "Method Not Allowed",
                         "Only GET and HEAD exist on this gateway (spec section 9).", self.server.gateway.port), "GET")

    def _send(self, status, headers, body, method, raw=False):
        self.send_response(status)
        has_len = False
        for k, v in headers:
            if k.lower() in ("content-length", "connection", "transfer-encoding"):
                continue
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        if not raw:
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        if method != "HEAD" and body:
            self.wfile.write(body)
        self.close_connection = True

    def _serve(self, method):
        gw = self.server.gateway
        gw.stats["requests"] += 1
        port = gw.port
        # O16: the gateway's own name only, and never for another origin's page
        host = (self.headers.get("Host") or "").strip().lower()
        if host not in gw.hosts_ok:
            gw.stats["refused"] += 1
            self._send(421, [("Content-Type", "text/html")], _page("421 Misdirected Request", "Misdirected Request",
                       "This gateway answers to localhost:%d only." % port, port), method)
            return
        site = (self.headers.get("Sec-Fetch-Site") or "").strip().lower()
        if site and site not in ("same-origin", "none"):
            gw.stats["refused"] += 1
            self._send(403, [("Content-Type", "text/html")], _page("403 Forbidden", "Forbidden",
                       "A page on another origin asked for this; the gateway does not answer it.", port), method)
            return
        path = self.path or "/"
        if path in ("/", ""):
            self._send(200, [("Content-Type", "text/html; charset=utf-8")], self._index(), method)
            return
        if path == STATUS_PATH:
            body = json.dumps(gw.status(), indent=1).encode("utf-8")
            self._send(200, [("Content-Type", "application/json")], body, method)
            return
        link = split_link(path)
        if link is None:
            # outside the prefix: back under the prefix of the page it came from, else 404
            name = referer_prefix(self.headers.get("Referer"), gw.hosts_ok)
            if name:
                gw.stats["redirected"] += 1
                self._send(302, [("Location", PREFIX + urllib.parse.quote(name, safe="") + path)], b"", method)
                return
            self._send(404, [("Content-Type", "text/html")], _page("404 Not Found", "Not Found",
                       "Name links look like /IPv7:NAME/ -- see <a href=\"/\">the index</a>.", port), method)
            return
        name, rest = link
        if rest is None:
            self._send(301, [("Location", PREFIX + urllib.parse.quote(name, safe="") + "/")], b"", method)
            return
        if not name or "/" in name or len(name.encode("utf-8")) > 255:
            self._send(404, [("Content-Type", "text/html")], _page("404 Not Found", "Not Found",
                       "That is not a site name.", port), method)
            return
        if ADDRESS_LINK.match(name):
            self._send(501, [("Content-Type", "text/html")], _page("501 Not Implemented", "Not Implemented",
                       "Address links (ipv7://%s/) are not carried by this gateway: it serves name links, "
                       "/IPv7:NAME/, which the host answers from its site table." % name, port), method)
            return
        fwd = [(k, v) for k, v in self.headers.items()
               if k.lower() in ("cookie", "if-none-match", "if-modified-since", "accept", "accept-language")]
        if not gw.sem.acquire(timeout=30):
            self._send(503, [("Content-Type", "text/html")], _page("503 Service Unavailable", "Busy",
                       "Too many pages in flight; try again.", port), method)
            return
        try:
            status, headers, body = gw.relay.fetch(method, name, rest, headers=fwd)
        except FetchError as e:
            gw.stats["failed"] += 1
            self._send(e.code, [("Content-Type", "text/html")], _page("%d %s" % (e.code, _REASON.get(e.code, "Error")),
                       _REASON.get(e.code, "Error"), "/IPv7:%s%s -- %s" % (name, rest, e.text), port), method)
            return
        except Exception as e:
            gw.stats["failed"] += 1
            self._send(502, [("Content-Type", "text/html")], _page("502 Bad Gateway", "Bad Gateway",
                       "%s: %s" % (type(e).__name__, e), port), method)
            return
        finally:
            gw.sem.release()
        gw.stats["served"] += 1
        ctype = ""
        for k, v in headers:
            if k.lower() == "content-type":
                ctype = v.lower()
        if method != "HEAD" and body:
            if "text/html" in ctype:
                body = rewrite_html(body, name)
            elif "text/css" in ctype:
                body = rewrite_css(body, name)
        self._send(status, rewrite_headers(headers, name), body, method, raw=True)

    def _index(self):
        gw = self.server.gateway
        try:
            info = dict(gw.info() or {})
        except Exception:
            info = {}
        rows = [("host", info.get("host", "?")), ("TP/IX address", info.get("address", "?")),
                ("key", info.get("key", "?")), ("carrier", info.get("carrier", "?")),
                ("session", "bound" if info.get("bound") else "not bound"),
                ("gateway", "localhost:%d" % gw.port),
                ("pages", "%d served, %d failed" % (gw.stats["served"], gw.stats["failed"]))]
        h = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n<html><head>\n<title>IPv7</title>\n</head><body>\n<h1>IPv7</h1>\n"
        h += "<table border=\"1\">\n"
        for k, v in rows:
            h += "<tr><td>%s</td><td>%s</td></tr>\n" % (_esc(k), _esc(str(v)))
        h += "</table>\n<h2>Sites</h2>\n"
        if gw.sites:
            h += "<ul>\n" + "".join("<li><a href=\"%s\">%s</a></li>\n" %
                                    (PREFIX + urllib.parse.quote(n, safe="") + "/", _esc(n)) for n in gw.sites) + "</ul>\n"
        else:
            h += "<p>This invite opens no sites.</p>\n"
        h += "<p>Name links: <code>http://localhost:%d/IPv7:NAME/</code> -- the host matches NAME exactly, case and all.</p>\n" % gw.port
        h += "<hr>\n<address>IPv7 gateway at localhost Port %d</address>\n</body></html>\n" % gw.port
        return h.encode("utf-8")


_REASON = {403: "Forbidden", 404: "Not Found", 410: "Gone", 413: "Payload Too Large", 500: "Internal Server Error",
           502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"}


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")


# ---------------------------------------------------------------- selftest
def selftest():
    import http.client
    results = []
    MARK_OK, MARK_BAD = "*_", "-_"

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    # -- rewriting
    html = (b"<a href=\"/a\">x</a><img src='/i.png' srcset=\"/s1.png 1x, /s2.png 2x, //cdn/x.png 3x\">"
            b"<form action=/go><div style=\"background:url(/bg.png)\"></div><a href=\"//other/x\">y</a>"
            b"<a href=\"rel/x\">z</a><link href=\"/c.css\" rel=stylesheet>")
    out = rewrite_html(html, "XAG.loky")
    check("root-relative href/src/action/url() and each srcset entry are prefixed, // and relative ones are not",
          b"href=\"/IPv7:XAG.loky/a\"" in out and b"src='/IPv7:XAG.loky/i.png'" in out
          and b"srcset=\"/IPv7:XAG.loky/s1.png 1x, /IPv7:XAG.loky/s2.png 2x, //cdn/x.png 3x\"" in out
          and b"action=/IPv7:XAG.loky/go" in out and b"url(/IPv7:XAG.loky/bg.png)" in out
          and b"href=\"//other/x\"" in out and b"href=\"rel/x\"" in out and b"href=\"/IPv7:XAG.loky/c.css\"" in out)
    css = b"@import \"/f.css\"; body{background:url( '/b.png' )} a{background:url(data:x)}"
    out = rewrite_css(css, "G")
    check("css @import and url() are prefixed, data: urls untouched",
          b"@import \"/IPv7:G/f.css\"" in out and b"url( '/IPv7:G/b.png' )" in out and b"url(data:x)" in out)
    hd = rewrite_headers([("Location", "/next"), ("Location", "http://x/y"), ("Set-Cookie", "s=1; Path=/; Domain=x.loky; HttpOnly"),
                          ("Set-Cookie", "t=2"), ("ETag", "\"e\"")], "XAG.loky")
    check("Location is prefixed when root-relative, Set-Cookie is scoped to the prefix and loses Domain",
          hd == [("Location", "/IPv7:XAG.loky/next"), ("Location", "http://x/y"), ("Set-Cookie", "s=1; HttpOnly; Path=/IPv7:XAG.loky/"),
                 ("Set-Cookie", "t=2; Path=/IPv7:XAG.loky/"), ("ETag", "\"e\"")])
    check("split_link parses a name link, keeps the name's case, and flags a missing slash",
          split_link("/IPv7:XAG.loky/a/b?c") == ("XAG.loky", "/a/b?c") and split_link("/IPv7:XAG.loky") == ("XAG.loky", None)
          and split_link("/other") is None and split_link("/IPv7:Caf%C3%A9/") == ("Café", "/"))
    ok_hosts = {"localhost:8888", "127.0.0.1:8888"}
    check("referer_prefix finds the page's site only for this gateway's own referer",
          referer_prefix("http://localhost:8888/IPv7:XAG.loky/p.html", ok_hosts) == "XAG.loky"
          and referer_prefix("http://evil:8888/IPv7:XAG.loky/", ok_hosts) is None
          and referer_prefix("http://localhost:8888/", ok_hosts) is None and referer_prefix(None, ok_hosts) is None)

    # -- the server, against a relay whose host is a dict of pages
    pages = {("XAG.loky", "/"): (200, [("Content-Type", "text/html")], b"<a href=\"/css/a.css\">a</a>"),
             ("XAG.loky", "/css/a.css"): (200, [("Content-Type", "text/css")], b"body{background:url(/i.png)}"),
             ("XAG.loky", "/go"): (302, [("Location", "/landed")], b""),
             ("XAG.loky", "/big"): (200, [("Content-Type", "application/octet-stream")], os.urandom(50000)),
             ("XAG.loky", "/echo"): None}
    seen = []

    class _Relay:
        served = failed = 0

        def fetch(self, method, name, path, timeout=60.0, headers=()):
            seen.append((method, name, path, tuple(headers)))
            if (name, path) not in pages:
                raise FetchError(404, "no site named %s here" % name) if name != "XAG.loky" else FetchError(404, "not found")
            if pages[(name, path)] is None:
                return 200, [("Content-Type", "text/plain")], repr(sorted(headers)).encode()
            return pages[(name, path)]
    info = {"host": "AAAA-BBBB", "address": "192.0.0.172.16.0.2.2", "key": "K", "carrier": "[::1]:7171", "bound": True}
    gw = Gateway(_Relay(), lambda: info, sites=("XAG.loky", "Other"), port=0)
    check("start() binds 127.0.0.1 and reports running", gw.start() and gw.running)
    def get(path, method="GET", headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", gw.port, timeout=5)
        h = {"Host": host or ("localhost:%d" % gw.port)}
        h.update(headers or {})
        c.request(method, path, headers=h)
        r = c.getresponse()
        body = r.read()
        hdrs = [(k, v) for k, v in r.getheaders()]
        c.close()
        return r.status, hdrs, body

    st, h, b = get("/")
    check("the index lists the session rows and the sites as links",
          st == 200 and b"192.0.0.172.16.0.2.2" in b and b"href=\"/IPv7:XAG.loky/\"" in b and b"href=\"/IPv7:Other/\"" in b
          and b"<table border=\"1\">" in b and b"AAAA-BBBB" in b)
    st, h, b = get(STATUS_PATH)
    d = json.loads(b)
    check("status.json carries the session, the sites with their urls and the counters",
          st == 200 and d["session"]["address"] == "192.0.0.172.16.0.2.2" and d["sites"][0]["url"].endswith("/IPv7:XAG.loky/")
          and "served" in d and d["gateway"].startswith("127.0.0.1:"))
    st, h, b = get("/IPv7:XAG.loky/")
    check("a name link fetches over the relay and the html comes back rewritten",
          st == 200 and b == b"<a href=\"/IPv7:XAG.loky/css/a.css\">a</a>" and seen[-1][:3] == ("GET", "XAG.loky", "/")
          and ("Content-Length", str(len(b))) in h and ("X-Content-Type-Options", "nosniff") in h)
    st, h, b = get("/IPv7:XAG.loky/css/a.css")
    check("css is rewritten too", b == b"body{background:url(/IPv7:XAG.loky/i.png)}")
    st, h, b = get("/IPv7:XAG.loky/go")
    check("a redirect's Location is prefixed", st == 302 and ("Location", "/IPv7:XAG.loky/landed") in h)
    st, h, b = get("/IPv7:XAG.loky/big")
    check("a binary body passes through untouched, whole", st == 200 and b == pages[("XAG.loky", "/big")][2])
    st, h, b = get("/IPv7:XAG.loky/big", method="HEAD")
    check("HEAD sends the headers and no body", st == 200 and b == b"" and seen[-1][0] == "HEAD")
    st, h, b = get("/IPv7:XAG.loky/echo", headers={"Cookie": "s=1", "X-Other": "no", "If-None-Match": "\"e\""})
    check("only the allowed request headers travel to the host", st == 200 and b"('Cookie', 's=1')" in b
          and b"If-None-Match" in b and b"X-Other" not in b)
    st, h, b = get("/IPv7:XAG.loky")
    check("a link without the trailing slash is redirected to it", st == 301 and ("Location", "/IPv7:XAG.loky/") in h)
    st, h, b = get("/css/a.css", headers={"Referer": "http://localhost:%d/IPv7:XAG.loky/" % gw.port})
    check("a root-relative request outside the prefix goes back under the page's own prefix (Referer)",
          st == 302 and ("Location", "/IPv7:XAG.loky/css/a.css") in h)
    st, h, b = get("/css/a.css")
    check("... and without a Referer it is 404, pointing at the index", st == 404 and b"/IPv7:NAME/" in b)
    st, h, b = get("/IPv7:Nope/")
    check("a site the host does not have is the host's 404, as a plain page", st == 404 and b"Nope" in b)
    st, h, b = get("/IPv7:192.0.0.172.16.0.2.2/")
    check("an address link gets 501 and a sentence saying why", st == 501 and b"Address links" in b)
    # O16
    st, h, b = get("/IPv7:XAG.loky/", host="evil.example:8888")
    check("a wrong Host header is 421 and nothing is fetched", st == 421 and seen[-1][2] != "/x")
    n_before = len(seen)
    st, h, b = get("/IPv7:XAG.loky/", headers={"Sec-Fetch-Site": "cross-site"})
    check("a cross-site request is 403 before anything goes over the session", st == 403 and len(seen) == n_before)
    st, h, b = get("/IPv7:XAG.loky/", headers={"Sec-Fetch-Site": "same-origin"})
    check("a same-origin request is fine", st == 200)
    st, h, b = get("/IPv7:XAG.loky/", method="OPTIONS", headers={"Origin": "http://evil", "Access-Control-Request-Method": "GET"})
    check("OPTIONS (a preflight) is 403 with no CORS headers at all", st == 403 and not any(k.lower().startswith("access-control") for k, _ in h))
    st, h, b = get("/IPv7:XAG.loky/", method="POST")
    check("POST is 405, only GET and HEAD are allowed", st == 405 and ("Allow", "GET, HEAD") in h)
    check("the counters add up", gw.stats["refused"] == 4 and gw.stats["redirected"] == 1 and gw.stats["served"] >= 6)
    import io as _io
    import socket as _socket
    old_err, sys.stderr = sys.stderr, _io.StringIO()
    try:
        for _ in range(3):
            c = _socket.create_connection(("127.0.0.1", gw.port))
            c.setsockopt(_socket.SOL_SOCKET, _socket.SO_LINGER, __import__("struct").pack("ii", 1, 0))   # a hard reset, like a browser's spare connection
            c.close()
        time.sleep(0.3)
        st, h, b = get(STATUS_PATH)
        noise = sys.stderr.getvalue()
    finally:
        sys.stderr = old_err
    check("a connection reset before any request prints no traceback and is only counted",
          "Traceback" not in noise and json.loads(b)["dropped"] >= 0 and st == 200)
    gw2 = Gateway(_Relay(), lambda: info, port=gw.port)
    check("a second gateway on a taken port says so instead of crashing", gw2.start() is False and gw2.error)
    gw.stop()
    check("stop() ends it", not gw.running)

    import re as _re
    lines = open(__file__, encoding="utf-8").readlines()
    hits = [ln for ln in lines if _re.match(r"\s*(import|from)\s+ipv7_(host|sites)", ln)]
    check("this file never imports host code (the client build stays host-free)", not hits)

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


def main():
    return selftest() if "--selftest" in __import__("sys").argv else (print(__doc__) or 0)


if __name__ == "__main__":
    __import__("sys").exit(main())
