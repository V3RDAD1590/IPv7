#!/usr/bin/env python3
"""ipv7_client_core.py: the IPv7 client -- `ClientConn` (drives a bind, or a resumption, and
then a session over one UDP socket) and the Command: menu loop. No host code anywhere in it:
this file never imports `ipv7_host.py` or `ipv7_host_menu.py`, which is exactly what lets
`ipv7_client.py` (a strict client-only build) import this file and come out of PyInstaller's
import analysis with no way to host a network, no host-identity handling, and no invite-book
logic in the binary at all.

`ipv7_connect.py` (the combined host+client program used for this project's own development and
testing) imports this file too, rather than keeping its own copy, so there is exactly one client
implementation shared by both builds.

`IPv7.session`, written next to the invite file after every successful bind or resumption,
holds what coming back needs (spec section 7): the resumption ticket and secret the host handed
over, the host fingerprint they belong to, and a hash of the invite ticket they came from. With
it, the next run resumes instead of redeeming the invite again -- which it could never do anyway,
since an invite works exactly once. Without resumption, every restart of the client was a dead
bind: the host refused the used invite in silence, each try counted against the throttle, and
the only way back on was a new invite. The secret inside is as sensitive as the ticket: the file
is chmod 600 and nothing in it is ever printed.
"""
import base64
import hashlib
import os
import socket
import struct
import sys
import threading
import time

import ipv6_inet_check as V6
import ipv7_bind as B
import ipv7_inet_users as U
import ipv7_menu as M
import ipv7_path as P
from ipv7_core import (MARK_STEP, MARK_OK, MARK_BAD, DEFAULT_PORT, RECV_TIMEOUT, HOST_ADDR,
                        APP_LIST, APP_LIST_RESP, APP_PING, APP_PING_RESP, APP_BYE, Transport, app_pack,
                        say, read_invite_file)
from ipv7_policy import policy_from_settings
from ipv7_relay import RelayClient, APP_SITE_META, APP_SITE_CHUNK, APP_SITE_ERR
from ipv7_gateway import Gateway
from ipv7_tui import row, enable_vt, confirm_exit

SESSION_FILE = "IPv7.session"


class ClientConn:
    """Drives a bind (or, given `resume=(ticket, secret)` from a saved IPv7.session, a
    resumption) and then a session over one UDP socket, with its own receive thread.
    `progress(step)` is called at each step of either; the login screen's own loading rows hang
    off it. Nothing here prints."""

    def __init__(self, host, port, cert, pin, ticket, settings=None, clock=time.time, resume=None,
                 progress=None):
        family, self.peer = self._resolve(host, port)
        B.pinned_cert(cert, pin)                 # a wrong pin is refused before any packet, either way
        if resume:
            self.client = B.ClientResume(resume[0], resume[1], progress=progress, clock=clock)
        else:
            self.client = B.ClientBind(cert, pin, ticket, progress=progress, clock=clock)
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.settimeout(RECV_TIMEOUT)
        self.settings = settings
        self.timed_out = False
        self.save_error = None                   # set when IPv7.session could not be written
        self.mgr = None
        self.ether = None
        self.transport = Transport(self.sock)
        self.lock = threading.Lock()
        self.pending_app = []
        self.handlers = {}                       # opcode -> callable(app): claimed on the receive thread
        self.gateway = None                      # the local name-link gateway, once started (start_gateway)
        self.relay = None
        self.started_at = None
        self.stop = threading.Event()

    @staticmethod
    def _resolve(host, port):
        """-> (socket family, (ip, port)) for whatever `host` turns out to be -- a plain IPv4
        literal, a bare IPv6 literal (`ipv7_menu.parse_host` already strips the `[...]` brackets
        off one of those before this ever sees it), or a hostname that needs a real DNS lookup
        either way. The socket here used to be hardcoded `AF_INET`, so a real IPv6 host address
        -- exactly the `[...]:port` form `parse_host` accepts and this build's own login prompt
        advertises -- could never actually be dialed: `sendto()` on an IPv4-only socket can't
        resolve an IPv6 literal at all, and that surfaces as a bare, uncaught
        `socket.gaierror: getaddrinfo failed` the moment the first bind packet tries to go out.
        Resolving once here, up front, and building the socket to match whatever family actually
        came back fixes v4 and v6 hosts (and plain hostnames) the same way, and turns an
        unresolvable address into a clean `BindError` instead of a crash three calls later."""
        try:
            infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
        except socket.gaierror as e:
            raise B.BindError("can't resolve host %r: %s" % (host, e), "route")
        family, _, _, _, sockaddr = infos[0]
        return family, sockaddr[:2]

    def bind(self, timeout=10.0):
        """Run the bind (or resumption) to its end. -> the Session, or None with `self.client.error`
        set to say why; a host that never answered (it is down, this address is throttled there,
        or it dropped a used invite in silence -- all the same from here, by section 6's own
        rule) sets `self.timed_out` too. Prints nothing: that is the caller's."""
        try:
            for d in self.client.start():
                self.sock.sendto(d, self.peer)
            end = time.time() + timeout
            while time.time() < end and self.client.session is None and self.client.error is None:
                try:
                    data, _ = self.sock.recvfrom(2048)
                except socket.timeout:
                    for d in self.client.resend():
                        self.sock.sendto(d, self.peer)
                    continue
                for d in self.client.receive(data):
                    self.sock.sendto(d, self.peer)
        except OSError as e:
            # "network is unreachable" (an IPv6 host from a machine with no IPv6 route, say),
            # a closed socket, a firewall refusal: a route problem, reported as one
            self.client.error = B.BindError("network error: %s" % e, "route")
        if self.client.session is None and self.client.error is None:
            self.timed_out = True
            self.client.error = B.BindError("no answer from the host", "route")
        if self.client.session is not None:
            self.started_at = time.time()
            self.mgr = P.PathManager(self.client.session, "user", P.udp_addr(*self.peer),
                                     self._policy(), time.time)
            self.recv_thread = threading.Thread(target=self._serve, daemon=True)
            self.recv_thread.start()
            self.tick_thread = threading.Thread(target=self._ticker, daemon=True)
            self.tick_thread.start()
        return self.client.session

    def _policy(self):
        # the one implementation of "settings -> Policy" lives in ipv7_policy, shared with the
        # host's own current_policy(), so the client and the host never work this out differently
        return policy_from_settings(self.settings)

    def _serve(self):
        while not self.stop.is_set():
            try:
                data, peer = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                plain = self.client.session.rx.open(data)
                if plain is None:
                    continue
                # an IPv6 socket's recvfrom() hands back a 4-tuple (ip, port, flowinfo, scopeid);
                # udp_addr() only ever wants the first two, same as everywhere else in this project
                app, outs = self.mgr.receive(P.udp_addr(*peer[:2]), plain)
                for dest, frame in outs:
                    self.transport.send(dest, frame)
                if app is not None:
                    h = self.handlers.get(app[0]) if app else None
                    if h is not None:
                        h(app)                  # a site message: straight to its fetch, never queued
                    else:
                        with self.lock:
                            self.pending_app.append(app)
            except Exception:                   # one bad datagram must not end the receive thread
                continue                        # (which would look like a dead session, in silence)

    def _ticker(self):
        while not self.stop.is_set():
            time.sleep(1.0)
            try:
                if self.mgr:
                    for dest, frame in self.mgr.tick():
                        self.transport.send(dest, frame)
            except Exception:
                continue

    def send_app(self, op, payload=b""):
        frame = self.client.session.tx.seal(app_pack(op, payload))
        self.transport.send(self.mgr.remote, frame)

    def wait_app(self, op, timeout=3.0):
        end = time.time() + timeout
        while time.time() < end:
            with self.lock:
                for i, a in enumerate(self.pending_app):
                    if a and a[0] == op:
                        return self.pending_app.pop(i)
            time.sleep(0.02)
        return None

    def close(self):
        if self.gateway is not None:
            try:
                self.gateway.stop()
            except Exception:
                pass
        try:
            self.send_app(APP_BYE)
        except Exception:
            pass
        self.stop.set()
        self.sock.close()


# ---------------------------------------------------------------- the local gateway (spec section 9)
def session_info(cc, fpr, carrier):
    """What the gateway's index page and status.json show about this session."""
    sess = cc.client.session
    return {"host": B.groups(bytes.fromhex(fpr)[:10]) if fpr else "?", "fingerprint": fpr or "",
            "address": U.dotted(sess.address), "key": sess.rx.label_text(), "carrier": carrier,
            "bound": not cc.stop.is_set(), "resumed": bool(getattr(cc.client, "resumed", False)),
            "uptime": int(time.time() - cc.started_at) if cc.started_at else 0}


def start_gateway(cc, sites, fpr, carrier):
    """Hang the name-link gateway (ipv7_gateway.py) off a bound session: a RelayClient speaks the
    site messages over `cc`, the gateway serves http://localhost:8888/IPv7:NAME/ from it. -> the
    Gateway (check `.running`; `.error` says why when the port was taken). Stops with cc.close()."""
    relay = RelayClient(cc.send_app)
    for op in (APP_SITE_META, APP_SITE_CHUNK, APP_SITE_ERR):
        cc.handlers[op] = relay.on_app
    gw = Gateway(relay, lambda: session_info(cc, fpr, carrier), sites)
    gw.start()
    cc.relay, cc.gateway = relay, gw
    return gw


def gateway_line(gw):
    if gw is None:
        return "off"
    if gw.running:
        return gw.url
    return "off (port %d is taken: %s)" % (gw.port, gw.error or "?")


def list_users(cc, timeout=3.0):
    cc.send_app(APP_LIST)
    a = cc.wait_app(APP_LIST_RESP, timeout)
    return U.unpack_users(a[1:]) if a else None


def ping(cc, count=4, size=32, out=print, pause=1.0, timeout=3.0):
    """Windows-ping look, over the sealed session: APP_PING carries `size` bytes (a timestamp and
    random fill) and the host echoes them back; a reply that is not ours (late, or stale) is
    not counted. Ends with the usual statistics block."""
    target = U.dotted(HOST_ADDR)
    out("\nPinging %s with %d bytes of data:" % (target, size))
    rtts = []
    for i in range(count):
        payload = struct.pack(">d", time.time()) + os.urandom(max(0, size - 8))
        t0 = time.time()
        try:
            cc.send_app(APP_PING, payload)
        except Exception:
            out("Request timed out.")
            continue
        end = t0 + timeout
        got = None
        while time.time() < end:
            a = cc.wait_app(APP_PING_RESP, timeout=max(0.0, end - time.time()))
            if a is None:
                break
            if a[1:] == payload:
                got = a
                break
        if got is not None:
            ms = (time.time() - t0) * 1000.0
            rtts.append(ms)
            out(U.reply_line(target, size, ms, 64))
        else:
            out("Request timed out.")
        if i < count - 1 and pause:
            time.sleep(pause)
    out("")
    for line in U.ping_stats(target, count, len(rtts), rtts):
        out(line)
    return rtts


def adapter_lines():
    """This machine's own Ethernet adapters, one line each, in the same `|_` style as the host
    admin console's device list. Informational only: nothing here is selectable or wired to Paths
    (the client build has no settings menu, by the user's own call, section 31)."""
    devices, npcap = M.find_devices()
    if not devices:
        return [MARK_STEP + ("no adapters found" if npcap else "no adapters found (Npcap is not installed)")]
    out = []
    for name, desc, mac in devices:
        addr = ":".join("%02X" % x for x in mac) if mac else "no address"
        out.append("%s%s  %s  %s" % (MARK_STEP, name, addr, desc))
    return out


PROMPT = "Command: "                      # the space after the colon is part of the design
HELP = ["   ListUsers     who is on the network right now",
        "   Ping [N]      N round trips to the host over the session (4 if not given)",
        "   Status        this session, its key and the local gateway",
        "   Ipv6          the carrier: endpoint, family, this machine's own IPv6 addresses",
        "   Sites         the sites this invite opens, as links for a browser",
        "   ListAdapters  this machine's own Ethernet adapters (informational)",
        "   Help          this list",
        "   Quit          log out and close"]


def network_row(online=True):
    """What replaced the ###### banner (the user's call, 2026-10-22): one ipconfig-style row."""
    return row("Red Sky Network", "Online" if online else "Offline")


def own_name(cc, timeout=3.0):
    """The nickname the host knows this session by (the invite's name, suffixed if it was
    taken) -- read from ListUsers, since the ticket carrying it is sealed and the client never
    sees it otherwise. -> the name, or None."""
    try:
        sess = cc.client.session
        rows = list_users(cc, timeout=timeout)
        for r in rows or ():
            if list(r[2]) == list(sess.address):
                return r[3]
    except Exception:
        pass
    return None


def _local_v6():
    """This machine's own addresses, the quick way: ipconfig on Windows (no PowerShell start),
    ip/ifconfig elsewhere. -> rows like ipv6_inet_check.local_addresses() gives."""
    try:
        if os.name == "nt":
            return V6.parse_ipconfig(V6.run(["ipconfig"], 15))
        rows = V6.parse_ip_o(V6.run(["ip", "-o", "addr"]))
        return rows or V6.parse_ifconfig(V6.run(["ifconfig"]))
    except Exception:
        return []


def ipv6_lines(cc):
    """The Ipv6 command: the carrier endpoint and family, the socket's own endpoint, the source
    address the OS would pick for the host, then every IPv6 address this machine has, with its
    class (GLOBAL / TEMPORARY / LINK-LOCAL / ULA ...), in the ipconfig style."""
    out = ["", "Adapter UDP6:", ""]
    peer = getattr(cc, "peer", None)
    sock = getattr(cc, "sock", None)
    if peer:
        host, port = peer[0], peer[1]
        fam6 = ":" in host
        out.append(row("Carrier Endpoint", M.host_text((host, port))))
        out.append(row("Carrier Family", "IPv6 (UDP6)" if fam6 else "IPv4 (UDP4)"))
        try:
            lh, lp = sock.getsockname()[:2]
            out.append(row("Local Endpoint", M.host_text((lh, lp))))
        except Exception:
            pass
        src = V6.outbound(socket.AF_INET6 if fam6 else socket.AF_INET, host)
        if src:
            out.append(row("Outbound Source", src))
    else:
        out.append(row("Carrier Endpoint", "?"))
    out.append("")
    out.append("IPv6 addresses on this machine:")
    out.append("")
    rows = [r for r in _local_v6() if r.get("fam") == 6]
    if not rows:
        out.append("   (none found)")
    for r in rows:
        try:
            kind, usable = V6.classify6(r["addr"])
        except Exception:
            kind = "?"
        if r.get("temp"):
            kind = "TEMPORARY"
        label = (r.get("iface") or "adapter")[:30]
        out.append(row(label, "%s/%d  %s" % (r["addr"], r.get("plen", 64), kind)))
    return out


def status_lines(cc):
    """The Status command: the ONLINE banner, then the session and the gateway in the ipconfig
    style. Works against anything with a `.client.session`; missing pieces show as ?."""
    out = ["", network_row(not cc.stop.is_set() if hasattr(cc, "stop") else True), ""]
    sess = getattr(getattr(cc, "client", None), "session", None)
    out.append("Session:")
    out.append("")
    if sess is None:
        out.append(row("Session", "not bound"))
    else:
        gw = getattr(cc, "gateway", None)
        info = gw.info() if gw is not None else {}
        out.append(row("Host", info.get("host", "?")))
        out.append(row("TP/IX Address", U.dotted(sess.address)))
        out.append(row("Key", sess.rx.label_text()))
        out.append(row("Ticket", "resumed" if getattr(cc.client, "resumed", False) else "found"))
        mgr = getattr(cc, "mgr", None)
        carrier = "Ethernet" if (mgr and mgr.remote and mgr.remote.carrier == P.CARRIER_ETH) else "UDP"
        out.append(row("Carrier", carrier + "  (Ipv6 shows the endpoint)"))
        out.append(row("Frames", "sent %d, received %d" % (sess.tx.ctr, sess.rx.window.top)))
        started = getattr(cc, "started_at", None)
        out.append(row("Up", _since(started) if started else "?"))
    out.append("")
    out.append("Gateway:")
    out.append("")
    gw = getattr(cc, "gateway", None)
    out.append(row("Door", gateway_line(gw)))
    if gw is not None:
        out.append(row("Pages", "%d served, %d failed, %d refused" % (gw.stats["served"], gw.stats["failed"], gw.stats["refused"])))
        out.append(row("Sites", ", ".join(gw.sites) if gw.sites else "none on this invite"))
    return out


def sites_lines(cc):
    gw = getattr(cc, "gateway", None)
    if gw is None:
        return [MARK_STEP + "no gateway on this session"]
    if not gw.sites:
        return [MARK_STEP + "this invite opens no sites (the host puts names on an invite when making it)"]
    out = [MARK_STEP + "sites this invite opens, as links for a browser on this machine:"]
    for n in gw.sites:
        out.append("   %-24s %s" % (n, gw.link(n)))
    if not gw.running:
        out.append(MARK_BAD + "the gateway is not running (%s), so the links will not answer" % (gw.error or "?"))
    return out


def _since(t):
    d = int(time.time() - t)
    if d < 60:
        return "%ds" % d
    if d < 3600:
        return "%dm %ds" % (d // 60, d % 60)
    return "%dh %dm" % (d // 3600, (d % 3600) // 60)


def _command_loop(cc, out=None, reader=None):
    """The Command: prompt loop, shared by `connect_cli` (the router-look menu build) and
    `banner_connect_cli` (the no-menu, banner-dressed build) -- there is exactly one of these,
    not two copies that could drift apart. Ctrl-C asks before leaving; a wrong command, a
    timeout or an error inside a command never ends the session. `out`/`reader` default to
    print/input looked up at call time (so a test's patched `input` is the one used)."""
    out = out or print
    reader = reader or input
    try:
        while True:
            try:
                line = reader(PROMPT)
            except EOFError:
                break
            except KeyboardInterrupt:
                if confirm_exit():
                    break
                continue
            parts = line.strip().split()
            c = parts[0].lower() if parts else ""
            try:
                if c in ("listusers", "list", "users"):
                    rows = list_users(cc)
                    if rows is None:
                        out("Request timed out.")
                    else:
                        out("\n" + U.dotted(HOST_ADDR))
                        for x in U.table_lines(rows):
                            out(x)
                elif c == "ping":
                    n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 4
                    ping(cc, count=max(1, min(n, 100)), out=out)
                elif c == "status":
                    for x in status_lines(cc):
                        out(x)
                elif c == "sites":
                    for x in sites_lines(cc):
                        out(x)
                elif c in ("ipv6", "ip6", "carrier"):
                    for x in ipv6_lines(cc):
                        out(x)
                elif c in ("listadapters", "adapters"):
                    for x in adapter_lines():
                        out(x)
                elif c in ("help", "?"):
                    for x in HELP:
                        out(x)
                elif c in ("quit", "exit", "logout"):
                    break
                elif c:
                    out("%s is not a command. Type Help." % parts[0])
            except KeyboardInterrupt:              # Ctrl-C in the middle of a ping: just stop it
                out("")
            except Exception as e:                 # a bug in one command is not a reason to log out
                out("%s%s failed: %s: %s" % (MARK_BAD, parts[0] if parts else "command", type(e).__name__, e))
    finally:
        cc.close()
    out(U.EXIT_LINE)


# ---------------------------------------------------------------- the session file (spec section 7)
def session_path_for(invite_path):
    """IPv7.session lives next to the invite file it belongs to."""
    return os.path.join(os.path.dirname(invite_path or ""), SESSION_FILE)


def invite_hash(ticket):
    return hashlib.sha256(b"IPv7 invite " + ticket).hexdigest()


def write_session_file(path, fpr, invite_ticket, sess):
    """After a successful bind or resumption: what the next run needs to come back without a
    new invite. The host fingerprint and a hash of the invite ticket say WHICH host and WHICH
    invite this belongs to, so a new invite file is never shadowed by an old session, and a
    session from another host is never offered to this one. chmod 600: the secret inside is as
    sensitive as the ticket."""
    with open(path, "w", encoding="ascii") as f:
        f.write("IPv7.session\n")
        f.write("fingerprint %s\n" % fpr)
        f.write("invite %s\n" % invite_hash(invite_ticket))
        f.write("ticket %s\n" % base64.b64encode(sess.resumption_ticket).decode())
        f.write("secret %s\n" % base64.b64encode(sess.resumption_secret).decode())
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def read_session_file(path):
    """-> (fingerprint, invite hash, resumption ticket, resumption secret), or None when there is
    no such file or it is damaged (a damaged one is simply not used; the invite flow runs)."""
    try:
        with open(path, "r", encoding="ascii") as f:
            lines = [ln.rstrip("\n") for ln in f]
    except OSError:
        return None
    try:
        if not lines or lines[0] != "IPv7.session":
            return None
        kv = dict(ln.split(" ", 1) for ln in lines[1:] if " " in ln)
        ticket = base64.b64decode(kv["ticket"])
        secret = base64.b64decode(kv["secret"])
        if len(ticket) != B.RESUME_TICKET or len(secret) != 32:
            return None
        return kv["fingerprint"], kv["invite"], ticket, secret
    except (KeyError, ValueError):
        return None


def resume_for(fpr, invite_ticket, path):
    """-> (resumption ticket, secret) when IPv7.session is for this very host AND this very
    invite, else None (then the invite flow runs, as for a first login)."""
    s = read_session_file(path)
    if s is None:
        return None
    s_fpr, s_inv, ticket, secret = s
    if s_fpr.lower() != fpr.lower() or s_inv != invite_hash(invite_ticket):
        return None
    return ticket, secret


def forget_session(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _connect(host, port, cert, fpr, ticket, settings, session_path, progress=None, timeout=10.0):
    """One attempt to get a session: resume if IPv7.session matches, else the invite flow; on
    success write IPv7.session for next time. -> (ClientConn or None, BindError or None): the
    error is None on success; the ClientConn is None only when it could not even be built (an
    unresolvable host, a wrong pin), and is already closed when the bind itself failed. Shared
    by both CLIs so the two can never differ in WHEN they resume."""
    resume = resume_for(fpr, ticket, session_path) if session_path else None
    try:
        cc = ClientConn(host, port, cert, fpr, ticket, settings, resume=resume, progress=progress)
    except B.BindError as e:
        return None, e
    sess = cc.bind(timeout=timeout)
    if sess is None:
        cc.close()
        if resume and not cc.timed_out:
            # the host answered and the resumption was refused outright: the saved session is
            # dead (used from elsewhere -- section 7's own warning sign -- or the host's book
            # changed under it); forget it so the next try is a plain invite bind, which works
            # if the invite itself was never used
            forget_session(session_path)
        return cc, cc.client.error
    if session_path:
        try:
            write_session_file(session_path, fpr, ticket, sess)
        except OSError as e:
            cc.save_error = "%s: %s" % (type(e).__name__, e)
    return cc, None


def connect_cli(args):
    settings = None
    if args.invite and args.host_key:
        try:
            fpr, sites, cert, ticket = read_invite_file(args.invite)
        except (OSError, ValueError) as e:
            say(MARK_BAD, "could not read the invite file %r: %s" % (args.invite, e))
            return 1
        fpr = args.host_key
        invite_path = args.invite
    else:
        s = M.load_settings()
        if args.host:                          # else: leave whatever was saved/blank; the
            s.host = M.host_text((args.host, args.port))   # menu's own Host row lets it be typed in
        devices, npcap = M.find_devices()
        while True:
            try:
                saved = M.run_menu(s, devices, npcap, saver=M.save_settings) if sys.stdin.isatty() else s
                break
            except KeyboardInterrupt:              # Ctrl-C in the menu: ask, then show it again
                if confirm_exit():
                    saved = None
                    break
        if saved is None:
            print(M.EXIT_LINE)
            return 1
        settings = saved
        try:
            fpr, sites, cert, ticket = read_invite_file(settings.invite)
        except (OSError, ValueError) as e:
            say(MARK_BAD, "could not read the invite file %r: %s" % (settings.invite, e))
            return 1
        h, p = M.parse_host(settings.host)
        args.host, args.port = h, p
        invite_path = settings.invite
    steps = {"hello": "HELLO sent", "cookie": "cookie received", "keygen": "making the session keys ...",
             "hello2": "HELLO2 sent", "accept": "host signature verified", "finished": "FINISHED sent",
             "resume": "RESUME sent (coming back on the saved session)", "ready": "session ready"}
    while True:
        try:
            cc, err = _connect(args.host, args.port, cert, fpr, ticket, settings, session_path_for(invite_path),
                               progress=lambda step: say(MARK_STEP, steps.get(step, step)))
            break
        except KeyboardInterrupt:                  # Ctrl-C mid-bind: ask; 'no' tries the bind again
            if confirm_exit():
                print(M.EXIT_LINE)
                return 1
    if err is not None:
        say(MARK_BAD, "route ? | key ? | ticket ? - !NO MATCH! (%s: %s)" % (err.field, err))
        return 1
    say(MARK_OK, cc.client.result_line())
    if getattr(cc, "save_error", None):
        say(MARK_BAD, "could not save IPv7.session (%s): next time will need the invite again" % cc.save_error)
    gw = start_gateway(cc, sites, fpr, M.host_text((args.host, args.port)))
    say(MARK_OK if gw.running else MARK_BAD, "gateway " + gateway_line(gw))
    _command_loop(cc)
    return 0


# ---------------------------------------------------------------- the no-menu, banner-dressed login
def _clear_screen():
    """A full clear between the login sequence's 'pages', not the incremental redraw `Screen`
    does for a router-look menu -- this flow is a scrolling log on purpose (per the user's own
    mock-up), just not one that piles every page on top of the last forever."""
    enable_vt()
    print("\x1b[2J\x1b[H", end="")


def _gather_host_and_invite(args):
    """No interactive settings menu for this build (the user's own call -- see ipv7_client.py):
    load whatever IPv7.conf already has, let the command line override the host, and ask, once
    and plainly, for anything still missing -- the host address, or the invite file if the one
    on record isn't there. Paths/device/EtherType/link stay whatever IPv7.conf already says
    (UDP-only by default); there is no row here to change them. -> a Settings object ready to
    bind with, or None if the person gave up (an empty answer, or EOF)."""
    s = M.load_settings()
    if args.host:
        s.host = M.host_text((args.host, args.port))
    while not M.parse_host(s.host):
        try:
            text = input("Host address (name, IP, or IP:port): ").strip()
        except EOFError:
            return None
        if not text:
            return None
        h = M.parse_host(text)
        if h is None:
            print("that doesn't look like a host; try again, or leave it blank to give up.")
            continue
        s.host = M.host_text(h)
    while not os.path.isfile(s.invite):
        try:
            text = input("Invite file (%s not found): " % s.invite).strip()
        except EOFError:
            return None
        if not text:
            return None
        s.invite = text
    return s


class Loading:
    """The bind shown ipconfig-style, one dotted row per step as it happens, instead of the old
    `|_ growing dots ...` lines (section 13 item 1, O21) -- so the login screen is all one look
    and the `*_`/`|_` marks never mix into it. The slow step (making the RSA-4096 and ML-KEM
    keys) shows `generating ...` on a line that is then rewritten in place with `\\r` once the
    keys exist; everything else is simply appended. Ends with the three result rows (route, key,
    ticket) and the `!MATCH!` / `!NO MATCH!` verdict of section 13 items 2 to 4."""

    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.pending = None

    def _line(self, text):
        self.out.write(text + "\n")
        if hasattr(self.out, "flush"):
            self.out.flush()

    def step(self, name):
        if name == "cookie":
            self._line(row("Cookie", "received"))
        elif name == "keygen":
            self.out.write(row("Session keys", "generating ..."))
            if hasattr(self.out, "flush"):
                self.out.flush()
            self.pending = "Session keys"
        elif name == "hello2":
            self.out.write("\r" + row("Session keys", "generated (RSA-4096 + ML-KEM-1024)") + "\n")
            if hasattr(self.out, "flush"):
                self.out.flush()
            self.pending = None
        elif name == "accept":
            self._line(row("Host", "signature verified"))
        elif name == "resume":
            self._line(row("Session keys", "fresh ML-KEM-1024, resuming"))

    def result(self, cc, err, host_text):
        """The three result rows and the verdict. `err` is None on success; otherwise the
        BindError, with `cc` None when nothing could even be sent (bad host, wrong pin)."""
        if self.pending:                          # the bind died mid-step: finish the open line
            self.out.write("\n")
            self.pending = None
        if err is None:
            sess = cc.client.session
            self._line(row("Route", U.dotted(sess.address)))
            self._line(row("Key", sess.rx.label_text()))
            self._line(row("Ticket", "resumed" if cc.client.resumed else "found"))
            self._line("")
            self._line("   !MATCH!")
            return True
        field = err.field
        self._line(row("Route", "?"))
        self._line(row("Key", "?"))
        self._line(row("Ticket", "refused" if field == "ticket" else "?"))
        self._line("")
        if cc is not None and cc.timed_out:
            self._line("   !NO MATCH! (no answer from %s)" % host_text)
            self._line("   The host may be down or unreachable, this address may be throttled there,")
            self._line("   or this invite may already have been used (a new invite from the host fixes that).")
        else:
            self._line("   !NO MATCH! (%s: %s)" % (field, err))
        return False


def _login_once(args, cert, fpr, ticket, settings, invite_path, sites=()):
    """One pass of the login screen after the gate, -> ClientConn or None. Prints the loading
    rows, the verdict, and on success the adapter blocks (TP/IX first, then UDP6 with the key
    and the login), the gateway row and DONE!."""
    carrier = M.host_text((args.host, args.port))
    print()
    print("Assigning a TP/IX address from %s" % carrier)
    print()
    loading = Loading()
    cc, err = _connect(args.host, args.port, cert, fpr, ticket, settings, session_path_for(invite_path),
                       progress=loading.step)
    if not loading.result(cc, err, carrier):
        return None
    sess = cc.client.session
    gw = start_gateway(cc, sites, fpr, carrier)
    print()
    print("TP/IX Adapter:")
    print()
    print(row("TP/IX Address", U.dotted(sess.address)))
    print(row("Host", U.dotted(HOST_ADDR)))
    print(row("Gateway", gateway_line(gw)))
    print()
    print("Adapter UDP6:")                      # the endpoint itself moved to the Ipv6 command (the user's call)
    print()
    print(row("Key", sess.rx.label_text()))
    print(row("Login", "Yes"))
    if getattr(cc, "save_error", None):
        print(row("Session file", "not saved: %s" % cc.save_error))
    print()
    print("DONE!")
    return cc


def banner_connect_cli(args):
    """The whole login screen the user asked for instead of the router-look IPv7 SETUP menu: a
    private-network box, an 'Enter to assign' gate before the real bind, the bind itself as
    ipconfig-style loading rows ending in !MATCH!, the TP/IX adapter block and then the carrier
    block, DONE!, the "Red Sky Network : Online" row and a welcome by name -- then straight into
    Command:, same as `connect_cli` (the commands are not listed; Help lists them). No settings menu at all: see `_gather_host_and_invite` for what little this
    still has to ask. This machine's own adapters are no longer listed here; they are one
    `ListAdapters` away at the Command: prompt.

    Ctrl-C anywhere in here asks before leaving. A login that fails offers another try."""
    _clear_screen()
    for line in U.PRIVATE_BOX:
        print(line)
    print()
    while True:
        try:
            try:
                input("Enter to assign a TP/IX address...")
            except EOFError:
                print(U.EXIT_LINE)
                return 1

            settings = None
            if args.invite and args.host_key:
                try:
                    fpr, sites, cert, ticket = read_invite_file(args.invite)
                except (OSError, ValueError) as e:
                    print("   !NO MATCH! (ticket: could not read the invite file %r: %s)" % (args.invite, e))
                    print(U.EXIT_LINE)
                    return 1
                invite_path = args.invite
            else:
                settings = _gather_host_and_invite(args)
                if settings is None:
                    print(U.EXIT_LINE)
                    return 1
                try:
                    fpr, sites, cert, ticket = read_invite_file(settings.invite)
                except (OSError, ValueError) as e:
                    print("   !NO MATCH! (ticket: could not read the invite file %r: %s)" % (settings.invite, e))
                    print(U.EXIT_LINE)
                    return 1
                h, p = M.parse_host(settings.host)
                args.host, args.port = h, p
                invite_path = settings.invite

            cc = _login_once(args, cert, fpr, ticket, settings, invite_path, sites)
            if cc is None:
                try:
                    again = input("\nEnter to try again, or q to quit: ").strip().lower()
                except EOFError:
                    again = "q"
                if again.startswith("q"):
                    print(U.EXIT_LINE)
                    return 1
                print()
                continue
            break
        except KeyboardInterrupt:
            if confirm_exit():
                print(U.EXIT_LINE)
                return 1
            print()

    if settings is not None:
        try:
            M.save_settings(settings)             # a login that worked: the next run asks nothing
        except OSError:
            pass
    print()
    print(network_row(True))
    print()
    name = own_name(cc)
    print("Login Accepted! Welcome%s." % (" " + name if name else ""))
    _command_loop(cc)
    return 0


# ---------------------------------------------------------------- selftest
def selftest():
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    import re as _re
    lines = open(__file__, encoding="utf-8").readlines()
    imports = [ln for ln in lines if _re.match(r"\s*(import|from)\s+ipv7_host", ln)]
    check("this file never imports ipv7_host or ipv7_host_menu (the split stays one-directional)",
          not imports)

    import argparse as _ap
    args = _ap.Namespace(host=None, port=DEFAULT_PORT, invite="/no/such/IPv7.key",
                         host_key="00" * 32, name=None, days=None, sites=None)
    check("connect_cli reports a missing/bad invite file cleanly instead of crashing",
          connect_cli(args) == 1)

    # -- _gather_host_and_invite: the no-settings-menu path's one and only interactive step
    import tempfile
    import unittest.mock as mock

    def drive_gather(answers, host=None, port=DEFAULT_PORT):
        a = _ap.Namespace(host=host, port=port)
        it = iter(answers)
        with mock.patch("builtins.input", lambda _prompt="": next(it)):
            return _gather_host_and_invite(a)

    cwd = os.getcwd()

    def in_fresh_dir(fn):
        with tempfile.TemporaryDirectory() as d:
            os.chdir(d)
            try:
                return fn()
            finally:
                os.chdir(cwd)

    def with_invite_present():
        with open("IPv7.key", "w") as f:
            f.write("placeholder")
        s = drive_gather(["192.0.2.1:7171"])
        return (s is not None and s.host == "192.0.2.1:7171" and s.invite == "IPv7.key",
                drive_gather(["junk host", "192.0.2.1:7171"]))

    ok1, s2 = in_fresh_dir(with_invite_present)
    check("_gather_host_and_invite asks for a host only when none is on record, and accepts it", ok1)
    check("a bad host answer is refused and asked again, not accepted",
          s2 is not None and s2.host == "192.0.2.1:7171")
    check("an empty answer gives up (None), it does not loop forever",
          in_fresh_dir(lambda: drive_gather([""])) is None)

    def with_no_invite_file():
        # host is already valid (given on the command line), so only the invite prompt should
        # fire; "weird.key" doesn't exist either, so it's asked again, and a blank answer there
        # gives up -- this exercises the invite-file loop separately from the host-address one.
        return drive_gather(["weird.key", ""], host="192.0.2.1")
    check("a host given on the command line, but no invite file on record, is asked for the invite file",
          in_fresh_dir(with_no_invite_file) is None)

    # -- IPv7.session: what a later run resumes from (no socket needed for any of this)
    class _Sess:
        resumption_ticket, resumption_secret = os.urandom(B.RESUME_TICKET), os.urandom(32)
    fpr, inv = "ab" * 32, os.urandom(B.INVITE_TICKET)

    def session_round_trip():
        p = session_path_for("IPv7.key")
        write_session_file(p, fpr, inv, _Sess)
        got = read_session_file(p)
        mode_ok = os.name == "nt" or (os.stat(p).st_mode & 0o777) == 0o600
        return (got == (fpr, invite_hash(inv), _Sess.resumption_ticket, _Sess.resumption_secret) and mode_ok,
                resume_for(fpr, inv, p) == (_Sess.resumption_ticket, _Sess.resumption_secret),
                resume_for("cd" * 32, inv, p) is None,             # another host's fingerprint
                resume_for(fpr, os.urandom(B.INVITE_TICKET), p) is None,   # a NEW invite: not shadowed
                p == "IPv7.session")
    rt, match, other_host, new_invite, beside = in_fresh_dir(session_round_trip)
    check("IPv7.session round-trips the fingerprint, invite hash, ticket and secret, chmod 600", rt)
    check("resume_for() offers the saved session for the same host and the same invite", match)
    check("... but not for another host's fingerprint", other_host)
    check("... and not for a new invite (a fresh IPv7.key is never shadowed by an old session)", new_invite)
    check("the session file lives next to the invite file", beside
          and session_path_for(os.path.join("some", "dir", "x.key")) == os.path.join("some", "dir", SESSION_FILE))

    def damaged_session():
        with open("IPv7.session", "w") as f:
            f.write("IPv7.session\nfingerprint x\ninvite y\nticket !!!\nsecret ???\n")
        a = read_session_file("IPv7.session")
        with open("IPv7.session", "w") as f:
            f.write("not a session file at all\n")
        b = read_session_file("IPv7.session")
        forget_session("IPv7.session")
        return a is None and b is None and not os.path.exists("IPv7.session") and read_session_file("IPv7.session") is None
    check("a damaged or foreign IPv7.session is simply not used, and forget_session() removes it",
          in_fresh_dir(damaged_session))

    # -- the ipconfig-style loading rows, driven by the same progress steps the bind really emits
    import io
    out = io.StringIO()
    ld = Loading(out)
    for step in ("hello", "cookie", "keygen", "hello2", "accept", "finished"):
        ld.step(step)
    text = out.getvalue()
    check("Loading shows cookie / session keys / host rows in the dotted ipconfig style, no *_ or |_ marks",
          "Cookie" in text and "generating ..." in text and "\r" in text and "generated" in text
          and "signature verified" in text and MARK_OK not in text and MARK_STEP not in text and " : " in text)

    class _Dir:
        label = b"L" * 10

        @staticmethod
        def label_text():
            return "AAAA-BBBB-CCCC-DDDD"

    class _FakeSession:
        address, rx = bytes([192, 0, 0, 172, 16, 0, 2, 2]), _Dir()

    class _FakeClient:
        session, resumed, error = _FakeSession(), False, None

    class _FakeConn:
        client, timed_out = _FakeClient(), False
    out = io.StringIO()
    ok_match = Loading(out).result(_FakeConn(), None, "[::1]:7171")
    check("a completed bind ends in the route/key/ticket rows and !MATCH!", ok_match
          and "192.0.0.172.16.0.2.2" in out.getvalue() and "AAAA-BBBB-CCCC-DDDD" in out.getvalue()
          and "found" in out.getvalue() and "!MATCH!" in out.getvalue())
    _FakeClient.resumed = True
    out = io.StringIO()
    Loading(out).result(_FakeConn(), None, "[::1]:7171")
    check("a resumed session says so in the ticket row", "resumed" in out.getvalue())

    class _TimedOut:
        timed_out = True

        class client:
            session, error = None, B.BindError("no answer from the host", "route")
    out = io.StringIO()
    ld = Loading(out)
    ld.step("keygen")
    ok_no = ld.result(_TimedOut(), _TimedOut.client.error, "[::1]:7171")
    check("a host that never answered gives !NO MATCH! with the three possible reasons, the open row closed first",
          not ok_no and "!NO MATCH! (no answer from [::1]:7171)" in out.getvalue() and "throttled" in out.getvalue()
          and "already have been used" in out.getvalue() and out.getvalue().count("\n") >= 7)
    out = io.StringIO()
    Loading(out).result(None, B.BindError("can't resolve host 'nope'", "route"), "nope:7171")
    check("an unresolvable host gives !NO MATCH! (route: ...) with nothing sent",
          "!NO MATCH! (route: can't resolve host 'nope')" in out.getvalue())

    # -- the Command: loop's new commands, against a stub connection (no socket)
    class _StubConn:
        def __init__(self):
            self.closed, self.sent = False, []

        def send_app(self, op, payload=b""):
            self.sent.append((op, payload))

        def wait_app(self, op, timeout=3.0):
            if op == APP_PING_RESP and self.sent:
                return bytes([APP_PING_RESP]) + self.sent[-1][1]
            if op == APP_LIST_RESP:
                return bytes([APP_LIST_RESP]) + U.pack_users([(U.ADMIN, True, HOST_ADDR, "ADMIN", False)])
            return None

        def close(self):
            self.closed = True
    outs = []
    answers = iter(["help", "bogus", "ping 2", "listusers", "quit"])
    stub = _StubConn()
    with mock.patch.object(time, "sleep", lambda s: None):
        _command_loop(stub, out=outs.append, reader=lambda _p: next(answers))
    text = "\n".join(outs)
    check("Help lists the commands (Ipv6 among them), a wrong one is refused, the loop ends on Quit and closes the connection",
          "ListAdapters" in text and "Status" in text and "Sites" in text and "Ipv6" in text and "bogus is not a command" in text
          and stub.closed and U.EXIT_LINE in text)
    check("the prompt keeps its space after the colon", PROMPT == "Command: ")
    check("Ping N sends N APP_PINGs over the session and prints Windows-style replies and statistics",
          sum(1 for op, _ in stub.sent if op == APP_PING) == 2 and "Reply from %s" % U.dotted(HOST_ADDR) in text
          and "Packets: Sent = 2, Received = 2, Lost = 0 (0% loss)" in text)
    check("ListUsers still prints the table", "ADMIN" in text)
    answers = iter(["listadapters", "quit"])
    outs = []
    _command_loop(_StubConn(), out=outs.append, reader=lambda _p: next(answers))
    check("ListAdapters lists this machine's adapters (or says there are none) in the |_ style",
          any(x.startswith(MARK_STEP) for x in outs))

    answers = iter(["status", "sites", "quit"])
    outs = []
    _command_loop(_StubConn(), out=outs.append, reader=lambda _p: next(answers))
    text = "\n".join(outs)
    check("Status on a connection with no session shows the Red Sky Network row, 'not bound' and the gateway off; Sites says there is none",
          "Red Sky Network" in text and "not bound" in text and "Door" in text and "no gateway" in text)

    # -- status_lines / sites_lines against a session-shaped stub with a gateway on a free port
    class _Win:
        top = 7

    class _Rx:
        window = _Win()

        @staticmethod
        def label_text():
            return "AAAA-BBBB-CCCC-DDDD"

    class _Tx:
        ctr = 12

    class _S:
        address, rx, tx = bytes([192, 0, 0, 172, 16, 0, 2, 2]), _Rx(), _Tx()

    class _C:
        session, resumed = _S(), True

    class _Conn:
        client, stop, mgr, peer, started_at, handlers = _C(), threading.Event(), None, ("::1", 7171), time.time() - 65, {}
        gateway = relay = None

        @staticmethod
        def send_app(op, payload=b""):
            pass
    conn = _Conn()
    with mock.patch.dict(os.environ, {"IPV7_GATEWAY_PORT": "0"}):
        gw = start_gateway(conn, ("XAG.loky", "Gallery"), "ab" * 32, "[::1]:7171")
    try:
        text = "\n".join(status_lines(conn))
        check("Status on a bound session shows host, address, key, resumed, carrier, frames, uptime and the gateway rows",
              "192.0.0.172.16.0.2.2" in text and "AAAA-BBBB-CCCC-DDDD" in text and "resumed" in text and "UDP" in text
              and "sent 12, received 7" in text and "1m 5s" in text and "0 served" in text and "XAG.loky, Gallery" in text)
        class _Sock:
            @staticmethod
            def getsockname():
                return ("::1", 40000, 0, 0)
        conn.sock = _Sock()
        v6 = "\n".join(ipv6_lines(conn))
        check("Ipv6 shows the carrier endpoint and family, the local endpoint and this machine's IPv6 addresses",
              "Carrier Endpoint" in v6 and "[::1]:7171" in v6 and "IPv6 (UDP6)" in v6 and "[::1]:40000" in v6
              and "IPv6 addresses on this machine" in v6)
        stext = "\n".join(sites_lines(conn))
        check("Sites lists each name with its gateway link", "XAG.loky" in stext and "/IPv7:Gallery/" in stext)
        check("start_gateway registers the site opcodes on the connection and the gateway runs",
              all(op in conn.handlers for op in (APP_SITE_META, APP_SITE_CHUNK, APP_SITE_ERR)) and gw.running
              and gw.info()["address"] == "192.0.0.172.16.0.2.2" and gw.info()["resumed"])
    finally:
        gw.stop()

    def interrupted(_p):
        raise KeyboardInterrupt
    answers = iter([interrupted, lambda _p: "quit"])
    with mock.patch.object(sys.modules[__name__], "confirm_exit", lambda: False):
        outs = []
        stub = _StubConn()
        _command_loop(stub, out=outs.append, reader=lambda p: next(answers)(p))
    check("Ctrl-C at the Command: prompt asks; 'no' keeps the session, the prompt comes back",
          stub.closed and U.EXIT_LINE in outs)
    with mock.patch.object(sys.modules[__name__], "confirm_exit", lambda: True):
        stub = _StubConn()
        _command_loop(stub, out=lambda _x: None, reader=interrupted)
    check("Ctrl-C then 'yes' logs out cleanly", stub.closed)

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


def main():
    return selftest() if "--selftest" in sys.argv else (print(__doc__) or 0)


if __name__ == "__main__":
    sys.exit(main())
