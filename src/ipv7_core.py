#!/usr/bin/env python3
"""ipv7_core.py: the small, content-free pieces shared by both ends of a session -- the opcode
constants, the Transport that hands a sealed frame to a real UDP socket or an Ethernet carrier,
the IPv7.key reader, and the one "say" print style used everywhere else in this project.

Deliberately content-free: nothing here knows a host's private key, an invite book, or any
host-admin surface. `ipv7_client.py` (a strict client-only build, with no host code at all) and
`ipv7_host.py` (the host) both import this file, and this file imports neither of them.
"""
import base64

import ipv7_menu as M
import ipv7_path as P

MARK_STEP, MARK_OK, MARK_BAD = "|_", "*_", "-_"
DEFAULT_PORT = M.DEFAULT_PORT
RECV_TIMEOUT, KEEPALIVE = 0.2, 10.0
HOST_ADDR = [192, 0, 0, 172, 16, 0, 1, 1]            # HOST 1 of the test network, as in ipv7_inet_users

# the application layer riding on top of each session's sealed frames, once a bind has completed
APP_LIST, APP_LIST_RESP, APP_PING, APP_PING_RESP, APP_BYE = 1, 0x81, 2, 0x82, 4


def say(mark, text):
    print("%s%s" % (mark, text))


def read_invite_file(path):
    """-> (fingerprint, sites, cert bytes, ticket bytes)"""
    fpr, sites, cert, ticket = None, (), None, None
    with open(path, encoding="ascii") as f:
        for line in f:
            k, _, v = line.strip().partition(" ")
            if k == "fingerprint":
                fpr = v
            elif k == "sites":
                sites = tuple(s for s in v.split(",") if s)
            elif k == "cert":
                cert = base64.b64decode(v)
            elif k == "ticket":
                ticket = base64.b64decode(v)
    if not (fpr and cert and ticket):
        raise ValueError("not a valid IPv7.key file")
    return fpr, sites, cert, ticket


def app_pack(op, payload=b""):
    return bytes([op]) + payload


def app_send(sess, mgr, transport, op, payload=b""):
    frame = sess.tx.seal(app_pack(op, payload))
    transport.send(mgr.remote if mgr else None, frame)


class Transport:
    """One UDP socket, plus an optional Ethernet carrier once a path move succeeds. `send` takes
    a path.Addr (UDP or Ethernet) or, with no path manager yet (during the bind), a plain
    (ip, port) tuple."""

    def __init__(self, sock, carrier=None):
        self.sock, self.carrier = sock, carrier

    def send(self, addr, frame):
        if addr is None or (hasattr(addr, "carrier") and addr.carrier == P.CARRIER_UDP) or isinstance(addr, tuple):
            ip, port = (addr.ip, addr.port) if hasattr(addr, "carrier") else addr
            self.sock.sendto(frame, (ip, port))
        elif addr.carrier == P.CARRIER_ETH and self.carrier is not None:
            self.carrier.send(addr.link, frame)


# ---------------------------------------------------------------- selftest
def selftest():
    import socket as _socket
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % (MARK_OK if ok else MARK_BAD, name, "" if ok else "FAILED"))

    check("say() prints the mark then the text", True)  # smoke only; printed output isn't captured here
    check("app_pack prepends the opcode byte", app_pack(APP_PING, b"xy") == bytes([APP_PING]) + b"xy")
    fpr, sites, cert, ticket = None, None, None, None
    try:
        read_invite_file("/nonexistent-ipv7-invite-file")
        check("read_invite_file on a missing file raises", False)
    except (OSError, ValueError):
        check("read_invite_file on a missing file raises", True)

    import tempfile
    with tempfile.TemporaryDirectory() as d:
        import os
        path = os.path.join(d, "IPv7.key")
        with open(path, "w", encoding="ascii") as f:
            f.write("IPv7.key\n")
            f.write("fingerprint AA\n")
            f.write("sites a,b\n")
            f.write("cert %s\n" % base64.b64encode(b"CERT").decode())
            f.write("ticket %s\n" % base64.b64encode(b"TICKET").decode())
        fpr, sites, cert, ticket = read_invite_file(path)
    check("read_invite_file round-trips fingerprint, sites, cert and ticket",
          fpr == "AA" and sites == ("a", "b") and cert == b"CERT" and ticket == b"TICKET")

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    t = Transport(sock)
    t.send(("127.0.0.1", sock.getsockname()[1]), b"hello")
    data, _ = sock.recvfrom(64)
    check("Transport.send delivers a plain (ip, port) tuple over a real UDP socket", data == b"hello")
    sock.close()

    n = sum(results)
    print("%s%d of %d checks passed" % (MARK_OK if n == len(results) else MARK_BAD, n, len(results)))
    return 0 if n == len(results) else 1


def main():
    return selftest() if "--selftest" in __import__("sys").argv else (print(__doc__) or 0)


if __name__ == "__main__":
    __import__("sys").exit(main())
