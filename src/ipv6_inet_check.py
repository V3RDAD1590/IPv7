#!/usr/bin/env python3
"""ipv6_inet_check.py - can this machine be reached over IPv6, and does 172.16.0.0/12 clash here?

  python ipv6_inet_check.py                    report
  python ipv6_inet_check.py --help             every option
  python ipv6_inet_check.py --status           add the explanatory Status lines
  python ipv6_inet_check.py --online           also ask ipify what the internet sees (v6 and v4)
  python ipv6_inet_check.py --wan 100.64.1.2   the WAN ipv4 your router shows -> CGNAT check
  python ipv6_inet_check.py --port 7171        port used in the carrier lines (default 7171)
  python ipv6_inet_check.py --selftest         checks of the code itself, nothing touches the network

The two-machine test (--receive / --connect) is its own file: ipv7_inet_peer.py.
Standard library only. Without --online nothing leaves the machine.
"""
import argparse
import csv
import io
import ipaddress
import platform
import re
import socket
import subprocess
import sys
import textwrap
import urllib.request

OVERLAY = "172.16.0.0/12"

# order matters: the first match wins, so the narrow blocks come before 2000::/3
V6_CLASSES = [
    ("::1/128", "LOOPBACK", False),
    ("::/128", "UNSPECIFIED", False),
    ("fe80::/10", "LINK-LOCAL", False),
    ("fc00::/7", "ULA-PRIVATE", False),
    ("ff00::/8", "MULTICAST", False),
    ("::ffff:0:0/96", "V4-MAPPED", False),
    ("64:ff9b::/96", "NAT64", False),
    ("2001:db8::/32", "DOCUMENTATION", False),
    ("2001::/32", "TEREDO", True),
    ("2002::/16", "6TO4", True),
    ("2000::/3", "GLOBAL", True),
]
V4_CLASSES = [
    ("127.0.0.0/8", "LOOPBACK"),
    ("169.254.0.0/16", "LINK-LOCAL"),
    ("100.64.0.0/10", "CGNAT"),
    ("10.0.0.0/8", "PRIVATE"),
    ("172.16.0.0/12", "PRIVATE"),
    ("192.168.0.0/16", "PRIVATE"),
    ("0.0.0.0/8", "UNSPECIFIED"),
    ("224.0.0.0/4", "MULTICAST"),
]


def strip_scope(s):
    return s.split("%")[0]


def classify6(a):
    ip = ipaddress.IPv6Address(strip_scope(a))
    for net, name, usable in V6_CLASSES:
        if ip in ipaddress.ip_network(net):
            return name, usable
    return "RESERVED", False


def classify4(a):
    ip = ipaddress.IPv4Address(strip_scope(a))
    for net, name in V4_CLASSES:
        if ip in ipaddress.ip_network(net):
            return name
    return "PUBLIC"


def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except Exception:
        return ""


# ---- reading the machine's own addresses -------------------------------------------------------

def v6_tokens(line):
    out = []
    for tok in re.findall(r"[0-9A-Fa-f:]*:[0-9A-Fa-f:]+", line):
        try:
            ipaddress.IPv6Address(tok)
            out.append(tok)
        except ValueError:
            pass
    return out


def parse_ps_csv(text):
    """Get-NetIPAddress | Select IPAddress,InterfaceAlias,PrefixLength,AddressFamily,pref | ConvertTo-Csv"""
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        a = (r.get("IPAddress") or "").strip()
        if not a:
            continue
        fam = 6 if ":" in a else 4
        try:
            plen = int(r.get("PrefixLength") or 0)
        except ValueError:
            plen = 0
        try:
            pref = int(r.get("pref") or -1)
        except ValueError:
            pref = -1
        rows.append({"addr": strip_scope(a), "iface": (r.get("InterfaceAlias") or "").strip(),
                     "plen": plen, "fam": fam, "pref": pref, "temp": False})
    return rows


def parse_ipconfig(text):
    """fallback for Windows without PowerShell; English ipconfig labels"""
    rows, iface, last4 = [], "", None
    for line in text.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            iface = re.sub(r"^.*adapter\s+", "", line.rstrip()[:-1]).strip()
            continue
        low = line.lower()
        if "ipv4" in low and ":" in line:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                last4 = {"addr": m.group(1), "iface": iface, "plen": 24, "fam": 4, "pref": -1, "temp": False}
                rows.append(last4)
        elif "subnet mask" in low and last4:
            m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                last4["plen"] = bin(int(ipaddress.IPv4Address(m.group(1)))).count("1")
        else:
            for tok in v6_tokens(line):
                rows.append({"addr": tok, "iface": iface, "plen": 64, "fam": 6, "pref": -1,
                             "temp": "temporary" in low})
    return rows


def parse_ip_o(text):
    """Linux: ip -o addr"""
    rows = []
    for line in text.splitlines():
        p = line.split()
        if len(p) < 4 or p[2] not in ("inet", "inet6"):
            continue
        addr, _, plen = p[3].partition("/")
        m = re.search(r"preferred_lft\s+(\d+)sec", line)
        rows.append({"addr": strip_scope(addr), "iface": p[1], "plen": int(plen or 0),
                     "fam": 6 if p[2] == "inet6" else 4, "pref": int(m.group(1)) if m else -1,
                     "temp": "temporary" in p})
    return rows


def parse_ifconfig(text):
    """macOS / BSD: ifconfig"""
    rows, iface = [], ""
    for line in text.splitlines():
        if line and not line[0].isspace():
            iface = line.split(":")[0]
            continue
        p = line.split()
        if len(p) >= 4 and p[0] == "inet6":
            m = re.search(r"prefixlen\s+(\d+)", line)
            rows.append({"addr": strip_scope(p[1]), "iface": iface, "plen": int(m.group(1)) if m else 64,
                         "fam": 6, "pref": -1, "temp": "temporary" in p})
        elif len(p) >= 4 and p[0] == "inet":
            m = re.search(r"netmask\s+(0x[0-9a-fA-F]+)", line)
            plen = bin(int(m.group(1), 16)).count("1") if m else 24
            rows.append({"addr": p[1], "iface": iface, "plen": plen, "fam": 4, "pref": -1, "temp": False})
    return rows


def local_addresses():
    if platform.system() == "Windows":
        ps = ("Get-NetIPAddress | Select-Object IPAddress,InterfaceAlias,PrefixLength,AddressFamily,"
              "@{n='pref';e={[int][Math]::Min($_.PreferredLifetime.TotalSeconds,2147483647)}} "
              "| ConvertTo-Csv -NoTypeInformation")
        rows = parse_ps_csv(run(["powershell", "-NoProfile", "-Command", ps], 25))
        ipc = run(["ipconfig"], 15)
        if not rows:
            return parse_ipconfig(ipc)
        temp = set()
        for line in ipc.splitlines():
            if "temporary" in line.lower():
                temp.update(v6_tokens(line))
        for r in rows:
            r["temp"] = r["fam"] == 6 and r["addr"] in temp
        return rows
    rows = parse_ip_o(run(["ip", "-o", "addr"]))
    return rows or parse_ifconfig(run(["ifconfig"]))


def outbound(fam, target):
    """the source address the OS would use; a UDP connect() sends nothing"""
    try:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect((target, 53))
        a = s.getsockname()[0]
        s.close()
        return strip_scope(a)
    except OSError:
        return None


def fetch(url):
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.read().decode().strip()
    except Exception:
        return None


# ---- screen (same look as ipv7_inet_peer.py: ipconfig adapters, dotted leaders, firmware legend) ---------

W = 96
KV_COL = 33


def banner(title):
    print("#" * W)
    for t in ("IPv7_INET_CHECK", title):
        print(t.center(W))
    print("$" * W)


def adapter(name):
    print("\n%s:\n" % name)


def kv(label, value=""):
    dots = "".join("." if i >= len(label) and i % 2 == (KV_COL - 1) % 2 else " " for i in range(len(label), KV_COL))
    print("   %s%s : %s" % (label, dots, value))


def more(value):
    pad = " " * (3 + KV_COL + 3)
    for line in textwrap.wrap(value, W - len(pad)) or [""]:
        print(pad + line)


STATUS = False


def status(text):
    """an explanation, printed only with --status: the screen carries facts, not commentary"""
    if STATUS:
        lines = textwrap.wrap(text, W - (3 + KV_COL + 3))
        kv("Status", lines[0])
        for line in lines[1:]:
            more(line)


LEGEND = [
    ("(no arguments)", "report: adapters, carrier lines, overlay clash, reachability"),
    ("--online", "also ask ipify what the internet sees, v6 and v4"),
    ("--wan ADDR", "the WAN ipv4 your router shows: CGNAT and upstream NAT check"),
    ("--port N", "port used in the carrier lines, default 7171"),
    ("--overlay NET", "overlay block checked for clashes, default 172.16.0.0/12"),
    ("--status", "add the explanatory Status lines"),
    ("--selftest", "checks of the code itself, nothing touches the network"),
    ("--help", "this text"),
]


def help_lines():
    out = ["IPv7_INET_CHECK   can this machine be reached over IPv6", "", "ipv6_inet_check.py [options]", ""]
    out += ["   %-24s %s" % (k, d) for k, d in LEGEND]
    out += ["", "Without --online nothing leaves the machine.", ""]
    return out


V6_LABEL = {"GLOBAL": "IPv6 Address", "LINK-LOCAL": "Link-local IPv6 Address", "ULA-PRIVATE": "Unique-local IPv6 Address"}


def v6_label(r):
    if r.get("temp"):
        return "Temporary IPv6 Address"
    return V6_LABEL.get(r["cls"], "IPv6 Address")


def report(args):
    rows = local_addresses()
    banner("%s   %s" % (socket.gethostname(), platform.system()))
    o6 = outbound(socket.AF_INET6, "2001:4860:4860::8888")
    o4 = outbound(socket.AF_INET, "8.8.8.8")
    ov = ipaddress.ip_network(args.overlay)

    ifaces = []
    for r in rows:
        if r["iface"] not in ifaces:
            ifaces.append(r["iface"])
    glob, clash = [], 0
    for name in ifaces:
        mine = [r for r in rows if r["iface"] == name]
        shown = False
        for r in mine:
            if r["fam"] == 6:
                try:
                    r["cls"], r["usable"] = classify6(r["addr"])
                except ValueError:
                    continue
                if not shown:
                    adapter("Adapter " + (name or "?"))
                    shown = True
                kv(v6_label(r), "%s   %s%s" % (r["addr"], r["cls"],
                                               "  pref %ds" % r["pref"] if STATUS and 0 <= r["pref"] < 2147483647 else ""))
                if r["usable"]:
                    glob.append(r)
            elif not r["addr"].startswith("127."):
                try:
                    net = ipaddress.ip_interface("%s/%d" % (r["addr"], r["plen"])).network
                except ValueError:
                    continue
                if not shown:
                    adapter("Adapter " + (name or "?"))
                    shown = True
                hit = net.overlaps(ov)
                clash += hit
                kv("IPv4 Address", "%s/%d   %s%s" % (r["addr"], r["plen"], classify4(r["addr"]),
                                                       "   CLASH with %s" % args.overlay if hit else ""))

    adapter("Carrier adapter UDP6")
    if glob:
        for r in sorted(glob, key=lambda x: x["temp"]):
            kv("Temporary Endpoint" if r["temp"] else "Carrier Endpoint", "[%s]:%d" % (r["addr"], args.port))
        status("give out the stable Carrier Endpoint; a Temporary Endpoint changes about daily and an answer "
               "may leave from it, so run the receiver with --bind and the stable address")
        stable = [r for r in glob if not r["temp"]]
        if stable:
            kv("Receive With", "--receive %d --bind %s" % (args.port, stable[0]["addr"]))
    else:
        kv("Media State", "Media disconnected")
        kv("Reason", "no global ipv6 address on this machine")
    kv("Outbound IPv6", o6 or "none")
    kv("Outbound IPv4", o4 or "none")

    adapter("Overlay adapter %s" % args.overlay)
    kv("Overlay", "CLASH on %d local networks" % clash if clash else "clear")
    status("clear: no local network overlaps the overlay block. CLASH: a local network uses part of it, "
           "so addresses there are ambiguous")

    pub4 = pub6 = None
    adapter("Reachability summary")
    kv("Global IPv6 Address", "YES  %d" % len(glob) if glob else "NO")
    kv("IPv6 Route Out", "OK" if o6 and classify6(o6)[1] else "NO")
    kv("Overlay Clash", "YES  %d" % clash if clash else "no")
    if args.online:
        pub6 = fetch("https://api6.ipify.org")
        pub4 = fetch("https://api.ipify.org")
        kv("Internet Sees IPv6", pub6 or "nothing")
        kv("Internet Sees IPv4", pub4 or "nothing")
        if pub6:
            mine6 = {r["addr"] for r in rows if r["fam"] == 6}
            kv("IPv6 Is Direct", "yes" if pub6 in mine6 else "no, a different address")
            status("yes: the internet sees an address on this machine. no: a privacy address or a v6 NAT")
    if args.wan:
        try:
            wan = ipaddress.ip_address(args.wan)
            wc = classify4(args.wan)
            kv("Router WAN IPv4", "%s  %s" % (args.wan, wc))
            same = None
            for r in rows:
                if r["fam"] == 4 and not r["addr"].startswith("127."):
                    try:
                        net = ipaddress.ip_interface("%s/%d" % (r["addr"], r["plen"])).network
                    except ValueError:
                        continue
                    if wan in net:
                        same = (r["addr"], net)
            if same:
                kv("Not A WAN Address", "%s is in %s, the subnet of this PC %s" % (args.wan, same[1], same[0]))
                status("a router cannot have its WAN and LAN in one subnet, so this is another device on your LAN "
                       "or the router's LAN side. Read the WAN line again")
            elif wc == "CGNAT":
                kv("CGNAT", "YES")
                status("the ISP shares one public v4 between customers: a forwarded v4 port will not reach you")
            elif wc == "PRIVATE":
                kv("Upstream NAT", "the WAN address is private")
                status("whatever hands it out does NAT, an ISP modem in router mode counts. That is not proof of a "
                       "second router of yours: forward the port on every NAT in the chain, or use ipv6")
            elif pub4 and pub4 != args.wan:
                kv("CGNAT", "probably, the internet sees %s, not %s" % (pub4, args.wan))
            else:
                kv("CGNAT", "no sign of it")
        except ValueError:
            kv("Router WAN IPv4", "%s  not an ipv4 address" % args.wan)
    else:
        kv("CGNAT", "?")
        status("add --wan with the WAN ipv4 your router shows, and --online")
    return 0


# ---- selftest ------------------------------------------------------------------------------------

def selftest():
    n = bad = 0

    def check(name, ok):
        nonlocal n, bad
        n += 1
        bad += 0 if ok else 1
        print("%-4s %s" % ("PASS" if ok else "FAIL", name))

    for a, want, usable in [
        ("2345:6789:abcd:ef01::1", "GLOBAL", True), ("2001:4860:4860::8888", "GLOBAL", True),
        ("fe80::1234:5678:9abc:def0%27", "LINK-LOCAL", False), ("fd00::1", "ULA-PRIVATE", False),
        ("::1", "LOOPBACK", False), ("2001:db8::1", "DOCUMENTATION", False), ("2002:c000:204::1", "6TO4", True),
        ("2001:0:4137:9e76::1", "TEREDO", True), ("ff02::1", "MULTICAST", False), ("::ffff:192.0.2.1", "V4-MAPPED", False),
    ]:
        check("classify6 %-28s %s" % (a, want), classify6(a) == (want, usable))
    for a, want in [("192.168.1.100", "PRIVATE"), ("172.22.96.1", "PRIVATE"), ("100.64.1.2", "CGNAT"),
                    ("100.127.255.255", "CGNAT"), ("100.128.0.1", "PUBLIC"), ("8.8.8.8", "PUBLIC"),
                    ("169.254.3.4", "LINK-LOCAL"), ("127.0.0.1", "LOOPBACK")]:
        check("classify4 %-28s %s" % (a, want), classify4(a) == want)

    ps = ('"IPAddress","InterfaceAlias","PrefixLength","AddressFamily","pref"\n'
          '"2345:6789:abcd:ef01:1111:2222:3333:4444","Ethernet 2","64","IPv6","86400"\n'
          '"fe80::1234:5678:9abc:def0%27","Ethernet 2","64","IPv6","2147483647"\n'
          '"172.22.96.1","vEthernet (Default Switch)","20","IPv4","2147483647"\n')
    r = parse_ps_csv(ps)
    check("parse_ps_csv rows", len(r) == 3 and r[0]["fam"] == 6 and r[2]["plen"] == 20 and r[1]["addr"] == "fe80::1234:5678:9abc:def0")

    ipc = ("Ethernet adapter vEthernet (Default Switch):\n\n   Link-local IPv6 Address . . . . . : fe80::2222:3333:4444:5555%29\n"
           "   IPv4 Address. . . . . . . . . . . : 172.22.96.1\n   Subnet Mask . . . . . . . . . . . : 255.255.240.0\n\n"
           "Ethernet adapter Ethernet 2:\n\n   IPv6 Address. . . . . . . . . . . : 2345:6789:abcd:ef01::100\n"
           "   Temporary IPv6 Address. . . . . . : 2345:6789:abcd:ef01:aaaa:bbbb:cccc:dddd\n"
           "   IPv4 Address. . . . . . . . . . . : 192.168.1.100\n   Subnet Mask . . . . . . . . . . . : 255.255.255.0\n")
    r = parse_ipconfig(ipc)
    v4 = [x for x in r if x["fam"] == 4]
    check("parse_ipconfig v4 + mask", len(v4) == 2 and v4[0]["plen"] == 20 and v4[1]["plen"] == 24 and v4[0]["iface"] == "vEthernet (Default Switch)")
    check("parse_ipconfig temporary flag", [x["temp"] for x in r if x["fam"] == 6 and x["addr"].startswith("2345")] == [False, True])

    ipo = ("2: eth0    inet 192.168.1.9/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever preferred_lft forever\n"
           "2: eth0    inet6 2345:6789:abcd:ef01:1:2:3:4/64 scope global temporary dynamic \\       valid_lft 86400sec preferred_lft 3600sec\n")
    r = parse_ip_o(ipo)
    check("parse_ip_o", len(r) == 2 and r[1]["temp"] and r[1]["pref"] == 3600 and r[0]["plen"] == 24)

    ifc = ("en0: flags=8863<UP> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n"
           "\tinet6 2345:1::5 prefixlen 64 autoconf temporary\n\tinet 192.168.1.5 netmask 0xffffff00 broadcast 192.168.1.255\n")
    r = parse_ifconfig(ifc)
    check("parse_ifconfig", len(r) == 3 and r[1]["temp"] and r[2]["plen"] == 24)

    ov = ipaddress.ip_network(OVERLAY)
    check("overlay overlaps 172.22.96.0/20", ipaddress.ip_network("172.22.96.0/20").overlaps(ov))
    check("overlay clear of 192.168.1.0/24", not ipaddress.ip_network("192.168.1.0/24").overlaps(ov))

    hl = help_lines()
    check("help fits the screen, has no border, lists every option",
          all(len(x) <= W for x in hl) and not any(x.startswith(("+", "|")) for x in hl)
          and all(o in " ".join(hl) for o in ("--online", "--wan", "--port", "--status", "--selftest", "--help")))
    check("no colour codes anywhere in the source", chr(27) not in open(__file__, encoding="utf-8").read())
    import contextlib
    cap = io.StringIO()
    with contextlib.redirect_stdout(cap):
        kv("IPv4 Address", "x")
        kv("Subnet Mask", "x")
    a, b2 = cap.getvalue().splitlines()
    check("ipconfig column alignment", a.index(" : ") == b2.index(" : ") == 3 + KV_COL and a.startswith("   IPv4 Address. . ."))
    check("v6 labels: temporary wins", v6_label({"temp": True, "cls": "GLOBAL"}) == "Temporary IPv6 Address"
          and v6_label({"temp": False, "cls": "LINK-LOCAL"}) == "Link-local IPv6 Address")

    print("\n%d checks, %d failed" % (n, bad))
    return 1 if bad else 0


def main():
    ap = argparse.ArgumentParser(description="IPv6 reachability and overlay clash check for IPv7", add_help=False)
    ap.add_argument("-h", "--help", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--online", action="store_true", help="ask ipify what the internet sees")
    ap.add_argument("--wan", help="the WAN ipv4 your router shows")
    ap.add_argument("--port", type=int, default=7171)
    ap.add_argument("--overlay", default=OVERLAY)
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()
    global STATUS
    STATUS = args.status
    if args.help:
        for line in help_lines():
            print(line)
        return 0
    if args.selftest:
        return selftest()
    return report(args)


if __name__ == "__main__":
    sys.exit(main())
