#!/usr/bin/env python3
"""ipv7_policy.py: the one place "settings -> ipv7_path.Policy" is worked out, shared by the
client (`ipv7_client_core.ClientConn`) and the host (`ipv7_host.HostState`) so the two never
work this out differently.

Deliberately its own tiny file, separate from `ipv7_host_menu.py` (the host operator's admin
console, which re-exports this for the host's own convenience): a strict client-only build needs
this one function but must never pull in the admin console, `FakeHost`, or any other host-only
code along with it.
"""
import ipv7_menu as M


def policy_from_settings(settings, find_devices=None):
    """-> an ipv7_path.Policy. Imports ipv7_path/ipv7_ether lazily, so nothing here needs Npcap
    unless Ethernet is actually on."""
    import ipv7_path as P
    find_devices = find_devices or M.find_devices
    if settings is None or settings.paths == 0:
        return P.Policy(allow_ethernet=False)
    import ipv7_ether as E
    try:
        dev = next((d for d in find_devices()[0] if d[0] == settings.device), None)
        policy_str = (settings.custom_link if settings.link == 2 else
                      ("real" if settings.link == 1 else "random"))
        link = E.link_address(policy_str, dev[2] if dev else None)
        return P.Policy(allow_ethernet=True, ethertype=settings.ethertype_value(), my_link=link)
    except Exception:
        return P.Policy(allow_ethernet=False)


# ---------------------------------------------------------------- selftest
def selftest():
    import ipv7_path as P
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % ("*_" if ok else "-_", name, "" if ok else "FAILED"))

    check("None settings refuse Ethernet", policy_from_settings(None).allow_ethernet is False)
    check("paths == 0 refuses Ethernet", policy_from_settings(M.Settings()).allow_ethernet is False)
    s = M.Settings()
    s.paths = 1
    s.link = 1                                    # "real adapter address", needs a real MAC we won't give it
    s.device = "no-such-device"
    pol = policy_from_settings(s, find_devices=lambda: ([], False))
    check("Ethernet on but no matching device/Npcap falls back to refused, not a crash",
          pol.allow_ethernet is False)
    s2 = M.Settings()
    s2.paths = 1
    s2.device = "no-such-device"                  # "random" link (the default) never needs the device's MAC
    pol2 = policy_from_settings(s2, find_devices=lambda: ([], False))
    check("Ethernet on with a random link address succeeds even with no matching device",
          pol2.allow_ethernet is True)

    n = sum(results)
    print("%s%d of %d checks passed" % ("*_" if n == len(results) else "-_", n, len(results)))
    return 0 if n == len(results) else 1


def main():
    import sys
    return selftest() if "--selftest" in sys.argv else (print(__doc__) or 0)


if __name__ == "__main__":
    import sys
    sys.exit(main())
