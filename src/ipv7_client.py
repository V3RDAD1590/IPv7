#!/usr/bin/env python3
"""ipv7_client.py: the IPv7 client, and ONLY the client -- the build to compile and hand to
someone you do not want able to host a network, because this file cannot do it: there is no
--host flag anywhere in its own argument parser, and nothing it imports
(`ipv7_client_core`, `ipv7_bind`, `ipv7_menu`, `ipv7_inet_users`, `ipv7_path`, `ipv7_policy`,
`ipv7_core`, `ipv7_tui`) knows how to read or write a host's identity key, manage an invite
book, or run the host admin console. `ipv7_host.py` and `ipv7_host_menu.py` -- the only two
files in this project with that code in them -- are never imported here, directly or
indirectly, so a PyInstaller build of this file alone carries none of it: not a disabled copy,
an absent one.

    python ipv7_client.py                                                     a password prompt, then the login screen
    python ipv7_client.py --connect HOST [PORT]                              skips asking for the host
    python ipv7_client.py --connect HOST PORT --invite IPv7.key --host-key FINGERPRINT   skips the login screen too

No flags are required at all: double-clicking a build of this file (no terminal, no typed
flags) drops straight into the password prompt and then the login screen, asking for a host
address and an invite file only if one isn't already on record in `IPv7.conf`. There is no
router-look IPv7 SETUP menu here any more (the user's own call, 2026-10-20): this build picks
UDP only and asks nothing about Ethernet, Paths, EtherType or link address -- those still work
if hand-edited into `IPv7.conf`, there is just no screen for them here.

A password gate (`check_password`) runs before anything else; what is typed echoes (the user's
own call). This is a front-door lock, not a cryptographic one: it stops someone from poking at
the program at all without the word first, but anyone holding the compiled exe can, in
principle, recover the stored hash and brute-force a short password offline, or simply patch the
check out of the binary. It does not replace, and is not meant to replace, the real protection
in this project, which is the invite ticket and the ML-KEM/RSA/OpenPGP bind that follows it.

After the first successful login, `IPv7.session` (next to `IPv7.key`) lets every later run come
back on the same invite by resumption (spec section 7) -- an invite itself works exactly once,
so without that file a second run could only fail. Ctrl-C anywhere asks before leaving, and
nothing reaches the screen as a traceback: an unexpected error is one readable line, held until
Enter so a double-clicked window does not vanish with it.

For hosting a network -- and for this project's own development and testing, where one machine
needs to play either side -- see `ipv7_connect.py` instead. That file imports `ipv7_host.py` too,
so a build of IT can still host; this file is the one to compile when that must not be possible.

This is an unaudited prototype: it should not protect anyone whose safety depends on it.
"""
import argparse
import hashlib
import sys

from ipv7_client_core import banner_connect_cli
from ipv7_core import DEFAULT_PORT
from ipv7_tui import EXIT_LINE, confirm_exit, report_crash, console_icon, install_terminal_profile, relaunch_in_conhost, close_handoff_window

# A sha256 of the password, not the password itself, so a casual look at this file (or a string
# dump of the compiled exe) doesn't hand it over in plain text. This is still not real security
# (see the module docstring): a short numeric password's hash is not hard to brute-force once
# it's been pulled out of the binary, and the check itself could be patched out entirely by
# someone willing to disassemble the exe. Change this by hashing a new password the same way:
#   python3 -c "import hashlib; print(hashlib.sha256(b'NEWPASSWORD').hexdigest())"
PASSWORD_SHA256 = "b7624cb694ed8c692cd8cc4a218056f3cee7b4f085ebae045976f9e959178eee"


def check_password(prompt="Password: ", attempts=3, reader=None, asker=None):
    """-> True once the right password is entered (prints 'Password Accepted!' itself), False
    after `attempts` wrong tries, on EOF, or when Ctrl-C is answered with 'yes, exit'. `reader`
    is swapped out in the self-test; a real run uses plain `input()`, so what's typed echoes to
    the screen (the user's own design choice -- `getpass.getpass()` is the hidden-input
    alternative, if that's ever wanted back). Ctrl-C asks `asker` (confirm_exit) first: 'no'
    just asks for the password again, without using up a try."""
    reader = reader or input
    asker = asker or confirm_exit
    tries = 0
    while tries < attempts:
        try:
            entered = reader(prompt)
        except EOFError:
            return False
        except KeyboardInterrupt:
            if asker():
                return False
            print()
            continue
        if hashlib.sha256(entered.encode("utf-8", "replace")).hexdigest() == PASSWORD_SHA256:
            print("Password Accepted!")
            return True
        tries += 1
        print("Incorrect.")
    return False


def build_argparser():
    ap = argparse.ArgumentParser(description="IPv7 client only -- this build cannot host a network.")
    ap.add_argument("--connect")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--invite")
    ap.add_argument("--host-key")
    return ap


# ---------------------------------------------------------------- selftest
def selftest():
    results = []

    def check(name, ok):
        results.append(bool(ok))
        print("%s%s %s" % ("*_" if ok else "-_", name, "" if ok else "FAILED"))

    # The real password never appears in this file -- only its hash does (the file is public).
    # The checks below run against a throwaway word under a patched hash.
    import re as _re
    import unittest.mock as _mock
    check("PASSWORD_SHA256 is a sha256 hex digest, nothing else", bool(_re.fullmatch(r"[0-9a-f]{64}", PASSWORD_SHA256)))
    word = "test-word-only"
    patched = _mock.patch.object(sys.modules[__name__], "PASSWORD_SHA256", hashlib.sha256(word.encode()).hexdigest())
    patched.start()

    tries = iter(["wrong", word])
    check("check_password accepts the password after a wrong try, printing acceptance",
          check_password(reader=lambda _p: next(tries)) is True)

    always_wrong = iter(["a", "b", "c", "d", "e"])
    check("check_password gives up after the attempt limit instead of asking forever",
          check_password(reader=lambda _p: next(always_wrong), attempts=3) is False)

    def eof_reader(_p):
        raise EOFError
    check("check_password treats EOF (Ctrl-D) as a refusal, not a crash", check_password(reader=eof_reader) is False)

    def kbint_reader(_p):
        raise KeyboardInterrupt
    check("Ctrl-C at the password prompt asks; 'yes' exits (False), no crash",
          check_password(reader=kbint_reader, asker=lambda: True) is False)
    seq = iter([kbint_reader, lambda _p: word])
    check("Ctrl-C then 'no' simply asks for the password again, without spending a try",
          check_password(reader=lambda p: next(seq)(p), asker=lambda: False, attempts=1) is True)
    patched.stop()

    ap = build_argparser()
    args = ap.parse_args([])
    check("no flags are required at all: --connect is optional", args.connect is None)
    check("this build's own parser has no --host flag (only --host-key, a different one)",
          not any(a.option_strings == ["--host"] for a in ap._actions)
          and any(a.option_strings == ["--host-key"] for a in ap._actions))

    n = sum(results)
    print("%s%d of %d checks passed" % ("*_" if n == len(results) else "-_", n, len(results)))
    return 0 if n == len(results) else 1


def _main():
    if relaunch_in_conhost():                    # a Windows Terminal tab: start again under conhost.exe, let this tab close
        return 0
    console_icon("IPv7 Client")
    close_handoff_window()                       # ... and close the Terminal window the first copy was handed to                  # this program's own icon on the console window (Windows)
    install_terminal_profile("IPv7 Client")      # and its own Windows Terminal profile (one small JSON, idempotent)
    print("iPv7.exe")
    if not check_password():
        print(EXIT_LINE)
        return 1
    ap = build_argparser()
    args = ap.parse_args()
    args.host = args.connect
    return banner_connect_cli(args)


def main():
    """Nothing gets out of here as a traceback: Ctrl-C is asked about wherever it lands (and
    answered 'yes' it ends here, cleanly), and anything unexpected becomes one readable line
    plus `......Program exits!`, held on screen so a double-clicked build can be read."""
    if "--selftest" in sys.argv:
        return selftest()
    try:
        return _main()
    except KeyboardInterrupt:
        print(EXIT_LINE)
        return 1
    except Exception as e:                          # noqa: BLE001 -- the last line of defence
        return report_crash(e)


if __name__ == "__main__":
    sys.exit(main())
