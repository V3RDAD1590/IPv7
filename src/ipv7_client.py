#!/usr/bin/env python3
import argparse
import hashlib
import sys

from ipv7_client_core import banner_connect_cli
from ipv7_core import DEFAULT_PORT
from ipv7_tui import EXIT_LINE, confirm_exit, report_crash, console_icon, install_terminal_profile, relaunch_in_conhost, close_handoff_window

PASSWORD_SHA256 = "b7624cb694ed8c692cd8cc4a218056f3cee7b4f085ebae045976f9e959178eee"


def check_password(prompt="Password: ", attempts=3, reader=None, asker=None):
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
