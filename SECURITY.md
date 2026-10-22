# Security

IPv7 is an experimental, unaudited prototype. Do not rely on it for anything whose safety
depends on it.

What protects a session is the bind: ML-KEM-1024 plus a fresh RSA-4096 key per session,
a host signed with its OpenPGP key and pinned by fingerprint, invite tickets that work once,
AES-GCM frames. The password prompt at startup is a front-door lock on the program, not a
cryptographic one: anyone holding the exe can recover the hash and brute-force a short
password offline. Change `PASSWORD_SHA256` in `src/ipv7_client.py` before you build for others.

The local gateway on 127.0.0.1:8888 answers only to its own name, refuses requests made by
pages on other origins, and serves only GET and HEAD for names the host lists for your invite.

Found something? Tell the maintainer privately before telling anyone else.
