# IPv7
Experimental UDP overlay tunnel using [TP/IX] (IP version 7) addressing.

This is for me and my friends, because my art has became a radical talking point.
Invite only for now.

## Host not included for reasons stated above.
<img width="1056" height="613" alt="image" src="https://github.com/user-attachments/assets/7fe78bd5-41a4-4bcb-bccc-6a333996ab0d" />
<img width="1060" height="604" alt="image" src="https://github.com/user-attachments/assets/e1d700cd-fb04-465b-8182-ca71063a0f75" />



## Peering methods
UDP://IPV6
I2P://127.0.0.1:4447 (soon)

## Build
```
pip install -r requirements.txt
build.bat
```
`dist\IPv7Client.exe` is the whole client. Needs Python 3.11+.

## Run
Put `IPv7.key` (the invite you were given) next to the exe and double-click it. Password, then the login screen.
It opens in the classic console with its own icon; the Terminal window that flashes first closes itself.

Once in: `Command: Help` lists what there is. The sites your invite opens are at
```
http://localhost:8888/            the index
http://localhost:8888/IPv7:NAME/  a site, NAME exactly as given (case matters)
```

## Files next to the exe
| File | What | Share? |
| --- | --- | --- |
| `IPv7.key` | your invite: the host's fingerprint, the sites it opens, a one-use ticket | no |
| `IPv7.session` | written after the first login; lets you come back without a new invite | no |
| `IPv7.conf` | the host address you typed, so it is not asked again | no |

An invite works once. Lose both files and you need a new invite from the host.

## notice
Source-available, non-commercial use. See LICENSE.
