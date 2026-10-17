# Grumpy Guard – indicator database

The indicator database of Grumpy Guard, a network and autostart guard for Windows.
The program uses it in its “Suspicious” tab to judge programs and connections.

Grumpy Guard fetches it once a day (can be switched off) and only accepts a version if

- the signature in `indicators.json.sig` is valid (Ed25519, key below) and
- its version is higher than the one the program already has.

Changing the files here or on the way achieves nothing: without the publisher's
private key there is no valid version.

## Files

| File | Content |
|---|---|
| `indicators.json` | the database, format `gg-merkmale-1` (field names in German) |
| `indicators.json.sig` | version, size, SHA-256 and Ed25519 signature of this file |

## Content

- `prozesse` (programs): Windows names in the wrong place, typo names, Windows tools
  with internet access, suspicious command lines, checksums.
- `ziele` (destinations): domains, IP addresses and networks that belong to spyware.
- `browser`, `regelmaessig_ok`, `abfluss_ok`: programs for which regular connections
  or a lot of upload are normal.

A match is a hint, not a verdict. Grumpy Guard never blocks anything on its own
because of it.

## What is sent when fetching

Only these two files are requested: first `indicators.json.sig`, and only for a
higher version also `indicators.json`. Like with any request, GitHub sees the IP
address and the time, plus the program version (user agent `GrumpyGuard/<version>`).
Nothing about the computer, its programs or findings is sent.

## Check the signature yourself

Public key (Ed25519, Base64): `tvFT9XBDAvEWJIgKkJbNhtDodPPoEaRyfW5aY1QUFQA=`

Signed are all fields of the signature file except `sig`, as JSON with sorted keys
and without whitespace. With Python and `cryptography`:

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

KEY = "tvFT9XBDAvEWJIgKkJbNhtDodPPoEaRyfW5aY1QUFQA="
m = json.load(open("indicators.json.sig", encoding="utf-8"))
data = open("indicators.json", "rb").read()
signed = json.dumps({k: v for k, v in m.items() if k != "sig"}, sort_keys=True,
                    separators=(",", ":"), ensure_ascii=False).encode("utf-8")
Ed25519PublicKey.from_public_bytes(base64.b64decode(KEY)).verify(
    base64.b64decode(m["sig"]), signed)            # raises InvalidSignature if not
assert m["art"] == "merkmale" and m["datei"] == "indicators.json"
assert len(data) == m["groesse"] and hashlib.sha256(data).hexdigest() == m["sha256"]
assert json.loads(data)["version"] == m["version"]
print("valid, version", m["version"])
```

## Deutsch

Die Merkmal-Datenbank von Grumpy Guard, einem Netz- und Autostart-Wächter für
Windows. Das Programm holt sie einmal am Tag (abschaltbar) und übernimmt einen Stand
nur mit gültiger Ed25519-Signatur (Schlüssel oben) und höherer Version als der, die es
schon hat. Abgerufen werden nur diese zwei Dateien. GitHub sieht dabei IP-Adresse,
Uhrzeit und Programmversion, sonst wird nichts gesendet. Ein Treffer ist ein Hinweis,
kein Urteil: Grumpy Guard sperrt deswegen nichts von selbst.
