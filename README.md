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
- `empfehlungen` (recommendations): for startup entries and scheduled tasks
  (`autostart`), Windows and third-party services (`dienste`) and whether a program
  may go online (`netz`), per level `moderat` / `streng` / `anonym` (recommended /
  strict / anonymous). Values: `allow`, `block`, `neutral` (matter of taste) and, for
  the network, `frag` (depends on the case – Grumpy Guard asks). An optional `pfad`
  limits an entry to certain folders, so a copied name does not count. Each entry
  carries its text in all 13 languages of the program; `begriffe` translates the
  categories.

A match is a hint, not a verdict. Grumpy Guard never blocks anything on its own
because of it. Recommendations are suggestions: the user decides, and in the AI modes
known programs no longer need to be sent to an AI.

## Sources

- Entries `stalkerware-*` (servers and vendor websites of stalkerware): from
  [Stalkerware Indicators](https://github.com/AssoEchap/stalkerware-indicators) by
  Echap, licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
  Changed: only server domains/IPs and websites taken over, subdomains of listed
  domains merged, shared or legitimate hosts removed, IP addresses only if a domain of
  the same program still pointed to them. That list covers phone stalkerware; when a
  browser opens such an address, it is usually someone using the customer account, so
  Grumpy Guard reports it one level lower.
- Entries `spaeh-*` (Windows monitoring software): file and folder names from the
  sources named in each entry (`quelle`), e.g. Microsoft Security Intelligence and the
  vendors' own documentation.
- Recommendations (`empfehlungen`): compiled by the publisher of Grumpy Guard.

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
kein Urteil: Grumpy Guard sperrt deswegen nichts von selbst. Dazu kommen feste
Empfehlungen für Autostart-Einträge, Dienste und den Netzzugang von Programmen
(`empfehlungen`), je Stufe und in allen 13 Sprachen des Programms. Was dort steht,
muss keiner KI mehr vorgelegt werden.

Quellen: Die Einträge `stalkerware-*` stammen aus
[Stalkerware Indicators](https://github.com/AssoEchap/stalkerware-indicators) von Echap
(CC BY 4.0), verändert wie oben beschrieben. Die Einträge `spaeh-*` nennen ihre Quelle
jeweils im Feld `quelle`.
