# Grumpy Guard – Merkmal-Datenbank

Die Merkmal-Datenbank von Grumpy Guard, einem Netz- und Autostart-Wächter für Windows.
Danach beurteilt das Programm im Reiter „Auffällig“ Programme und Verbindungen.

Grumpy Guard holt sie einmal am Tag (abschaltbar) und übernimmt einen Stand nur, wenn

- die Signatur in `merkmale.json.signatur` gültig ist (Ed25519, Schlüssel unten) und
- seine Version höher ist als die, die das Programm schon hat.

Wer die Dateien hier oder unterwegs verändert, erreicht damit nichts: Ohne den privaten
Schlüssel des Herausgebers entsteht kein gültiger Stand.

## Dateien

| Datei | Inhalt |
|---|---|
| `merkmale.json` | die Datenbank, Format `gg-merkmale-1` |
| `merkmale.json.signatur` | Version, Größe, SHA-256 und Ed25519-Signatur dieser Fassung |

## Inhalt

- `prozesse`: Merkmale von Programmen – Windows-Namen am falschen Ort, Tippfehler-Namen,
  Windows-Werkzeuge mit Internetzugang, verdächtige Befehlszeilen, Prüfsummen.
- `ziele`: Adressen (Domains, IP-Adressen, Netze), die zu Spähprogrammen gehören.
- `browser`, `regelmaessig_ok`, `abfluss_ok`: Programme, bei denen regelmäßige
  Verbindungen oder viel Upload normal sind.

Ein Treffer ist ein Hinweis, kein Urteil. Grumpy Guard sperrt deswegen nichts von selbst.

## Was beim Abruf übertragen wird

Abgerufen werden nur diese zwei Dateien: zuerst `merkmale.json.signatur`, und nur bei
höherer Version auch `merkmale.json`. GitHub sieht dabei, wie bei jedem Abruf,
IP-Adresse und Uhrzeit, dazu die Programmversion (User-Agent `GrumpyGuard/<Version>`).
Über den Rechner, seine Programme oder Befunde wird nichts gesendet.

## Signatur selbst prüfen

Öffentlicher Schlüssel (Ed25519, Base64): `tvFT9XBDAvEWJIgKkJbNhtDodPPoEaRyfW5aY1QUFQA=`

Signiert sind alle Felder der Signaturdatei außer `sig`, als JSON mit sortierten
Schlüsseln und ohne Leerraum. Mit Python und `cryptography`:

```python
import base64, hashlib, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SCHLUESSEL = "tvFT9XBDAvEWJIgKkJbNhtDodPPoEaRyfW5aY1QUFQA="
m = json.load(open("merkmale.json.signatur", encoding="utf-8"))
daten = open("merkmale.json", "rb").read()
signiert = json.dumps({k: v for k, v in m.items() if k != "sig"}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False).encode("utf-8")
Ed25519PublicKey.from_public_bytes(base64.b64decode(SCHLUESSEL)).verify(
    base64.b64decode(m["sig"]), signiert)          # wirft InvalidSignature, wenn nicht
assert m["art"] == "merkmale" and m["datei"] == "merkmale.json"
assert len(daten) == m["groesse"] and hashlib.sha256(daten).hexdigest() == m["sha256"]
assert json.loads(daten)["version"] == m["version"]
print("gültig, Version", m["version"])
```

## English

The feature database of Grumpy Guard, a network and autostart guard for Windows. The
program fetches it once a day (can be switched off) and accepts a version only with a
valid Ed25519 signature (public key above) and a higher version number than the one it
already has. Only these two files are requested; GitHub sees the IP address, the time
and the program version, nothing else is sent. A match is a hint, not a verdict:
Grumpy Guard never blocks anything on its own because of it.
