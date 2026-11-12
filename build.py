#!/usr/bin/env python3
"""Baut aus dem Ordner inhalt/ die fertige, verschlüsselte Webseite in docs/.

Aufruf:
    python3 build.py             Seite bauen und QR-Code erzeugen
    python3 build.py --vorschau  zusätzlich lokal im Browser öffnen

Was passiert:
- liest inhalt/brief.txt, inhalt/fragen.txt, inhalt/schluss.txt
- verkleinert die Fotos aus inhalt/fotos/ und entfernt alle Metadaten (GPS!)
- verschlüsselt Texte und Fotos (AES-GCM) -> docs/daten.bin, docs/fotos/*.bin
- schreibt qr-code.png mit dem Link samt Schlüssel

Der Schlüssel liegt in inhalt/schluessel.txt und steht im Link hinter dem "#".
Er wird nie an den Server geschickt und darf nicht auf GitHub landen
(inhalt/ und qr-code.png stehen deshalb in .gitignore).
"""
import hashlib
import hmac
import json
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("FEHLER: Das Python-Paket 'cryptography' fehlt. Installation: python3 -m pip install cryptography")

WURZEL = Path(__file__).resolve().parent
INHALT = WURZEL / "inhalt"
FOTOS = INHALT / "fotos"
ZIEL = WURZEL / "docs"
ZIEL_FOTOS = ZIEL / "fotos"
SCHLUESSEL_DATEI = INHALT / "schluessel.txt"
ADRESSE_DATEI = INHALT / "adresse.txt"
QR_DATEI = WURZEL / "qr-code.png"
MAX_KANTE = 1600  # längste Bildkante in Pixeln
VORSCHAU_PORT = 8000


def abbruch(meldung):
    sys.exit(f"FEHLER: {meldung}")


def normalisiere(text):
    """Muss exakt zu normalisiere() in docs/quiz.js passen."""
    text = unicodedata.normalize("NFC", text).lower()
    for von, nach in (("ä", "ae"), ("ö", "oe"), ("ü", "ue"), ("ß", "ss")):
        text = text.replace(von, nach)
    text = unicodedata.normalize("NFD", text)
    return re.sub(r"[^a-z0-9]", "", text)


# ---- Inhalte lesen ---------------------------------------------------------
def lies(datei):
    pfad = INHALT / datei
    if not pfad.is_file():
        abbruch(f"{pfad} fehlt.")
    return pfad.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def titel_und_text(datei):
    """Erste Zeile = Überschrift, der Rest = Text."""
    zeilen = lies(datei).strip().split("\n")
    titel = zeilen[0].strip()
    text = "\n".join(zeilen[1:]).strip()
    if not titel:
        abbruch(f"{datei}: Die erste Zeile (Überschrift) ist leer.")
    return titel, text


def lies_fragen():
    pflicht = ("foto", "frage", "antwort")
    erlaubt = pflicht + ("antwortfoto",)
    fragen = []
    for block in re.split(r"\n\s*\n", lies("fragen.txt")):
        felder = {}
        for zeile in block.split("\n"):
            zeile = zeile.strip()
            if not zeile or zeile.startswith("#"):
                continue
            if ":" not in zeile:
                abbruch(f"fragen.txt: Zeile ohne 'Feld:' am Anfang: {zeile!r}")
            feld, wert = zeile.split(":", 1)
            feld = feld.strip().lower()
            if feld not in erlaubt:
                abbruch(f"fragen.txt: Unbekanntes Feld {feld!r} (erlaubt: Foto, Frage, Antwort, Antwortfoto).")
            felder[feld] = wert.strip()
        if not felder:
            continue
        nr = len(fragen) + 1
        for feld in pflicht:
            if not felder.get(feld):
                abbruch(f"fragen.txt: Bei Frage {nr} fehlt das Feld '{feld.capitalize()}'.")
        antworten = [a.strip() for a in felder["antwort"].split("|") if a.strip()]
        for antwort in antworten:
            if not normalisiere(antwort):
                abbruch(f"fragen.txt: Frage {nr}: Antwort {antwort!r} enthält keine Buchstaben oder Ziffern.")
        for feld in ("foto", "antwortfoto"):
            if felder.get(feld) and not (FOTOS / felder[feld]).is_file():
                abbruch(f"Frage {nr}: {feld.capitalize()} {felder[feld]!r} liegt nicht in {FOTOS}.")
        fragen.append({
            "foto": felder["foto"],
            "frage": felder["frage"],
            "antworten": antworten,
            "antwortfoto": felder.get("antwortfoto") or None,
        })
    if not fragen:
        abbruch("fragen.txt enthält keine Fragen.")
    return fragen


# ---- Schlüssel und Verschlüsselung -----------------------------------------
def lies_schluessel():
    """Der Schlüssel wird einmal erzeugt und bleibt dann gleich,
    damit ein ausgedruckter QR-Code nach jedem neuen Build weiter funktioniert."""
    if SCHLUESSEL_DATEI.is_file():
        text = SCHLUESSEL_DATEI.read_text().strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", text):
            abbruch(f"{SCHLUESSEL_DATEI} ist beschädigt (erwartet: 32 Hex-Zeichen).")
        return text
    text = secrets.token_hex(16)
    SCHLUESSEL_DATEI.write_text(text + "\n")
    print(f"Neuer Schlüssel erzeugt: {SCHLUESSEL_DATEI}")
    return text


def verschluessele(schluessel, klartext):
    """AES-128-GCM. Ausgabe: 12 Byte Nonce + Chiffrat.
    Die Nonce wird aus dem Inhalt abgeleitet: gleicher Inhalt -> gleiche Datei,
    also keine unnötigen Änderungen im Git, und nie dieselbe Nonce für zwei Inhalte."""
    nonce = hmac.new(schluessel, b"nonce:" + klartext, hashlib.sha256).digest()[:12]
    return nonce + AESGCM(schluessel).encrypt(nonce, klartext, None)


def verarbeite_foto(schluessel, name, arbeitsordner):
    """Verkleinert das Foto, dreht es richtig herum, entfernt alle Metadaten
    und legt es verschlüsselt in docs/fotos/ ab."""
    quelle = FOTOS / name
    klar = Path(arbeitsordner) / "foto.jpg"
    befehl = [
        "magick", f"{quelle}[0]",
        "-auto-orient",
        "-resize", f"{MAX_KANTE}x{MAX_KANTE}>",
        "-strip",
        "-quality", "82",
        str(klar),
    ]
    ergebnis = subprocess.run(befehl, capture_output=True, text=True)
    if ergebnis.returncode != 0 or not klar.is_file():
        abbruch(f"Foto {name!r} konnte nicht verarbeitet werden:\n{ergebnis.stderr.strip()}")
    daten = klar.read_bytes()
    klar.unlink()
    if b"Exif" in daten:
        abbruch(f"Foto {name!r}: Metadaten konnten nicht entfernt werden.")
    # Dateiname verrät weder Reihenfolge noch Inhalt.
    ziel_name = hmac.new(schluessel, b"name:" + daten, hashlib.sha256).hexdigest()[:16] + ".bin"
    (ZIEL_FOTOS / ziel_name).write_bytes(verschluessele(schluessel, daten))
    return f"fotos/{ziel_name}"


# ---- Link und QR-Code ------------------------------------------------------
def lies_adresse():
    if not ADRESSE_DATEI.is_file():
        abbruch(f"{ADRESSE_DATEI} fehlt. Dort steht die Adresse der Seite, z. B. https://abelhecker.github.io/quiz/")
    adresse = ADRESSE_DATEI.read_text().strip()
    if not adresse.startswith("https://"):
        abbruch(f"{ADRESSE_DATEI}: Die Adresse muss mit https:// beginnen.")
    return adresse.rstrip("/") + "/"


def schreibe_qr(link):
    try:
        import segno
    except ImportError:
        print("Hinweis: Kein QR-Code erzeugt, das Paket 'segno' fehlt (python3 -m pip install segno).")
        return
    segno.make(link, error="m").save(str(QR_DATEI), scale=16, border=4)
    print(f"QR-Code:  {QR_DATEI}")


def vorschau(schluessel_hex):
    import functools
    import http.server
    import webbrowser

    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(ZIEL))
    handler.log_message = lambda *a, **k: None
    with http.server.ThreadingHTTPServer(("127.0.0.1", VORSCHAU_PORT), handler) as server:
        url = f"http://localhost:{VORSCHAU_PORT}/#{schluessel_hex}"
        print(f"\nVorschau: {url}\n(Neu anfangen: http://localhost:{VORSCHAU_PORT}/?reset#{schluessel_hex})\nBeenden mit Ctrl+C.")
        webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print()


def main():
    if shutil.which("magick") is None:
        abbruch("ImageMagick ('magick') wurde nicht gefunden. Installation: brew install imagemagick")

    titel, brief = titel_und_text("brief.txt")
    schluss_titel, schluss = titel_und_text("schluss.txt")
    fragen = lies_fragen()
    adresse = lies_adresse()
    schluessel_hex = lies_schluessel()
    schluessel = bytes.fromhex(schluessel_hex)

    if ZIEL_FOTOS.exists():
        shutil.rmtree(ZIEL_FOTOS)
    ZIEL_FOTOS.mkdir(parents=True)
    (ZIEL / "daten.js").unlink(missing_ok=True)  # Überbleibsel der unverschlüsselten Fassung

    salz = hmac.new(schluessel, b"salz", hashlib.sha256).hexdigest()[:16]
    daten = {
        "titel": titel,
        "brief": brief,
        "schlussTitel": schluss_titel,
        "schluss": schluss,
        "salz": salz,
        "fragen": [],
    }
    with tempfile.TemporaryDirectory() as arbeitsordner:
        for nummer, frage in enumerate(fragen):
            hashes = sorted({
                hashlib.sha256(f"{salz}:{nummer}:{normalisiere(a)}".encode()).hexdigest()
                for a in frage["antworten"]
            })
            daten["fragen"].append({
                "foto": verarbeite_foto(schluessel, frage["foto"], arbeitsordner),
                "frage": frage["frage"],
                "antworten": hashes,
                "antwortfoto": (
                    verarbeite_foto(schluessel, frage["antwortfoto"], arbeitsordner)
                    if frage["antwortfoto"] else None
                ),
            })

    klartext = json.dumps(daten, ensure_ascii=False).encode("utf-8")
    (ZIEL / "daten.bin").write_bytes(verschluessele(schluessel, klartext))

    print(f"Fertig: {len(fragen)} Fragen -> {ZIEL}")
    for nummer, frage in enumerate(fragen, 1):
        zusatz = "" if frage["antwortfoto"] else "  (ohne Antwortfoto)"
        print(f"  {nummer}. {frage['frage']}  [{' | '.join(frage['antworten'])}]{zusatz}")

    link = f"{adresse}#{schluessel_hex}"
    print(f"\nLink:     {link}")
    schreibe_qr(link)

    if "--vorschau" in sys.argv[1:]:
        vorschau(schluessel_hex)


if __name__ == "__main__":
    main()
