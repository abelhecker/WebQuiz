/* Quiz-Logik. Texte und Fotos liegen verschlüsselt in daten.bin und fotos/*.bin
   (erzeugt von build.py). Der Schlüssel steht im Link hinter dem "#". */

// ---- Antwortprüfung -------------------------------------------------------
// Muss exakt zu normalisiere() in build.py passen.
function normalisiere(text) {
  return text
    .normalize('NFC')
    .toLowerCase()
    .replace(/ä/g, 'ae')
    .replace(/ö/g, 'oe')
    .replace(/ü/g, 'ue')
    .replace(/ß/g, 'ss')
    .normalize('NFD')
    .replace(/[^a-z0-9]/g, '');
}

var SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];

// SHA-256 für reine ASCII-Texte (mehr brauchen wir nach normalisiere() nicht).
function sha256(text) {
  function rr(v, n) { return (v >>> n) | (v << (32 - n)); }
  var bytes = [], i;
  for (i = 0; i < text.length; i++) bytes.push(text.charCodeAt(i) & 255);
  var bits = bytes.length * 8;
  bytes.push(128);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (i = 7; i >= 0; i--) bytes.push(i > 3 ? 0 : (bits >>> (i * 8)) & 255);

  var h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  var w = new Array(64);
  for (var off = 0; off < bytes.length; off += 64) {
    for (i = 0; i < 16; i++) {
      w[i] = (bytes[off + 4 * i] << 24) | (bytes[off + 4 * i + 1] << 16) |
             (bytes[off + 4 * i + 2] << 8) | bytes[off + 4 * i + 3];
    }
    for (i = 16; i < 64; i++) {
      var s0 = rr(w[i - 15], 7) ^ rr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      var s1 = rr(w[i - 2], 17) ^ rr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], k = h[7];
    for (i = 0; i < 64; i++) {
      var t1 = (k + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[i] + w[i]) | 0;
      var t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      k = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + k) | 0;
  }
  var hex = '';
  for (i = 0; i < 8; i++) hex += ('00000000' + (h[i] >>> 0).toString(16)).slice(-8);
  return hex;
}

function antwortHash(salz, nummer, eingabe) {
  return sha256(salz + ':' + nummer + ':' + normalisiere(eingabe));
}

function istRichtig(quiz, nummer, eingabe) {
  if (!normalisiere(eingabe)) return false;
  return quiz.fragen[nummer].antworten.indexOf(antwortHash(quiz.salz, nummer, eingabe)) !== -1;
}

// ---- Links in Brief und Schlusstext ---------------------------------------
// Zerlegt einen Text in normale Stücke und Links. Zwei Schreibweisen:
//   https://example.org            -> die Adresse selbst wird anklickbar
//   [Restaurant](https://...)      -> das Wort "Restaurant" wird anklickbar
function zerlegeLinks(text) {
  var muster = /\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)|https?:\/\/[^\s<>"]+/g;
  var teile = [], ende = 0, treffer;
  while ((treffer = muster.exec(text))) {
    var ganz = treffer[0], adresse = treffer[2] || ganz, name = treffer[1] || ganz;
    if (!treffer[2]) {
      // Satzzeichen direkt hinter einer nackten Adresse gehören nicht zum Link
      adresse = name = ganz.replace(/[).,;:!?]+$/, '');
      muster.lastIndex = treffer.index + adresse.length;
    }
    if (treffer.index > ende) teile.push({ text: text.slice(ende, treffer.index) });
    teile.push({ text: name, adresse: adresse });
    ende = muster.lastIndex;
  }
  if (ende < text.length) teile.push({ text: text.slice(ende) });
  return teile;
}

// ---- Entschlüsselung ------------------------------------------------------
// Dateiformat (siehe build.py): 12 Byte Nonce, danach AES-GCM-Chiffrat.
function hexZuBytes(hex) {
  var bytes = new Uint8Array(hex.length / 2);
  for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(2 * i, 2), 16);
  return bytes;
}

async function ladeEntschluesselt(schluessel, pfad) {
  var antwort = await fetch(pfad);
  if (!antwort.ok) throw new Error('Datei nicht gefunden: ' + pfad);
  var daten = new Uint8Array(await antwort.arrayBuffer());
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv: daten.slice(0, 12) }, schluessel, daten.slice(12));
}

// ---- Oberfläche -----------------------------------------------------------
async function starteQuiz() {
  var SPEICHER = 'webquiz-stand';
  var SPEICHER_SCHLUESSEL = 'webquiz-schluessel';
  var ANSICHTEN = ['hinweis', 'brief', 'frage', 'loesung', 'ende'];
  var $ = function (id) { return document.getElementById(id); };

  function zeige(ansicht) {
    ANSICHTEN.forEach(function (name) { $('ansicht-' + name).hidden = name !== ansicht; });
    window.scrollTo(0, 0);
  }

  function zeigeHinweis(text) {
    $('hinweis-text').textContent = text;
    zeige('hinweis');
  }

  // -- Schlüssel aus dem Link (QR-Code) holen, sonst den gemerkten nehmen
  var gueltig = /^[0-9a-f]{32}$/;
  var hex = location.hash.replace(/^#/, '').trim().toLowerCase();
  if (!gueltig.test(hex)) {
    try { hex = localStorage.getItem(SPEICHER_SCHLUESSEL) || ''; } catch (e) { hex = ''; }
  }
  if (!gueltig.test(hex)) {
    zeigeHinweis('Bitte scanne den QR-Code, um das Quiz zu öffnen.');
    return;
  }
  if (!window.crypto || !crypto.subtle) {
    zeigeHinweis('Diese Seite funktioniert nur über eine sichere Verbindung (https).');
    return;
  }

  var schluessel, quiz;
  try {
    schluessel = await crypto.subtle.importKey('raw', hexZuBytes(hex), 'AES-GCM', false, ['decrypt']);
    quiz = JSON.parse(new TextDecoder().decode(await ladeEntschluesselt(schluessel, 'daten.bin')));
  } catch (e) {
    zeigeHinweis('Das Quiz konnte nicht geöffnet werden. Prüfe deine Internetverbindung oder scanne den QR-Code noch einmal.');
    return;
  }
  try { localStorage.setItem(SPEICHER_SCHLUESSEL, hex); } catch (e) {}

  // -- Spielstand
  // gestartet: Brief wurde gelesen, geloest: Anzahl gelöster Fragen,
  // loesung: die Auflösung der zuletzt gelösten Frage ist gerade zu sehen
  var stand = { gestartet: false, geloest: 0, loesung: false };

  if (/[?&]reset\b/.test(location.search)) {
    try { localStorage.removeItem(SPEICHER); } catch (e) {}
    history.replaceState(null, '', location.pathname + location.hash);
  }
  try {
    var alt = JSON.parse(localStorage.getItem(SPEICHER));
    if (alt && typeof alt.geloest === 'number') {
      stand.gestartet = !!alt.gestartet;
      stand.geloest = Math.max(0, Math.min(Math.floor(alt.geloest), quiz.fragen.length));
      stand.loesung = !!alt.loesung && stand.geloest > 0;
    }
  } catch (e) {}

  function speichere() {
    try { localStorage.setItem(SPEICHER, JSON.stringify(stand)); } catch (e) {}
  }

  // -- Fotos: laden, entschlüsseln, als Bild-Adresse im Speicher halten
  var fotoCache = {};
  function fotoAdresse(pfad) {
    if (!fotoCache[pfad]) {
      fotoCache[pfad] = ladeEntschluesselt(schluessel, pfad).then(function (puffer) {
        return URL.createObjectURL(new Blob([puffer], { type: 'image/jpeg' }));
      });
      fotoCache[pfad].catch(function () { delete fotoCache[pfad]; });
    }
    return fotoCache[pfad];
  }

  function vorladen(pfad) {
    if (pfad) fotoAdresse(pfad).catch(function () {});
  }

  function setzeFoto(bild, pfad) {
    bild.dataset.pfad = pfad;
    bild.removeAttribute('src');
    bild.classList.add('laedt');
    fotoAdresse(pfad).then(function (adresse) {
      if (bild.dataset.pfad !== pfad) return;
      bild.src = adresse;
      bild.classList.remove('laedt');
    }, function () {
      // z. B. Funkloch: nach kurzer Pause noch einmal versuchen
      setTimeout(function () { if (bild.dataset.pfad === pfad) setzeFoto(bild, pfad); }, 3000);
    });
  }

  function setzeAbsaetze(element, text) {
    element.textContent = '';
    text.split(/\n\s*\n/).forEach(function (absatz) {
      if (!absatz.trim()) return;
      if (absatz.trim() === '---') {
        element.appendChild(document.createElement('hr'));
        return;
      }
      var p = document.createElement('p');
      zerlegeLinks(absatz.trim()).forEach(function (teil) {
        if (!teil.adresse) { p.appendChild(document.createTextNode(teil.text)); return; }
        var a = document.createElement('a');
        a.href = teil.adresse;
        a.textContent = teil.text;
        a.target = '_blank';
        a.rel = 'noopener';
        p.appendChild(a);
      });
      element.appendChild(p);
    });
  }

  function fortschrittText(nummer) {
    return 'Frage ' + (nummer + 1) + ' von ' + quiz.fragen.length;
  }

  // -- Ansichten
  function zeigeBrief() {
    $('knopf-start').textContent = stand.gestartet ? 'Zurück zum Quiz' : 'Quiz starten';
    zeige('brief');
  }

  function zeigeFrage() {
    var nummer = stand.geloest;
    if (nummer >= quiz.fragen.length) { zeige('ende'); return; }
    var frage = quiz.fragen[nummer];
    $('fortschritt').textContent = fortschrittText(nummer);
    setzeFoto($('foto'), frage.foto);
    vorladen(frage.antwortfoto);
    $('frage-text').textContent = frage.frage;
    $('eingabe').value = '';
    $('meldung').textContent = '';
    zeige('frage');
  }

  function zeigeLoesung() {
    var nummer = stand.geloest - 1;
    var frage = quiz.fragen[nummer];
    var letzte = stand.geloest >= quiz.fragen.length;
    $('loesung-fortschritt').textContent = fortschrittText(nummer);
    $('loesung-foto').hidden = !frage.antwortfoto;
    if (frage.antwortfoto) setzeFoto($('loesung-foto'), frage.antwortfoto);
    if (!letzte) vorladen(quiz.fragen[stand.geloest].foto);
    $('knopf-weiter').textContent = letzte ? 'Zum Schluss' : 'Weiter zur nächsten Frage';
    zeige('loesung');
  }

  function zeigeAktuell() {
    if (stand.loesung) zeigeLoesung(); else zeigeFrage();
  }

  document.title = quiz.titel;
  $('brief-titel').textContent = quiz.titel;
  setzeAbsaetze($('brief-text'), quiz.brief);
  $('ende-titel').textContent = quiz.schlussTitel;
  setzeAbsaetze($('ende-text'), quiz.schluss);

  $('knopf-start').addEventListener('click', function () {
    stand.gestartet = true;
    speichere();
    zeigeAktuell();
  });

  $('knopf-brief').addEventListener('click', zeigeBrief);

  $('formular').addEventListener('submit', function (ereignis) {
    ereignis.preventDefault();
    var eingabe = $('eingabe');
    if (!eingabe.value.trim()) return;

    if (istRichtig(quiz, stand.geloest, eingabe.value)) {
      stand.geloest += 1;
      stand.loesung = true;
      speichere();
      eingabe.blur();
      zeigeLoesung();
    } else {
      $('meldung').textContent = 'Das stimmt leider noch nicht.';
      eingabe.classList.remove('wackeln');
      void eingabe.offsetWidth; // Animation neu starten
      eingabe.classList.add('wackeln');
    }
  });

  $('knopf-weiter').addEventListener('click', function () {
    stand.loesung = false;
    speichere();
    zeigeFrage();
  });

  if (stand.gestartet) zeigeAktuell(); else zeigeBrief();
}

if (typeof document !== 'undefined') starteQuiz();
