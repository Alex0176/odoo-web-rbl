# Web RBL — Sperrliste für Angriffsverkehr auf Odoo-Webseiten

Erkennt Sondierungsanfragen auf öffentliche Odoo-Webseiten, führt eine
Sperrliste und veröffentlicht sie für HAProxy, nftables oder ipset.

## Warum

Auf einer gemessenen Produktivinstallation mit fünf Webseiten waren über
siebzehn Tage **98.411 von 715.799 Anfragen** Sondierungen — dreizehn
Prozent:

| Muster | Anfragen |
|---|---|
| `.env`-Abgriff | 60.817 |
| Pfad-Traversal (`/@fs/../../.env`) | 15.186 |
| PHP/ASP-Sonden | 13.372 |
| WordPress-Sonden | 4.795 |
| `.git`-Abgriff | 4.467 |

Teuer ist daran nicht die Abwehr, sondern der Weg dorthin. Odoo sucht für
jede dieser Anfragen eine Fehlerseite und rendert sie über die
Webseitenvorlagen. Enthält der Pfad Punkt-Segmente, scheitert dabei auch
noch das Bauen der `og:url` — aus einer Sonde werden zwei
Stapelprotokolle. Gemessen: 28.401 solcher Fehler, dazu 9.467
Folgefehler, zusammen **96 Prozent des gesamten Protokollaufkommens**.

Dieses Modul antwortet auf dieselbe Anfrage mit einem 403, bevor die
Wegfindung überhaupt beginnt.

## Die Regel

    Erstmalig auffällig               → 24 Stunden gesperrt
    An drei verschiedenen TAGEN       → dauerhaft gesperrt

Bewusst an drei verschiedenen Tagen und nicht nach drei Treffern: Ein
Scanner feuert dreißig Sonden in zwei Sekunden ab, das ist ein Vorfall.
Wer am Montag, am Mittwoch und am Freitag wiederkommt, hat uns auf einer
Liste.

## Vorsichtsmaßnahmen

**Proxy-Erkennung.** Steht ein Proxy davor, ist `remote_addr` dessen
Adresse. Wer darauf sperrt, sperrt den Proxy und damit jeden Besucher
aller Webseiten. Das Modul prüft deshalb zuerst, ob die Adresse
überhaupt belastbar ist:

* `proxy_mode = True` in der `odoo.conf` **und** `X-Forwarded-Host`
  vorhanden → Odoo hat ProxyFix angewandt, die Adresse stimmt
* `X-Forwarded-For` kommt an, aber `proxy_mode` fehlt → **es wird nicht
  gesperrt**, mit Hinweis im Protokoll
* Mehr als ein Eintrag in `X-Forwarded-For` → nicht gesperrt, denn Odoo
  vertraut nur einem Sprung (`ProxyFix(x_for=1)`)

**Eigene Netze nie.** RFC-1918, Loopback, Link-Local und CGNAT stehen
auf einer festen Ausnahmeliste.

**Beobachten vor Sperren.** Nach der Installation steht
`web_rbl.sperren_aktiv` auf `0`: Sonden werden abgewiesen und verbucht,
gewöhnliche Anfragen gelisteter Adressen laufen aber durch. Erst wenn
die Zahlen zeigen, dass die Schwelle passt, wird eingeschaltet.

**Fehler bleiben folgenlos.** Was in der Prüfung schiefgeht, wird
protokolliert; die Anfrage läuft unverändert weiter. Ein Schutzmodul,
das bei einem eigenen Fehler die Webseite mitnimmt, ist schlimmer als
gar keines.

## Einbau in HAProxy

Liste abholen (Token aus `web_rbl.token`):

    curl -s -o /etc/haproxy/rbl.lst \
      "https://www.example.com/web_rbl/liste?token=DEIN_TOKEN"

In der `haproxy.cfg`:

    frontend web
        acl gesperrt src -f /etc/haproxy/rbl.lst
        http-request silent-drop if gesperrt

Ohne Neustart nachziehen über die Runtime-API:

    echo "add acl /etc/haproxy/rbl.lst 185.177.72.31" | \
      socat stdio /var/run/haproxy.sock

Für nftables oder ipset dieselbe Datei — eine Adresse je Zeile, sonst
nichts.

## Köder (abgeschaltet ausgeliefert)

Statt eines 403 kann das Modul auf die ersten *n* Sonden einer Adresse
eine erfundene Antwort schicken — eine `.env`, eine `.git/config` oder
das Wurzelverzeichnis eines Commodore 500. Ein Gerät, das nie gebaut
wurde: Niemand kann behaupten, wir hätten ihn in etwas hineingelockt,
was wie ein echtes System aussah.

Der Zweck ist nicht Täuschung, sondern **Beweis**. In jeder Fälschung
steckt ein Kanarienwert, der nur dort existiert:

    ADMIN_PATH=/cp-8f3a2b9e

Wird dieser Pfad je abgerufen, hat jemand die Fälschung gelesen und
danach gehandelt. Fehlalarm ist ausgeschlossen — der Wert kann aus
keiner anderen Quelle stammen. Solche Adressen wandern auf die
Hochrisiko-Liste, ohne Frist.

Kommt der Abruf von einer **anderen** Adresse als der, die den Köder
bekam, sind die Daten weitergegeben worden. Das steht dann im Eintrag,
samt Herkunft.

    /web_rbl/liste/hochrisiko?token=…

Getrennt von der Hauptliste, weil die Folgen andere sind: Auf der
großen Liste stehen auch Adressen, die morgen jemand anderem gehören.
Die Hochrisiko-Liste kann man ohne schlechtes Gewissen dauerhaft in
eine Firewall hängen.

**Der Köder ist ausgeschaltet ausgeliefert** (`web_rbl.koeder_aktiv = 0`).
Er ändert das Verhalten nach außen sichtbar — statt 403 kommt 200 mit
Inhalt —, und ein 200 auf `/.env` ist für manche Scanner selbst schon
ein Signal. Wer das einschaltet, soll es bewusst tun.

## Systemparameter

| Schlüssel | Vorgabe | Bedeutung |
|---|---|---|
| `web_rbl.aktiv` | `1` | Modul insgesamt an |
| `web_rbl.sperren_aktiv` | `0` | Gelistete Adressen auch bei gewöhnlichen Anfragen abweisen |
| `web_rbl.antwort` | `leise` | `leise` oder `forbidden` (beide 403) |
| `web_rbl.token` | — | Ohne Token liefert der Endpunkt nichts |
| `web_rbl.koeder_aktiv` | `0` | Köderantworten statt 403 |
| `web_rbl.koeder_max` | `5` | Höchstzahl Köder je Adresse |
| `web_rbl.muster.<name>` | — | `sperren`, `zaehlen` oder `melden` je Muster |
| `web_rbl.muster.pflichtseite` | `melden` | Auf `sperren` stellen, um das maschinelle Abgrasen von Impressumsdaten auszusperren |
| `web_rbl.treffer_aufbewahrung` | `30` | Tage, bevor alte Treffer entfernt werden |

## Die drei Stufen

| Stufe | Auslösende Anfrage | Folge für die Adresse |
|---|---|---|
| `sperren` | abgewiesen | 24 h gesperrt, nach drei Tagen dauerhaft |
| `zaehlen` | durchgelassen | nur verbucht — keine Sperre |
| `melden` | durchgelassen | verbucht, mit Befund, Zustand `Fehlkonfiguration` bzw. `Sammler` — **nie** gesperrt |

`zaehlen` und `melden` erreichen die ausgelieferte Sperrliste nicht: Der
Endpunkt zählt die sperrenden Zustände einzeln auf, statt die anderen
auszuschließen. Ein neuer Zustand landet damit nie versehentlich in
einer Firewall.

## Fehlkonfigurationen statt Sperren

Nicht jede Anfrage ins Leere ist ein Angriff. Über siebzehn Tage
Echtverkehr gemessen:

| Muster | Anfragen | Was dahintersteckt |
|---|---|---|
| `qnap` | 1.367 | Qsync-Client, der die Webseite für sein NAS hält |
| `autodiscover` | 65 | Outlook, das die Domain für seinen Exchange hält |

Solche Adressen werden **nie** gesperrt. Eine Sperre behebt den Defekt
nicht, sie verbirgt ihn — und trifft dabei denjenigen, dessen Gerät
kaputt konfiguriert ist. Stattdessen sammelt das Modul sie in einer
Arbeitsliste mit Befund und den betroffenen Domains, damit jemand
anrufen kann.

Am 24.09.2026 hat genau dieser Fall einen Kunden ausgesperrt: Das
`.cgi`-Muster hielt die QNAP-Web-API für eine Sondierung, die Firewall
verwarf 4.649 Pakete einer IPsec-Gegenstelle.

## Pflichtseiten und Sammler

Das Impressum ist keine gewöhnliche Seite. Es muss für Menschen
erreichbar bleiben — eine Sperre schafft genau den Verstoß, den ein
Abmahnschreiben sucht. Zugleich ist es die Seite, auf der Name und
Anschrift stehen, und damit das Ziel maschineller Ernte: Bei der
österreichischen Google-Fonts-Abmahnwelle zeigten die Protokolle
Zugriffe auf nicht zusammenhängende Hosts im Abstand von
Millisekunden — ein Headless-Browser, kein Besucher.

Das Modul unterscheidet deshalb:

* **Kanonische Pfade** (`/impressum`, `/kontakt`, `/contactus`) treffen
  auf kein Muster. Sie werden nie verbucht und nie gesperrt — auch
  nicht, wenn die Sammlersperre eingeschaltet ist.
* **Fremde Schreibweisen** (`/impressum.php`, `/impressum.asp`) sind
  das Kennzeichen des Durchprobierens. Sie werden gemeldet, und wer
  will, stellt `web_rbl.muster.pflichtseite = sperren`.
* **Maschinendateien** (`sitemap`, `robots`) sind davon ausgenommen und
  **nicht** sperrbar. Sie enthalten keine personenbezogene Angabe, und
  sie zu holen ist die Aufgabe jedes Crawlers. Gemessen: 14 von 24
  auffälligen Adressen waren Suchmaschinen-Crawler, die einem alten
  Link auf `/SiteMap.aspx` folgten.

Jeder Treffer hält außerdem fest, **welche Domain** angesprochen wurde.
Das Zugriffsprotokoll von werkzeug enthält den Host nicht; er ist nur
zur Laufzeit zu bekommen. Mehrere nicht zusammenhängende Domains
derselben Adresse sind das Kennzeichen des Rundumschlags.

Wird ein Parameter von außerhalb des laufenden Prozesses gesetzt (etwa
über `odoo-bin shell`), greift er erst nach einem Neustart. Über die
Oberfläche geändert wirkt er sofort.

## Lizenz

AGPL-3.0 or later.
