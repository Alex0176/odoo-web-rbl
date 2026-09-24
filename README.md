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

## Systemparameter

| Schlüssel | Vorgabe | Bedeutung |
|---|---|---|
| `web_rbl.aktiv` | `1` | Modul insgesamt an |
| `web_rbl.sperren_aktiv` | `0` | Gelistete Adressen auch bei gewöhnlichen Anfragen abweisen |
| `web_rbl.antwort` | `leise` | `leise` oder `forbidden` (beide 403) |
| `web_rbl.token` | — | Ohne Token liefert der Endpunkt nichts |
| `web_rbl.treffer_aufbewahrung` | `30` | Tage, bevor alte Treffer entfernt werden |

Wird ein Parameter von außerhalb des laufenden Prozesses gesetzt (etwa
über `odoo-bin shell`), greift er erst nach einem Neustart. Über die
Oberfläche geändert wirkt er sofort.

## Lizenz

AGPL-3.0 or later.
