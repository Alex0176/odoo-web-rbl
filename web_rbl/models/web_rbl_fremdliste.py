# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Fremde Bedrohungslisten: was andere über eine Adresse wissen.

WARUM EINE EIGENE TABELLE UND NICHT DIE SPERRLISTE
---------------------------------------------------
Die Sperrliste enthält, was wir SELBST beobachtet haben: Diese
Adresse hat bei uns an diesem Tag diesen Pfad gesucht. Das ist ein
Befund mit Beleg.

Eine fremde Liste ist etwas anderes -- eine Behauptung, die jemand
anderes aufstellt, aus Gründen, die wir nicht kennen, über Verkehr,
den wir nie gesehen haben. Sie kann falsch sein, veraltet oder für
einen anderen Zweck gedacht: ``blocklist.de`` etwa sammelt vor allem
Adressen, die anderswo SSH-Anmeldungen durchprobiert haben, und das
sagt über einen Webserver wenig.

Beides in derselben Tabelle zu führen, hiesse in einem halben Jahr
nicht mehr zu wissen, warum eine Adresse darauf steht. Deshalb
getrennt, und deshalb ist die Vorgabe ``melden`` und nicht
``sperren``: Wer eine fremde Liste scharf schaltet, uebernimmt
fremdes Urteil.

WAS SIE KANN
------------
Vier Quellen sind vorkonfiguriert, alle frei zugänglich und ohne
Anmeldung:

* **Tor-Ausgangsknoten** (``check.torproject.org``) -- wer über Tor
  kommt, verbirgt seine Herkunft. Das ist nicht verboten und nicht
  einmal ungewöhnlich, aber es ist eine Angabe, die man haben will.
* **Spamhaus DROP** -- Netze, die nach Einschätzung von Spamhaus
  vollständig unter der Kontrolle von Kriminellen stehen. Die engste
  und verlässlichste der vier.
* **FireHOL Level 1** -- eine Zusammenführung mehrerer Quellen,
  bewusst konservativ gehalten.
* **blocklist.de** -- gemeldete Angreifer, vor allem SSH und Mail.
  Die breiteste und damit die mit dem höchsten Fehlalarmrisiko.

Jede Quelle trägt ihre eigene Stufe. Man kann also Spamhaus sperren
lassen und blocklist.de nur melden.

DIE REGEL, DIE ÜBER ALLEM STEHT
--------------------------------
Die Freiliste gewinnt immer. Eine Adresse, die bei uns auf der
Freiliste steht, wird nicht gesperrt, egal was eine fremde Liste über
sie behauptet. Unsere eigene Kenntnis eines Kunden wiegt schwerer als
die Einschätzung eines Dritten.
"""
import bisect
import ipaddress
import logging

from odoo import api, fields, models, tools

_logger = logging.getLogger(__name__)


class WebRblQuelle(models.Model):
    _name = "web.rbl.quelle"
    _description = "Fremde Bedrohungsliste"
    _order = "sequence, name"

    name = fields.Char(required=True)
    sequence = fields.Integer(default=10)
    url = fields.Char(string="Adresse", required=True)
    beschreibung = fields.Text()
    aktiv = fields.Boolean(string="Aktiv", default=True)

    stufe = fields.Selection(
        [("sperren", "Ganz sperren"),
         ("kein_backend", "Kein Zugang zur Anmeldung"),
         ("melden", "Nur melden"),
         ("zaehlen", "Nur zählen")],
        string="Stufe", default="melden", required=True,
        help="Was geschieht, wenn eine Adresse auf dieser Liste steht?\n\n"
             "'Kein Zugang zur Anmeldung' ist der Mittelweg: Die "
             "Webseite bleibt lesbar, die Anmeldemaske und die "
             "Schnittstellen sind zu. Für Tor-Ausgangsknoten ist das "
             "meist die richtige Antwort -- wer anonym lesen will, "
             "soll das dürfen; wer anonym Kennwörter durchprobieren "
             "will, nicht.\n\n"
             "Die Vorgabe ist 'melden': Wer eine fremde Liste scharf "
             "schaltet, übernimmt fremdes Urteil.")

    letzter_abgleich = fields.Datetime(readonly=True)
    anzahl = fields.Integer(string="Einträge", readonly=True)
    letzter_fehler = fields.Char(readonly=True)
    eintrag_ids = fields.One2many(
        "web.rbl.fremdliste", "quelle_id", string="Bereiche")

    _url_eindeutig = models.Constraint(
        "unique(url)", "Diese Quelle ist bereits eingetragen.")

    # ------------------------------------------------------------------
    def _holen(self):
        """Die Liste abrufen und in Bereiche zerlegen.

        Nimmt jede Zeile, die mit einer Adresse oder einem Netz
        beginnt, und übergeht alles andere. Damit kommen alle vier
        vorkonfigurierten Formate durch, ohne dass je Quelle ein
        eigener Leser nötig wäre: Spamhaus schreibt Kommentare mit
        ``;``, FireHOL mit ``#``, die Tor-Liste und blocklist.de
        schreiben gar keine.
        """
        self.ensure_one()
        import urllib.error
        import urllib.request
        try:
            anfrage = urllib.request.Request(
                self.url, headers={"User-Agent": "odoo-web-rbl"})
            with urllib.request.urlopen(anfrage, timeout=30) as antwort:
                roh = antwort.read(1024 * 1024 * 8).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError) as fehler:
            return None, str(fehler)[:200]

        bereiche = set()
        for zeile in roh.splitlines():
            zeile = zeile.strip()
            if not zeile or zeile[0] in "#;/":
                continue
            # Spamhaus: "1.2.3.0/24 ; SBL123"
            teil = zeile.split(";")[0].split("#")[0].strip().split()[0:1]
            if not teil:
                continue
            kandidat = teil[0]
            try:
                netz = ipaddress.ip_network(kandidat, strict=False)
            except ValueError:
                continue
            # Nichts Privates und nichts absurd Grosses. Ein /8 aus
            # einer fremden Liste ist kein Befund, sondern ein Risiko:
            # FireHOL fuehrt etwa reservierte Bereiche mit, und die
            # gehoeren nicht in eine Sperrliste fuer Webverkehr.
            if netz.is_private or netz.is_loopback or netz.is_link_local \
                    or netz.is_reserved or netz.is_multicast:
                continue
            if netz.version == 4 and netz.prefixlen < 16:
                continue
            if netz.version == 6 and netz.prefixlen < 32:
                continue
            bereiche.add(str(netz))
        return bereiche, ""

    def abgleichen(self):
        """Eine Quelle einlesen. Eine leere Antwort löscht NIE."""
        Fremd = self.env["web.rbl.fremdliste"].sudo()
        for quelle in self:
            bereiche, fehler = quelle._holen()
            if bereiche is None:
                quelle.write({"letzter_fehler": fehler,
                              "letzter_abgleich": fields.Datetime.now()})
                _logger.warning("Web RBL: Quelle %s nicht abrufbar: %s",
                                quelle.name, fehler)
                continue
            if not bereiche:
                quelle.write({
                    "letzter_fehler": "Leere Liste -- Bestand unveraendert",
                    "letzter_abgleich": fields.Datetime.now()})
                _logger.warning(
                    "Web RBL: Quelle %s lieferte eine LEERE Liste. Der "
                    "Bestand bleibt unveraendert.", quelle.name)
                continue

            vorhanden = {e.bereich: e
                         for e in Fremd.search([("quelle_id", "=", quelle.id)])}
            neu = [b for b in bereiche if b not in vorhanden]
            weg = [e.id for b, e in vorhanden.items() if b not in bereiche]
            if neu:
                Fremd.create([{"bereich": b, "quelle_id": quelle.id}
                              for b in neu])
            if weg:
                Fremd.browse(weg).unlink()
            quelle.write({
                "anzahl": len(bereiche),
                "letzter_fehler": False,
                "letzter_abgleich": fields.Datetime.now(),
            })
            _logger.info(
                "Web RBL: Quelle %s abgeglichen -- %s Bereiche "
                "(%s neu, %s entfallen).",
                quelle.name, len(bereiche), len(neu), len(weg))
        self.env.registry.clear_cache()
        return True

    def action_abgleichen(self):
        return self.abgleichen()

    @api.model
    def _cron_quellen_abgleichen(self):
        self.search([("aktiv", "=", True)]).abgleichen()
        return True


class WebRblFremdliste(models.Model):
    _name = "web.rbl.fremdliste"
    _description = "Bereich aus einer fremden Bedrohungsliste"
    _order = "bereich"
    _rec_name = "bereich"

    bereich = fields.Char(required=True, index=True, readonly=True)
    quelle_id = fields.Many2one(
        "web.rbl.quelle", required=True, ondelete="cascade", index=True)
    stufe = fields.Selection(related="quelle_id.stufe", store=False)

    # ------------------------------------------------------------------
    @api.model
    @tools.ormcache()
    def _bereiche(self):
        """Je Stufe sortierte, verschmolzene Bereiche.

        Dieselbe Bauform wie bei der Freiliste, und aus demselben
        Grund: Die Listen sind gross -- blocklist.de allein bringt
        ueber 25.000 Adressen mit -- und die Abfrage laeuft bei jeder
        Anfrage. Ein Durchlauf waere dort am falschen Platz.
        """
        roh = {stufe: {4: [], 6: []} for stufe in
               ("sperren", "kein_backend", "melden", "zaehlen")}
        self.env.cr.execute("""
            SELECT f.bereich, q.stufe
              FROM web_rbl_fremdliste f
              JOIN web_rbl_quelle q ON q.id = f.quelle_id
             WHERE q.aktiv = true
        """)
        for bereich, stufe in self.env.cr.fetchall():
            if stufe not in roh:
                continue
            try:
                netz = ipaddress.ip_network(bereich, strict=False)
            except ValueError:
                continue
            roh[stufe][netz.version].append(
                (int(netz.network_address), int(netz.broadcast_address)))

        ergebnis = {}
        for stufe, nach_version in roh.items():
            je_version = {}
            for version in (4, 6):
                geordnet = sorted(nach_version[version])
                verschmolzen = []
                for anfang, ende in geordnet:
                    if verschmolzen and anfang <= verschmolzen[-1][1] + 1:
                        verschmolzen[-1] = (verschmolzen[-1][0],
                                            max(verschmolzen[-1][1], ende))
                    else:
                        verschmolzen.append((anfang, ende))
                je_version[version] = tuple(verschmolzen)
            ergebnis[stufe] = je_version
        return ergebnis

    @api.model
    def stufe_fuer(self, adresse):
        """Welche Stufe gilt für diese Adresse? "" wenn keine.

        Die schärfste gewinnt: Steht eine Adresse auf einer sperrenden
        und einer meldenden Liste, wird gesperrt.
        """
        if not adresse:
            return ""
        try:
            geprueft = ipaddress.ip_address(adresse)
        except ValueError:
            return ""
        wert = int(geprueft)
        alle = self._bereiche()
        for stufe in ("sperren", "kein_backend", "melden", "zaehlen"):
            bereiche = alle.get(stufe, {}).get(geprueft.version, ())
            if not bereiche:
                continue
            i = bisect.bisect_right(bereiche, (wert, float("inf"))) - 1
            if i >= 0 and bereiche[i][0] <= wert <= bereiche[i][1]:
                return stufe
        return ""

    @api.model
    def quellen_zu(self, adresse):
        """Welche Quellen nennen diese Adresse? Für die Anzeige."""
        if not adresse:
            return self.browse()
        try:
            geprueft = ipaddress.ip_address(adresse)
        except ValueError:
            return self.browse()
        treffer = self.browse()
        for satz in self.search([]):
            try:
                netz = ipaddress.ip_network(satz.bereich, strict=False)
            except ValueError:
                continue
            if geprueft.version == netz.version and geprueft in netz:
                treffer |= satz
        return treffer
