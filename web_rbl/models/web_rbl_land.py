# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Herkunftsland: anzeigen immer, sperren nur auf ausdrücklichen Wunsch.

WOZU DAS LAND GUT IST
---------------------
Zum Beurteilen. Eine Adresse in der Liste ist eine Zahlenfolge; mit
dem Land daneben ist sie ein Befund. Ein Anmeldeversuch aus Österreich
um zehn Uhr vormittags ist etwas anderes als einer aus einem Land, in
dem wir keinen einzigen Kunden haben.

WOZU ES NICHT TAUGT
-------------------
Zum pauschalen Aussperren, und das sagen die eigenen Zahlen deutlich.
Die Angreifer, die am 25.09.2026 in unserer Liste standen, kamen
überwiegend aus Google-Cloud-Bereichen (``34.x``, ``35.x``) -- und die
liegen in Belgien, Finnland und den Niederlanden. Eine Sperre für
alles ausserhalb des deutschsprachigen Raums hätte sie **nicht**
getroffen.

Getroffen hätte sie: eigene Mitarbeiter im Urlaub, Kunden auf
Geschäftsreise, Suchmaschinen-Crawler aus den USA. Und was ein
Angreifer umgeht, indem er einen Server in Frankfurt mietet, kostet
ihn zwölf Euro im Monat.

Deshalb ist die Sperre nach Land eine **Option, die niemand
voreingestellt bekommt**. Wer sie einschaltet, soll einen konkreten
Anlass haben -- etwa eine Angriffswelle aus einem Bereich, in dem man
nachweislich keine Kunden hat.

WAS ES BRAUCHT
--------------
Die GeoLite2-Datenbank von MaxMind, kostenlos, aber mit Konto:
``/usr/share/GeoIP/GeoLite2-Country.mmdb``. Fehlt sie, bleibt das Feld
schlicht leer und alles andere arbeitet unverändert weiter -- das
Modul setzt sie nirgends voraus.

Und eine Einordnung, die in Europa dazugehört: Eine IP-Adresse einem
Ort zuzuordnen ist Verarbeitung personenbezogener Daten. Das gehört
ins Verarbeitungsverzeichnis, auch wenn die Abfrage örtlich
stattfindet und niemand erfährt, wonach man fragt.
"""
import logging

from odoo import api, fields, models, tools

_logger = logging.getLogger(__name__)


class WebRblLand(models.Model):
    _name = "web.rbl.land"
    _description = "Regel für ein Herkunftsland"
    _order = "stufe, country_id"
    _rec_name = "country_id"

    country_id = fields.Many2one(
        "res.country", string="Land", required=True, ondelete="cascade",
        index=True)
    code = fields.Char(related="country_id.code", store=True, index=True)
    stufe = fields.Selection(
        [("sperren", "Ganz sperren"),
         ("kein_backend", "Kein Zugang zur Anmeldung"),
         ("melden", "Nur melden"),
         ("frei", "Nie sperren")],
        string="Regel", default="melden", required=True,
        help="'Nie sperren' ist die Ausnahme in die andere Richtung: "
             "Verkehr aus diesem Land wird von keiner Länderregel "
             "erfasst. Nützlich, wenn man eine ganze Weltregion sperrt "
             "und einzelne Länder davon ausnehmen will.")
    bemerkung = fields.Char(
        help="Warum gibt es diese Regel? In einem Jahr ist das die "
             "einzige Frage, die zählt.")
    aktiv = fields.Boolean(string="Aktiv", default=True)

    _land_eindeutig = models.Constraint(
        "unique(country_id)", "Für dieses Land gibt es bereits eine Regel.")

    # ------------------------------------------------------------------
    @api.model
    @tools.ormcache()
    def _regeln(self):
        """{Länderkürzel: Stufe} -- zwischengespeichert.

        Die Abfrage läuft bei jeder Anfrage. Ein Wörterbuch mit
        höchstens ein paar Dutzend Einträgen ist dafür genau richtig.
        """
        regeln = {}
        for satz in self.sudo().search([("aktiv", "=", True)]):
            if satz.code:
                regeln[satz.code.upper()] = satz.stufe
        return regeln

    @api.model
    def stufe_fuer(self, land):
        """Welche Regel gilt für dieses Land? "" wenn keine."""
        if not land:
            return ""
        return self._regeln().get(land.upper(), "")

    def _cache_leeren(self):
        self.env.registry.clear_cache()
        registry = self.env.registry

        def benachrichtigen():
            try:
                if registry.ready:
                    registry.signal_changes()
            except Exception:  # noqa: BLE001
                _logger.warning(
                    "Web RBL: Länderregel geändert, andere Prozesse "
                    "konnten aber nicht benachrichtigt werden.")
        try:
            self.env.cr.postcommit.add(benachrichtigen)
        except AttributeError:
            benachrichtigen()

    @api.model_create_multi
    def create(self, werteliste):
        saetze = super().create(werteliste)
        saetze._cache_leeren()
        return saetze

    def write(self, werte):
        ergebnis = super().write(werte)
        self._cache_leeren()
        return ergebnis

    def unlink(self):
        ergebnis = super().unlink()
        self._cache_leeren()
        return ergebnis
