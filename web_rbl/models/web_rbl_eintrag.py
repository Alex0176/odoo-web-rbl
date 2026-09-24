# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Die Sperrliste selbst: Einträge, Fristen und die Verstetigung.

DIE REGEL
---------
Erstmalig auffällig  -> 24 Stunden gesperrt
An drei verschiedenen TAGEN auffällig -> dauerhaft gesperrt

Bewusst an drei verschiedenen Tagen und nicht nach drei Treffern:
Ein Scanner feuert dreißig Sonden in zwei Sekunden ab, das ist EIN
Vorfall. Wer aber am Montag, am Mittwoch und am Freitag wiederkommt,
sucht sich nicht mehr, sondern hat uns auf einer Liste.

WARUM TAGE UND NICHT STUNDEN GEZÄHLT WERDEN
--------------------------------------------
Gezählt wird das Datum des Treffers, nicht der Zeitpunkt. Zwei Sonden
um 23:59 und 00:01 sind damit zwei Tage -- unsauber, aber in die
sichere Richtung: Die Verstetigung tritt eher zu spät ein als zu früh.
Eine Dauersperre nimmt man nicht zurück, indem man wartet.
"""

import logging

from dateutil.relativedelta import relativedelta

from odoo import SUPERUSER_ID, _, api, fields, models
from odoo.exceptions import UserError

_logger = logging.getLogger(__name__)

SPERRE_STUNDEN = 24
TAGE_BIS_DAUERHAFT = 3


class WebRblEintrag(models.Model):
    _name = "web.rbl.eintrag"
    _description = "Sperrlisteneintrag"
    _order = "gesperrt_bis desc, id desc"
    _rec_name = "adresse"

    adresse = fields.Char(
        string="Adresse", required=True, index=True, readonly=True)
    zustand = fields.Selection(
        [("beobachtet", "Beobachtet"),
         ("gesperrt", "Gesperrt"),
         ("dauerhaft", "Dauerhaft gesperrt"),
         ("frei", "Freigegeben")],
        string="Zustand", default="beobachtet", required=True, index=True)
    treffer_anzahl = fields.Integer(
        string="Trefferzahl", default=0, readonly=True)
    tage_auffaellig = fields.Integer(
        string="Auffällige Tage", default=0, readonly=True,
        help="An wie vielen verschiedenen Tagen diese Adresse auffiel. "
             "Ab drei wird die Sperre dauerhaft.")
    erstmals = fields.Datetime(string="Erstmals", readonly=True)
    zuletzt = fields.Datetime(string="Zuletzt", readonly=True, index=True)
    gesperrt_bis = fields.Datetime(
        string="Gesperrt bis", readonly=True,
        help="Leer bei dauerhafter Sperre oder Freigabe.")
    letzter_pfad = fields.Char(string="Letzter Pfad", readonly=True)
    notiz = fields.Text(string="Notiz")
    treffer_ids = fields.One2many(
        "web.rbl.treffer", "eintrag_id", string="Einzeltreffer")

    _adresse_eindeutig = models.Constraint(
        "unique(adresse)",
        "Zu jeder Adresse gibt es genau einen Eintrag.")

    # ------------------------------------------------------------------
    # Ist gesperrt?
    # ------------------------------------------------------------------
    @api.model
    def ist_gesperrt(self, adresse):
        """Schnelle Abfrage für den Anfrageweg.

        Bewusst mit ``search_count`` und ohne Datensatzaufbau: Diese
        Abfrage läuft bei JEDER Anfrage an den Webserver.
        """
        if not adresse:
            return False
        jetzt = fields.Datetime.now()
        return bool(self.sudo().search_count([
            ("adresse", "=", adresse),
            "|",
            ("zustand", "=", "dauerhaft"),
            "&", ("zustand", "=", "gesperrt"), ("gesperrt_bis", ">", jetzt),
        ], limit=1))

    # ------------------------------------------------------------------
    # Treffer verbuchen
    # ------------------------------------------------------------------
    @api.model
    def treffer_eigene_transaktion(self, adresse, pfad, muster):
        """Treffer in einer EIGENEN Transaktion verbuchen.

        WARUM DAS NÖTIG IST
        -------------------
        Die Verbuchung geschieht mitten in einer Anfrage, die gleich
        darauf mit ``Forbidden`` abbricht. Odoo rollt die Transaktion
        einer abgebrochenen Anfrage zurück -- und nimmt den gerade
        geschriebenen Treffer mit. Gemessen am 24.09.2026: vier Sonden
        abgewiesen, null Einträge in der Tabelle.

        Ein eigener Cursor hängt nicht an der Anfrage und übersteht
        deren Abbruch. Er wird sofort festgeschrieben und geschlossen.

        Scheitert er, bleibt es dabei: Ein verlorener Treffer ist
        ärgerlich, eine hängende Verbindung wäre schlimmer.
        """
        if not adresse:
            return False
        try:
            with self.pool.cursor() as cr:
                eigene = api.Environment(cr, SUPERUSER_ID, {})
                eigene["web.rbl.eintrag"].treffer_buchen(
                    adresse, pfad, muster)
                cr.commit()
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Treffer fuer %s konnte nicht verbucht werden.",
                adresse)
            return False
        return True

    @api.model
    def treffer_buchen(self, adresse, pfad, muster):
        """Einen Sondierungsversuch verbuchen und die Frist fortschreiben."""
        if not adresse:
            return self.browse()
        jetzt = fields.Datetime.now()
        heute = fields.Date.context_today(self)
        eintrag = self.sudo().search([("adresse", "=", adresse)], limit=1)
        if not eintrag:
            eintrag = self.sudo().create({
                "adresse": adresse,
                "erstmals": jetzt,
                "zustand": "beobachtet",
            })

        eintrag.sudo().write({
            "treffer_anzahl": eintrag.treffer_anzahl + 1,
            "zuletzt": jetzt,
            "letzter_pfad": (pfad or "")[:255],
        })
        self.env["web.rbl.treffer"].sudo().create({
            "eintrag_id": eintrag.id,
            "pfad": (pfad or "")[:255],
            "muster": muster or "",
            "tag": heute,
        })

        # Eine einmal freigegebene Adresse bleibt frei. Wer sie von Hand
        # freigegeben hat, hatte einen Grund; ihn stillschweigend zu
        # ueberstimmen waere die schlechtere Ueberraschung.
        if eintrag.zustand == "frei":
            return eintrag

        eintrag.sudo()._frist_fortschreiben(heute, jetzt)
        return eintrag

    def _frist_fortschreiben(self, heute, jetzt):
        """Sperre setzen oder verstetigen."""
        self.ensure_one()
        tage = len(set(self.treffer_ids.mapped("tag")))
        werte = {"tage_auffaellig": tage}

        if tage >= TAGE_BIS_DAUERHAFT:
            if self.zustand != "dauerhaft":
                _logger.info(
                    "Web RBL: %s an %s verschiedenen Tagen auffaellig -- "
                    "Sperre wird dauerhaft.", self.adresse, tage)
            werte.update({"zustand": "dauerhaft", "gesperrt_bis": False})
        else:
            werte.update({
                "zustand": "gesperrt",
                "gesperrt_bis": jetzt + relativedelta(hours=SPERRE_STUNDEN),
            })
        self.write(werte)

    # ------------------------------------------------------------------
    # Von Hand
    # ------------------------------------------------------------------
    def action_freigeben(self):
        """Adresse freigeben und künftige Treffer ignorieren."""
        for eintrag in self:
            eintrag.write({"zustand": "frei", "gesperrt_bis": False})
            _logger.info("Web RBL: %s von Hand freigegeben.", eintrag.adresse)
        return True

    def action_dauerhaft_sperren(self):
        for eintrag in self:
            eintrag.write({"zustand": "dauerhaft", "gesperrt_bis": False})
        return True

    def action_beobachten(self):
        """Zurück auf Beobachtung, ohne die Trefferhistorie zu verlieren."""
        for eintrag in self:
            eintrag.write({"zustand": "beobachtet", "gesperrt_bis": False})
        return True

    @api.model
    def von_hand_sperren(self, adresse, dauerhaft=False, notiz=""):
        """Eine Adresse ohne Treffer auf die Liste setzen."""
        Herkunft = self.env["web.rbl.herkunft"]
        if not Herkunft.sperrbar(adresse):
            raise UserError(_(
                "%(adresse)s lässt sich nicht sperren — entweder keine "
                "gültige Adresse oder ein eigenes Netz.", adresse=adresse))
        eintrag = self.sudo().search([("adresse", "=", adresse)], limit=1)
        werte = {
            "zustand": "dauerhaft" if dauerhaft else "gesperrt",
            "gesperrt_bis": False if dauerhaft else (
                fields.Datetime.now() + relativedelta(hours=SPERRE_STUNDEN)),
            "notiz": notiz,
        }
        if eintrag:
            eintrag.sudo().write(werte)
            return eintrag
        werte.update({"adresse": adresse, "erstmals": fields.Datetime.now()})
        return self.sudo().create(werte)

    # ------------------------------------------------------------------
    # Aufräumen
    # ------------------------------------------------------------------
    @api.model
    def _cron_fristen_pruefen(self):
        """Abgelaufene Sperren auf Beobachtung zurücksetzen.

        Die Einträge werden NICHT gelöscht: Ihre Trefferhistorie ist es,
        die beim nächsten Besuch über die Verstetigung entscheidet.
        """
        abgelaufen = self.sudo().search([
            ("zustand", "=", "gesperrt"),
            ("gesperrt_bis", "<=", fields.Datetime.now()),
        ])
        if abgelaufen:
            abgelaufen.write({"zustand": "beobachtet", "gesperrt_bis": False})
            _logger.info(
                "Web RBL: %s Sperre(n) abgelaufen.", len(abgelaufen))
        return True

    @api.model
    def _cron_alte_treffer_loeschen(self):
        """Treffer nach einer Aufbewahrungsfrist entfernen.

        Sonst wächst die Treffertabelle unbegrenzt -- auf der gemessenen
        Installation wären das rund 98.000 Zeilen in siebzehn Tagen.
        Dauerhaft gesperrte Adressen behalten ihre Historie.
        """
        Parameter = self.env["ir.config_parameter"].sudo()
        try:
            tage = int(Parameter.get_param("web_rbl.treffer_aufbewahrung", 30))
        except (TypeError, ValueError):
            tage = 30
        grenze = fields.Date.context_today(self) - relativedelta(
            days=max(tage, 1))
        alte = self.env["web.rbl.treffer"].sudo().search([
            ("tag", "<", fields.Date.to_string(grenze)),
            ("eintrag_id.zustand", "!=", "dauerhaft"),
        ])
        if alte:
            anzahl = len(alte)
            alte.unlink()
            _logger.info("Web RBL: %s alte Treffer entfernt.", anzahl)
        return True


class WebRblTreffer(models.Model):
    _name = "web.rbl.treffer"
    _description = "Einzelner Sondierungsversuch"
    _order = "id desc"

    eintrag_id = fields.Many2one(
        "web.rbl.eintrag", string="Adresse", required=True,
        ondelete="cascade", index=True)
    pfad = fields.Char(string="Pfad", readonly=True)
    muster = fields.Char(string="Erkanntes Muster", readonly=True, index=True)
    tag = fields.Date(string="Tag", required=True, index=True)
