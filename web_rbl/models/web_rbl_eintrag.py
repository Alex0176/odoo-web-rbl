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
         ("hochrisiko", "Hochrisiko"),
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
    koeder_ids = fields.One2many(
        "web.rbl.koeder", "eintrag_id", string="Ausgelegte Köder")

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
            "|", "|",
            ("zustand", "=", "dauerhaft"),
            ("zustand", "=", "hochrisiko"),
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
            return self.browse()
        kennung = False
        try:
            with self.pool.cursor() as cr:
                # READ COMMITTED, sonst wirkt das ``ON CONFLICT`` unten
                # nicht: Odoo oeffnet jede Transaktion mit REPEATABLE
                # READ, und dort wirft PostgreSQL, statt zu schlucken.
                cr.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                # DEN EINTRAG WETTLAUFFREI SICHERSTELLEN.
                #
                # In der Nacht auf den 25.09.2026 sind so 77 Treffer
                # verlorengegangen: Zwei Arbeitsprozesse bearbeiten
                # gleichzeitig Sonden DERSELBEN Adresse, beide finden
                # keinen Eintrag, beide legen an -- einer laeuft in die
                # Eindeutigkeitsverletzung. Betroffen waren ausgerechnet
                # die aktivsten Angreifer, weil nur dort mehrere
                # Anfragen zeitgleich eintreffen.
                #
                # ``ON CONFLICT DO NOTHING`` legt an, wenn noetig, und
                # schweigt, wenn ein anderer schneller war. Danach ist
                # der Eintrag in jedem Fall vorhanden.
                cr.execute("""
                    INSERT INTO web_rbl_eintrag
                        (adresse, zustand, erstmals, treffer_anzahl,
                         tage_auffaellig, create_uid, create_date,
                         write_uid, write_date)
                    VALUES (%s, 'beobachtet', now() AT TIME ZONE 'UTC', 0, 0,
                            %s, now() AT TIME ZONE 'UTC',
                            %s, now() AT TIME ZONE 'UTC')
                    ON CONFLICT (adresse) DO NOTHING
                """, (adresse, SUPERUSER_ID, SUPERUSER_ID))
                eigene = api.Environment(cr, SUPERUSER_ID, {})
                eintrag = eigene["web.rbl.eintrag"].treffer_buchen(
                    adresse, pfad, muster)
                kennung = eintrag.id if eintrag else False
                cr.commit()
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Treffer fuer %s konnte nicht verbucht werden.",
                adresse)
            return self.browse()
        # Im Environment des Aufrufers zurueckgeben, damit der Koeder
        # damit weiterarbeiten kann.
        return self.browse(kennung) if kennung else self.browse()

    @api.model
    def hochrisiko_eigene_transaktion(self, adresse, kanarie):
        """Den Anbiss festhalten, unabhaengig von der Anfrage."""
        if not adresse:
            return False
        try:
            with self.pool.cursor() as cr:
                eigene = api.Environment(cr, SUPERUSER_ID, {})
                Eintrag = eigene["web.rbl.eintrag"]
                eintrag = Eintrag.search([("adresse", "=", adresse)], limit=1)
                if not eintrag:
                    eintrag = Eintrag.create({
                        "adresse": adresse,
                        "erstmals": fields.Datetime.now(),
                        "zustand": "beobachtet",
                    })
                eintrag.hochrisiko_setzen(
                    f"Kanarienwert {kanarie} abgerufen.")
                # Den Anbiss am Koeder im selben Cursor vermerken.
                eigene["web.rbl.koeder"].search(
                    [("kanarie", "=", kanarie)], limit=1).write({
                        "angebissen_am": fields.Datetime.now(),
                        "angebissen_von": adresse,
                    })
                cr.commit()
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Hochrisiko fuer %s nicht vermerkt.", adresse)
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

        # ATOMAR ZAEHLEN, NICHT LESEN-ADDIEREN-SCHREIBEN.
        #
        # ``treffer_anzahl = eintrag.treffer_anzahl + 1`` ueber den ORM
        # ist ein Lost Update: Zwei gleichzeitige Treffer lesen beide
        # denselben Stand und schreiben beide denselben neuen Wert --
        # einer geht verloren. Im Test mit zehn gleichzeitigen Sonden
        # zaehlte der Stand 11 statt 20.
        #
        # Die genaue Zahl steht ohnehin in ``treffer_ids``; dieses Feld
        # ist die schnelle Anzeige. Aber eine Anzeige, die bei jedem
        # Ansturm falsch wird, taugt nichts -- und ausgerechnet beim
        # Ansturm schaut man hin.
        eintrag.env.cr.execute("""
            UPDATE web_rbl_eintrag
               SET treffer_anzahl = treffer_anzahl + 1,
                   zuletzt        = %s,
                   letzter_pfad   = %s
             WHERE id = %s
        """, (jetzt, (pfad or "")[:255], eintrag.id))
        eintrag.invalidate_recordset(
            ["treffer_anzahl", "zuletzt", "letzter_pfad"])
        self.env["web.rbl.treffer"].sudo().create({
            "eintrag_id": eintrag.id,
            "pfad": (pfad or "")[:255],
            "muster": muster or "",
            "tag": heute,
        })

        # Eine einmal freigegebene Adresse bleibt frei. Wer sie von Hand
        # freigegeben hat, hatte einen Grund; ihn stillschweigend zu
        # ueberstimmen waere die schlechtere Ueberraschung.
        if eintrag.zustand in ("frei", "hochrisiko"):
            # "frei" ist eine Entscheidung eines Menschen, "hochrisiko"
            # die schaerfste Stufe - beide werden von einem weiteren
            # Treffer nicht angetastet.
            return eintrag

        eintrag.sudo()._frist_fortschreiben(heute, jetzt)
        return eintrag

    def hochrisiko_setzen(self, grund=""):
        """Die schärfste Stufe: nachweislich gehandelt, nicht nur gesucht.

        Wird gesetzt, wenn jemand einen Kanarienwert abgerufen hat --
        einen Pfad, den es nur in einer von uns ausgelieferten
        Fälschung gibt. Anders als bei der Mustererkennung ist hier
        kein Fehlalarm möglich: Der Wert kann aus keiner anderen Quelle
        stammen.

        Deshalb gibt es hier auch keine Frist. Wer den Köder gelesen und
        danach gehandelt hat, hat das nicht versehentlich getan.
        """
        for eintrag in self:
            eintrag.write({
                "zustand": "hochrisiko",
                "gesperrt_bis": False,
                "notiz": (eintrag.notiz or "") + ("\n" if eintrag.notiz else "")
                         + (grund or "Kanarienwert abgerufen."),
            })
            _logger.warning(
                "Web RBL: %s auf Hochrisiko gesetzt -- %s",
                eintrag.adresse, grund or "Kanarienwert abgerufen")
        return True

    def action_hochrisiko(self):
        return self.hochrisiko_setzen("Von Hand als Hochrisiko eingestuft.")

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
