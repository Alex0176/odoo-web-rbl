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
         ("fehlkonfiguration", "Fehlkonfiguration"),
         ("sammler", "Sammler"),
         ("gesperrt", "Gesperrt"),
         ("dauerhaft", "Dauerhaft gesperrt"),
         ("hochrisiko", "Hochrisiko"),
         ("frei", "Freigegeben")],
        string="Zustand", default="beobachtet", required=True, index=True,
        help="'Fehlkonfiguration' ist keine Vorstufe einer Sperre, "
             "sondern eine Arbeitsliste: Dort klopft defekte Software, "
             "kein Angreifer. Eine Sperre behebt den Defekt nicht.")
    befund = fields.Text(
        string="Befund", readonly=True,
        help="Was an dieser Adresse auffällt -- und was zu tun ist.")
    hosts = fields.Char(
        string="Betroffene Domains", readonly=True,
        help="Welche unserer Webseiten diese Adresse angesprochen hat.")
    hosts_anzahl = fields.Integer(
        string="Domains", default=0, readonly=True, index=True,
        help="Mehrere nicht zusammenhängende Domains derselben Adresse "
             "sind das Kennzeichen eines maschinellen Rundumschlags.")
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
    # Ein Verweis von Hand statt eines Many2one: Das Modul soll auch
    # dort laufen, wo es gar kein Ticketmodell gibt. Ein Many2one auf
    # ein nicht installiertes Modell macht das Modul uninstallierbar.
    ticket_modell = fields.Char(string="Ticketmodell", readonly=True)
    ticket_id = fields.Integer(string="Ticket", readonly=True, index=True)
    ticket_nummer = fields.Char(string="Ticketnummer", readonly=True)
    ticket_gemeldet_am = fields.Datetime(
        string="Zuletzt gemeldet", readonly=True,
        help="Bis zu diesem Zeitpunkt sind die Treffer im Ticket "
             "vermerkt. Was danach kommt, öffnet ein geschlossenes "
             "Ticket wieder.")
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
    def treffer_eigene_transaktion(self, adresse, pfad, muster, host="",
                                   stufe=None):
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
                    adresse, pfad, muster, host, stufe)
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
    def treffer_buchen(self, adresse, pfad, muster, host="", stufe=None):
        """Einen Sondierungsversuch verbuchen und die Frist fortschreiben.

        ``stufe`` ist ``sperren``, ``zaehlen`` oder ``melden`` -- und
        sie MUSS bis hierher durchgereicht werden. Ohne sie war der
        Unterschied zwischen den Stufen nur ein halber:

        DER FEHLER, DEN DAS BEHEBT
        --------------------------
        Bis zum 25.09.2026 kannte diese Methode die Stufe nicht und
        schrieb bei JEDEM Treffer die Frist fort. Ein zählendes Muster
        ließ damit zwar die auslösende Anfrage durch -- setzte den
        Eintrag aber auf ``gesperrt``, und die NÄCHSTE Anfrage
        derselben Adresse lief in die Sperrprüfung.

        "Zählen" hieß also in Wahrheit: eine Anfrage später sperren.
        Gemessen am Testsystem: ein einziger Aufruf von
        ``/SiteMap.aspx`` genügte, ``gesperrt_bis`` stand 24 Stunden in
        der Zukunft.

        Das machte die ganze Unterscheidung wirkungslos -- auch die
        Entschärfung von ``.asp``/``.aspx`` am selben Tag, die genau
        das verhindern sollte. Betroffen wäre etwa der Crawler, der
        einem alten Link auf ``/SiteMap.aspx`` folgt: Er hätte den Link
        geholt und wäre beim nächsten Abruf ausgesperrt gewesen.

        Jetzt eskaliert nur noch ``sperren``. ``zaehlen`` und
        ``melden`` verbuchen und lassen in Ruhe -- das ist der
        Beobachtungsbetrieb, für den sie gedacht sind.
        """
        if not adresse:
            return self.browse()
        from .ir_http import BEFUND, MELDEN, SPERREN
        if stufe is None:
            # Ein Aufrufer, der die Stufe nicht kennt, meint die
            # scharfe -- das ist das alte Verhalten und die sichere
            # Annahme fuer eine Sonde.
            stufe = SPERREN
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
        # WELCHE DOMAINS DIESE ADRESSE SCHON ANGESPROCHEN HAT.
        #
        # Wird im selben UPDATE mitgeschrieben. Das ist ein
        # Lesen-Aendern-Schreiben und damit theoretisch ein Lost
        # Update -- anders als beim Zaehler ist der Schaden hier aber
        # null: Es fehlt hoechstens ein Domainname, den der naechste
        # Treffer derselben Adresse wieder ergaenzt. Fuer eine Liste
        # von Namen einen zweiten Rundlauf zur Datenbank zu bezahlen,
        # waere im Anfrageweg der teurere Fehler.
        bekannt = [h for h in (eintrag.hosts or "").split(",") if h]
        if host and host not in bekannt:
            bekannt.append(host)
        bekannt = bekannt[:20]
        eintrag.env.cr.execute("""
            UPDATE web_rbl_eintrag
               SET treffer_anzahl = treffer_anzahl + 1,
                   zuletzt        = %s,
                   letzter_pfad   = %s,
                   hosts          = %s,
                   hosts_anzahl   = %s
             WHERE id = %s
        """, (jetzt, (pfad or "")[:255], ",".join(bekannt), len(bekannt),
              eintrag.id))
        eintrag.invalidate_recordset(
            ["treffer_anzahl", "zuletzt", "letzter_pfad",
             "hosts", "hosts_anzahl"])
        self.env["web.rbl.treffer"].sudo().create({
            "eintrag_id": eintrag.id,
            "pfad": (pfad or "")[:255],
            "muster": muster or "",
            "host": (host or "")[:120],
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

        # EINE FEHLKONFIGURATION IST KEINE VORSTUFE EINER SPERRE.
        #
        # Ein Qsync-Client, der seit Wochen unsere Webseite fuer sein
        # NAS haelt, klopft zwangslaeufig an vielen Tagen an -- nach
        # der Drei-Tage-Regel waere er binnen einer Woche DAUERHAFT
        # gesperrt. Genau so ist am 24.09.2026 ein Kunde auf der Liste
        # gelandet.
        #
        # Deshalb bricht ein Meldemuster hier ab, bevor die Frist
        # fortgeschrieben wird. Der Eintrag bekommt einen Befund und
        # bleibt sichtbar; gesperrt wird er nie.
        #
        # Mischfall: Wer AUSSERDEM sondiert, wird trotzdem gesperrt --
        # der naechste Treffer kommt dann mit einem Sperrmuster, laeuft
        # an dieser Stelle vorbei und schreibt die Frist fort. Ein
        # defektes NAS schuetzt niemanden, der daneben ``/.env`` sucht.
        if stufe != SPERREN:
            werte = {
                # Die Tageszahl wird trotzdem nachgefuehrt: Sie ist die
                # Kennzahl, an der man ablesen will, OB ein zaehlendes
                # Muster scharf geschaltet gehoert.
                "tage_auffaellig": len(set(eintrag.treffer_ids.mapped("tag"))),
            }
            if stufe == MELDEN:
                werte["befund"] = BEFUND.get(muster, "")
                if eintrag.zustand == "beobachtet":
                    # Ein Sammler ist keine Fehlkonfiguration. Beides
                    # wird gemeldet statt gesperrt, aber das eine ruft
                    # man beim Kunden an, das andere sieht man sich an.
                    werte["zustand"] = (
                        "sammler" if muster == "pflichtseite"
                        else "fehlkonfiguration")
            eintrag.sudo().write(werte)
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

    # ------------------------------------------------------------------
    # Aus einem Befund ein Ticket machen
    # ------------------------------------------------------------------
    @api.model
    def _cron_befunde_melden(self):
        """Je Adresse HÖCHSTENS EIN Ticket für eine Fehlkonfiguration.

        WARUM ALS CRON UND NICHT BEIM TREFFER
        --------------------------------------
        Ein Qsync-Client, dessen Ziel nicht stimmt, klopft im
        Minutentakt -- eine Adresse allein 968 mal in siebzehn Tagen.
        Ein Ticket im Anfrageweg anzulegen hiesse, für jede dieser
        Anfragen eine Datenbankverbindung, eine Nummernfolge und einen
        Nachrichtenkanal zu bezahlen. Am 25.09.2026 hat schon eine
        zusätzliche Verbindung je Sonde den Verbindungspool erschöpft.

        Hier nicht: Der Cron sieht einmal am Tag nach, was es Neues
        gibt, und legt in Ruhe an.

        WARUM ES KEIN MANY2ONE IST
        ---------------------------
        Das Modul ist öffentlich und soll ohne Ticketsystem laufen.
        Ein ``Many2one`` auf ein nicht installiertes Modell liesse es
        sich nicht einmal installieren. Also Modellname und Kennung von
        Hand -- und jeder Zugriff darauf geprüft.

        ABGESCHALTET AUSGELIEFERT. Einschalten je Muster::

            web_rbl.ticket.qnap         = 1
            web_rbl.ticket.autodiscover = 1
            web_rbl.ticket_modell       = helpdesk.ticket   (Vorgabe)
        """
        Parameter = self.env["ir.config_parameter"].sudo()
        modellname = Parameter.get_param(
            "web_rbl.ticket_modell", "helpdesk.ticket")
        if modellname not in self.env:
            # Kein Ticketsystem installiert -- das ist kein Fehler.
            return True

        offen = self.sudo().search([
            ("zustand", "in", ("fehlkonfiguration", "sammler")),
        ])
        angelegt = geoeffnet = 0
        for eintrag in offen:
            muster = eintrag._haupt_muster()
            if not muster:
                continue
            if Parameter.get_param(f"web_rbl.ticket.{muster}", "0") != "1":
                continue
            try:
                if eintrag.ticket_id:
                    geoeffnet += bool(eintrag._ticket_wiederoeffnen())
                else:
                    eintrag._ticket_anlegen(modellname)
                    angelegt += 1
            except Exception:  # noqa: BLE001
                # Ein misslungenes Ticket darf den Lauf nicht
                # abbrechen: Die naechste Adresse soll trotzdem ihres
                # bekommen. Beim naechsten Lauf wird es erneut
                # versucht.
                _logger.exception(
                    "Web RBL: Ticket fuer %s nicht bearbeitet.",
                    eintrag.adresse)
        if angelegt or geoeffnet:
            _logger.info(
                "Web RBL: %s Ticket(s) angelegt, %s wieder geoeffnet.",
                angelegt, geoeffnet)
        return True

    def _ticket_wiederoeffnen(self):
        """Ein geschlossenes Ticket bei einem neuen Fall wieder öffnen.

        WARUM NICHT EIN ZWEITES TICKET
        -------------------------------
        Eine Adresse, deren Sync-Client falsch zeigt, hört nicht auf zu
        klopfen, nur weil jemand das Ticket geschlossen hat. Für jeden
        Rückfall ein neues Ticket anzulegen hiesse, dieselbe Sache
        mehrfach zu führen -- und die Vorgeschichte, die beim Anruf am
        meisten hilft, läge über mehrere Tickets verstreut.

        Also: dasselbe Ticket, eine neue Notiz, wieder offen. Wer es
        geschlossen hat, sieht beim Wiederaufmachen sofort, was seither
        passiert ist.

        WANN NICHT
        ----------
        Nur, wenn seit der letzten Meldung tatsächlich etwas
        dazugekommen ist. Ein geschlossenes Ticket zu einer Adresse,
        die seither Ruhe gibt, bleibt geschlossen -- sonst ginge es bei
        jedem Cronlauf wieder auf.
        """
        self.ensure_one()
        if not self.ticket_id or not self.ticket_modell:
            return False
        if self.ticket_modell not in self.env:
            return False
        ticket = self.env[self.ticket_modell].sudo().browse(
            self.ticket_id).exists()
        if not ticket:
            # Jemand hat das Ticket geloescht. Dann ist der Verweis
            # wertlos; beim naechsten Lauf entsteht ein neues.
            self.write({"ticket_id": 0, "ticket_modell": False,
                        "ticket_nummer": False})
            return False

        # Gibt es ueberhaupt Neues?
        if self.ticket_gemeldet_am and self.zuletzt and \
                self.zuletzt <= self.ticket_gemeldet_am:
            return False

        stufe = getattr(ticket, "stage_id", False)
        geschlossen = bool(stufe) and getattr(stufe, "closed", False)
        if not geschlossen:
            # Offen: nur den Stand nachfuehren, keine Notiz. Wer das
            # Ticket gerade bearbeitet, braucht keine taegliche
            # Wiederholung derselben Meldung.
            self.write({"ticket_gemeldet_am": self.zuletzt})
            return False

        neue = self.treffer_ids.filtered(
            lambda t: not self.ticket_gemeldet_am
            or t.create_date > self.ticket_gemeldet_am)
        offene_stufe = self._offene_stufe(ticket)

        text = (
            f"<p><b>Der Befund ist wieder aufgetreten.</b></p>"
            f"<ul>"
            f"<li><b>Adresse:</b> {self.adresse}</li>"
            f"<li><b>Neue Anfragen seit der letzten Meldung:</b> "
            f"{len(neue)}</li>"
            f"<li><b>Zuletzt:</b> {self.zuletzt or ''}</li>"
            f"<li><b>Angesprochene Domains:</b> "
            f"{self.hosts or '(nicht erfasst)'}</li>"
            f"</ul>"
            f"<p>Das Ticket wurde deshalb wieder geöffnet. Die Ursache "
            f"liegt beim Anschlussinhaber und ist offenbar noch nicht "
            f"abgestellt.</p>"
        )

        # OHNE MAILVORLAGE UMSTUFEN.
        #
        # helpdesk_mgmt haengt an der Stufenaenderung eine Mailvorlage
        # (_track_template, helpdesk_ticket.py:322) und setzt dabei
        # ausdruecklich composition_mode "mass_mail", damit sie in
        # jedem Fall hinausgeht. Fuer eine interne Arbeitsnotiz waere
        # das falsch -- ``tracking_disable`` verhindert die
        # Nachverfolgung und damit die Vorlage.
        if offene_stufe:
            ticket.with_context(tracking_disable=True).write(
                {"stage_id": offene_stufe.id})
        # Die Notiz danach und von Hand: als internes Protokoll, nicht
        # als Nachricht an Abonnenten.
        ticket.message_post(body=text, subtype_xmlid="mail.mt_note")
        self.write({"ticket_gemeldet_am": self.zuletzt})
        _logger.info(
            "Web RBL: Ticket %s zu %s wieder geoeffnet (%s neue Treffer).",
            ticket.id, self.adresse, len(neue))
        return True

    @api.model
    def _offene_stufe(self, ticket):
        """Die Stufe, in die ein wiedereröffnetes Ticket gehört."""
        Parameter = self.env["ir.config_parameter"].sudo()
        gesetzt = Parameter.get_param("web_rbl.ticket_stufe_offen_id")
        Stufe = ticket.stage_id._name if getattr(
            ticket, "stage_id", False) else None
        if not Stufe:
            return None
        Stufen = self.env[Stufe].sudo()
        if gesetzt:
            try:
                kandidat = Stufen.browse(int(gesetzt)).exists()
                if kandidat:
                    return kandidat
            except (TypeError, ValueError):
                pass
        return Stufen.search(
            [("closed", "=", False)], order="sequence", limit=1) or None

    def _haupt_muster(self):
        """Das Muster, das diesen Eintrag am häufigsten ausgelöst hat."""
        self.ensure_one()
        zaehler = {}
        for treffer in self.treffer_ids:
            if treffer.muster:
                zaehler[treffer.muster] = zaehler.get(treffer.muster, 0) + 1
        if not zaehler:
            return ""
        return max(zaehler, key=zaehler.get)

    def _ticket_anlegen(self, modellname):
        self.ensure_one()
        Parameter = self.env["ir.config_parameter"].sudo()
        Ticket = self.env[modellname].sudo()

        # JE ADRESSE EINES -- AUCH ueBER DEN EINTRAG HINWEG.
        #
        # ``ticket_id`` allein genuegt nicht: Wird ein Eintrag
        # entfernt (etwa beim Aufraeumen) und die Adresse faellt
        # danach erneut auf, entstuende ein zweites Ticket zur selben
        # Sache. Deshalb vorher nachsehen, ob es schon eines gibt --
        # und sich daran haengen statt ein neues anzulegen.
        vorhanden = Ticket.search(
            [("name", "=like", f"Fehlkonfiguration {self.adresse}:%")],
            order="id desc", limit=1)
        if vorhanden:
            self.write({
                "ticket_modell": modellname,
                "ticket_id": vorhanden.id,
                "ticket_nummer": (
                    getattr(vorhanden, "number", False)
                    or vorhanden.display_name or str(vorhanden.id)),
            })
            # Kein ``ticket_gemeldet_am``: Das uebernimmt gleich das
            # Wiederoeffnen, das dann auch die Notiz schreibt.
            self._ticket_wiederoeffnen()
            return vorhanden

        domains = self.hosts or "(nicht erfasst)"
        pfade = []
        for treffer in self.treffer_ids[:8]:
            pfade.append(f"<li><code>{treffer.pfad or ''}</code>"
                         f"{' &mdash; ' + treffer.host if treffer.host else ''}"
                         f"</li>")
        beschreibung = (
            f"<p>{self.befund or ''}</p>"
            f"<ul>"
            f"<li><b>Adresse:</b> {self.adresse}</li>"
            f"<li><b>Angesprochene Domains:</b> {domains}</li>"
            f"<li><b>Anfragen bisher:</b> {self.treffer_anzahl}</li>"
            f"<li><b>Erstmals:</b> {self.erstmals or ''}</li>"
            f"<li><b>Zuletzt:</b> {self.zuletzt or ''}</li>"
            f"</ul>"
            f"<p><b>Zuletzt gesehene Pfade:</b></p><ul>{''.join(pfade)}</ul>"
            f"<p>Diese Adresse ist <b>nicht</b> gesperrt und wird es durch "
            f"diesen Befund auch nicht. Das Ticket ist eine Erinnerung, "
            f"die Ursache beim Anschlussinhaber abzustellen.</p>"
        )
        werte = {
            "name": f"Fehlkonfiguration {self.adresse}: "
                    f"{self._haupt_muster()}",
            "description": beschreibung,
        }
        for feld, schluessel in (("team_id", "web_rbl.ticket_team_id"),
                                 ("category_id", "web_rbl.ticket_kategorie_id"),
                                 ("user_id", "web_rbl.ticket_bearbeiter_id")):
            wert = Parameter.get_param(schluessel)
            if wert and feld in Ticket._fields:
                try:
                    werte[feld] = int(wert)
                except (TypeError, ValueError):
                    pass

        # OHNE BENACHRICHTIGUNG ANLEGEN.
        #
        # Ein Ticket, das beim Anlegen Post verschickt, waere hier
        # genau falsch: Es gibt keinen Kunden, der etwas davon hat,
        # und der Befund ist eine INTERNE Arbeitsnotiz. Kein
        # partner_id, keine Abonnenten, kein Protokolleintrag.
        ticket = Ticket.with_context(
            mail_create_nosubscribe=True,
            mail_create_nolog=True,
            mail_notrack=True,
            tracking_disable=True,
        ).create(werte)
        self.write({
            "ticket_modell": modellname,
            "ticket_id": ticket.id,
            "ticket_nummer": (
                getattr(ticket, "number", False)
                or getattr(ticket, "display_name", False) or str(ticket.id)),
            "ticket_gemeldet_am": self.zuletzt,
        })
        _logger.info("Web RBL: Ticket %s zu Befund %s angelegt.",
                     ticket.id, self.adresse)
        return ticket

    def action_ticket_oeffnen(self):
        self.ensure_one()
        if not self.ticket_id or not self.ticket_modell:
            raise UserError(_("Zu diesem Eintrag gibt es kein Ticket."))
        if self.ticket_modell not in self.env:
            raise UserError(_(
                "Das Ticketmodell %s ist hier nicht installiert.",
                self.ticket_modell))
        return {
            "type": "ir.actions.act_window",
            "res_model": self.ticket_modell,
            "res_id": self.ticket_id,
            "view_mode": "form",
        }

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
    host = fields.Char(
        string="Domain", readonly=True, index=True,
        help="Welche unserer Webseiten angesprochen wurde. Das "
             "Zugriffsprotokoll von werkzeug enthält den Host nicht -- "
             "er ist nur hier, zur Laufzeit, zu bekommen.")
    tag = fields.Date(string="Tag", required=True, index=True)
