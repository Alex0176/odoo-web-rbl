# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Gescheiterte Anmeldungen in die Sperrliste.

WARUM ODOOS EIGENE SPERRE NICHT GENUEGT
----------------------------------------
Odoo zaehlt Fehlversuche selbst und laesst nach
``base.login_cooldown_after`` eine Pause von
``base.login_cooldown_duration`` Sekunden eintreten. Das ist besser
als nichts und hat drei Grenzen, die im Odoo-Quelltext selbst stehen:

1. Der Zaehler liegt in ``registry._login_failures``, einem
   Woerterbuch im Arbeitsspeicher. Der Kommentar dort lautet
   woertlich "not shared between workers" -- und JEDER NEUSTART setzt
   ihn zurueck. Am 25.09.2026 haben wir sechsmal neu gestartet.
2. Er SPERRT nicht, er verzoegert. Nach sechzig Sekunden geht es
   weiter; dauerhaft wird daraus nie etwas.
3. Er zaehlt nur, was bis zur Kennwortpruefung durchkommt.

Dieses Modul haengt sich an dieselbe Stelle, schreibt aber in die
Datenbank: Der Stand uebersteht den Neustart, die Frist ist dieselbe
wie bei jeder anderen Sonde, und die Freiliste gilt auch hier.

WARUM ``_login`` UND NICHT DER CONTROLLER
------------------------------------------
``_login`` ist die Stelle, durch die BEIDE Wege laufen: die
Anmeldemaske unter ``/web/login`` und die Schnittstelle unter
``/xmlrpc/2/common``. Am Controller haetten wir nur den ersten.

Gemessen ueber siebzehn Tage: neun gescheiterte Web-Anmeldungen --
und eine Adresse mit 25 XML-RPC-Anmeldungen in sechs Minuten. Wer nur
die Maske absichert, sichert den kleineren Teil.

WARUM MIT SCHWELLE
------------------
Von den neun gescheiterten Web-Anmeldungen kamen FUENF von Kunden,
die sich den Zugang selbst auf einem weiteren Geraet einrichteten und
dabei die falsche Domain eintrugen -- einmal die eigene, nur mit
Bindestrich statt Punkt. Eine Sperre beim ersten Fehlversuch haette
also nicht Angreifer getroffen, sondern Kunden bei der Einrichtung. Deshalb
``web_rbl.schwelle.anmeldung`` (Vorgabe 10, wie bei Odoo selbst):
verbucht wird ab dem ersten, gesperrt ab dem zehnten.
"""
import logging

from odoo import models
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)

MUSTER = "anmeldung"


class ResUsers(models.Model):
    _inherit = "res.users"

    def _login(self, credential, user_agent_env):
        # ANMELDUNG GANZ VERBIETEN, wenn die Adresse dafuer gesperrt ist.
        #
        # Die Pfadliste in ir_http haelt solche Adressen schon von der
        # Anmeldemaske fern. Das ist billig und frueh, aber es haengt
        # daran, dass die Liste vollstaendig ist -- und eine
        # Pfadliste ist nie vollstaendig. Ein Modul, eine neue
        # Odoo-Fassung, ein Fremdcontroller, und es gibt einen Weg,
        # den niemand aufgeschrieben hat.
        #
        # Hier dagegen ist es einfach: Eine Anmeldung ist eine
        # Anmeldung, egal welche Adresse sie aufgerufen hat. Alle Wege
        # laufen durch diese Methode -- die Maske, XML-RPC, JSON-RPC.
        #
        # Das Kennwort wird dabei gar nicht erst geprueft. Wer nicht
        # anklopfen darf, soll auch nicht erfahren, ob er das richtige
        # Kennwort geraten hat.
        try:
            self._rbl_anmeldung_erlaubt()
        except AccessDenied:
            raise
        except Exception:  # noqa: BLE001
            # Ein Fehler in UNSERER Pruefung darf niemanden aussperren.
            _logger.exception(
                "Web RBL: Anmeldepruefung gescheitert, Anmeldung laeuft "
                "unveraendert weiter.")
        try:
            ergebnis = super()._login(credential, user_agent_env)
        except AccessDenied:
            # Die eigentliche Arbeit ist gekapselt und faengt alles ab:
            # Eine gescheiterte Anmeldung muss als gescheiterte
            # Anmeldung enden, nicht als Serverfehler. Wer sich
            # vertippt, soll die gewohnte Meldung sehen -- und ein
            # Fehler in UNSERER Buchhaltung darf daran nichts aendern.
            try:
                self._rbl_fehlversuch_verbuchen(credential)
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "Web RBL: Fehlversuch konnte nicht verbucht werden.")
            raise

        # HIER IST DIE ANMELDUNG GELUNGEN.
        #
        # Und genau das macht diesen Fall zum wertvollsten des ganzen
        # Moduls: Eine GESCHEITERTE Anmeldung von einer auffaelligen
        # Adresse ist Laerm -- jemand probiert, wie tausend andere
        # auch. Eine GELUNGENE von derselben Adresse heisst, dass
        # jemand das Kennwort HAT.
        #
        # Dafuer gibt es genau zwei Erklaerungen: Der berechtigte
        # Benutzer sitzt gerade hinter einer auffaelligen Adresse --
        # Hotel-WLAN, Tor, ein Anschluss, den vorher jemand anderes
        # hatte --, oder die Zugangsdaten sind abhandengekommen.
        #
        # Beides will man wissen, und beides will man von einem
        # Menschen beurteilt haben. Deshalb wird gemeldet und NICHT
        # gesperrt: Wer hier automatisch aussperrt, sperrt irgendwann
        # den Geschaeftsfuehrer aus einem Hotel aus.
        try:
            self._rbl_gelungene_anmeldung_pruefen(credential, ergebnis)
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Pruefung der gelungenen Anmeldung gescheitert.")
        return ergebnis

    def _rbl_gelungene_anmeldung_pruefen(self, credential, auth_info):
        """Eine gelungene Anmeldung von einer auffälligen Adresse.

        Gemeldet wird nur, wenn die Zugangsdaten GÜLTIG waren. Der
        Unterschied ist der ganze Befund: Ein Fehlversuch sagt, dass
        jemand raten wollte. Ein Erfolg sagt, dass jemand nicht mehr
        raten muss.
        """
        if not request:
            return
        Parameter = self.env["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.aktiv", "1") != "1":
            return
        if Parameter.get_param("web_rbl.verdacht_aktiv", "1") != "1":
            return

        Herkunft = self.env["web.rbl.herkunft"].sudo()
        adresse = Herkunft.adresse()
        if not adresse or not Herkunft.sperrbar(adresse):
            return
        if self.env["web.rbl.freiliste"].sudo().ist_frei(adresse):
            return

        # Woran erkennen wir "auffaellig"? An allem, was wir haben.
        gruende = []
        fremd = self.env["web.rbl.fremdliste"].sudo()
        stufe = fremd.stufe_fuer(adresse)
        if stufe:
            quellen = ", ".join(
                fremd.quellen_zu(adresse).mapped("quelle_id.name")) or "unbekannt"
            gruende.append(f"steht auf fremder Bedrohungsliste ({quellen})")

        Eintrag = self.env["web.rbl.eintrag"].sudo()
        eintrag = Eintrag.search([("adresse", "=", adresse)], limit=1)
        if eintrag and eintrag.zustand != "frei":
            try:
                schwelle = int(Parameter.get_param(
                    "web_rbl.verdacht_ab_bewertung", "10"))
            except (TypeError, ValueError):
                schwelle = 10
            if schwelle and (eintrag.bewertung or 0) >= schwelle:
                gruende.append(
                    f"eigene Bewertung {eintrag.bewertung} "
                    f"({eintrag.bewertung_grund or ''})")
        if not gruende:
            return

        benutzer = ""
        try:
            benutzer = str(credential.get("login") or "")[:80]
        except Exception:  # noqa: BLE001
            benutzer = ""
        # Das Kennwort wird nirgends beruehrt -- weder gelesen noch
        # vermerkt. Der Befund ist, DASS es gestimmt hat.
        _logger.warning(
            "Web RBL: GELUNGENE Anmeldung von auffaelliger Adresse %s "
            "als '%s' -- %s. Zugangsdaten moeglicherweise abhandengekommen.",
            adresse, benutzer or "?", "; ".join(gruende))
        self._rbl_verdacht_melden(adresse, benutzer, gruende, auth_info)

    def _rbl_verdacht_melden(self, adresse, benutzer, gruende, auth_info):
        """Den Verdacht festhalten -- intern, nie beim Kunden."""
        Parameter = self.env["ir.config_parameter"].sudo()
        Eintrag = self.env["web.rbl.eintrag"].sudo()
        try:
            pfad = request.httprequest.path or ""
            host = (request.httprequest.host or "")[:120]
            kennung = (request.httprequest.headers.get("User-Agent")
                       or "")[:255]
        except Exception:  # noqa: BLE001
            pfad, host, kennung = "", "", ""

        # Als Meldung verbuchen, nie als Sperre: Solange nicht geklaert
        # ist, ob der berechtigte Benutzer nur unterwegs war, waere
        # eine Sperre die falsche Antwort -- sie traefe ihn.
        Eintrag.treffer_eigene_transaktion(
            adresse, f"{pfad} (gelungene Anmeldung als {benutzer})"[:255],
            "anmeldung_verdacht", host, "melden", kennung)

        # Eine interne Aufgabe fuer die, die es beurteilen koennen.
        empfaenger = (Parameter.get_param("web_rbl.verdacht_melden_an")
                      or "").strip()
        if not empfaenger:
            return
        try:
            kennungen = [int(t) for t in empfaenger.replace(",", " ").split()]
        except (TypeError, ValueError):
            return
        benutzer_satz = self.env["res.users"].sudo().browse(kennungen).exists()
        if not benutzer_satz:
            return
        eintrag = Eintrag.search([("adresse", "=", adresse)], limit=1)
        if not eintrag:
            return
        modell = self.env["ir.model"]._get_id("web.rbl.eintrag")
        for empf in benutzer_satz:
            self.env["mail.activity"].sudo().create({
                "res_model_id": modell,
                "res_id": eintrag.id,
                "activity_type_id": self.env.ref(
                    "mail.mail_activity_data_todo").id,
                "summary": f"Verdacht: Anmeldung als {benutzer} von {adresse}",
                "note": (
                    f"<p>Von dieser Adresse hat sich jemand <b>erfolgreich</b> "
                    f"als <b>{benutzer}</b> angemeldet.</p>"
                    f"<p>Die Adresse ist auffällig: {'; '.join(gruende)}</p>"
                    f"<p>Entweder war der berechtigte Benutzer unterwegs "
                    f"(Hotel, Tor, wechselnder Anschluss) &mdash; oder die "
                    f"Zugangsdaten sind abhandengekommen. Bitte beim "
                    f"Benutzer nachfragen, bevor etwas gesperrt wird.</p>"
                    f"<p><i>Das Kennwort wurde nirgends vermerkt.</i></p>"),
                "user_id": empf.id,
            })

    def _rbl_anmeldung_erlaubt(self):
        """Darf sich von dieser Adresse ueberhaupt jemand anmelden?"""
        if not request:
            return
        Parameter = self.env["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.aktiv", "1") != "1":
            return
        Herkunft = self.env["web.rbl.herkunft"].sudo()
        adresse = Herkunft.adresse()
        if not adresse:
            return
        # Die Freiliste gewinnt auch hier. Wer bei uns als Kunde oder
        # Gegenstelle gefuehrt wird, meldet sich an, Punkt.
        if self.env["web.rbl.freiliste"].sudo().ist_frei(adresse):
            return
        grund = ""
        stufe = self.env["web.rbl.fremdliste"].sudo().stufe_fuer(adresse)
        if stufe in ("kein_backend", "sperren"):
            grund = f"fremde Bedrohungsliste, Stufe {stufe}"

        # AB WELCHER BEWERTUNG KEINE ANMELDUNG MEHR?
        #
        # Gemessen an allen 50 Eintraegen der Produktion am
        # 25.09.2026:
        #     ab 30: 18 Adressen, davon 0 freigegeben
        #     ab 40:  6 Adressen, davon 0 freigegeben
        #     ab 50:  1 Adresse
        # Die drei freigegebenen Kundenadressen liegen bei 12, die
        # Fehlkonfiguration bei 0. Ab 30 stehen dort ausschliesslich
        # Rechenzentrums-Scanner mit .env-, .git- und
        # Konfigurationssonden.
        #
        # Die Vorgabe ist trotzdem 40 und nicht 30, und zwar wegen
        # eines Risikos, das in unseren Daten NICHT sichtbar ist:
        # geteilte Adressen. Hinter einer Bueroadresse kann neben
        # zwanzig Mitarbeitern ein befallener Rechner sitzen. Bei 30
        # genuegt dessen einzelne .env-Sonde, um das ganze Buero von
        # der Anmeldung auszuschliessen; bei 40 braucht es zwei
        # verschiedene Muster oder Beharrlichkeit ueber Tage.
        #
        # 0 schaltet die Regel ab.
        if not grund:
            eintrag = self.env["web.rbl.eintrag"].sudo().search(
                [("adresse", "=", adresse)], limit=1)
            if eintrag:
                # Eine Freigabe von Hand zaehlt mehr als jede Zahl.
                # Wer sie erteilt hat, hatte einen Grund.
                if eintrag.zustand == "frei":
                    return
                if eintrag.zustand == "hochrisiko":
                    grund = "Koederanbiss"
                else:
                    try:
                        schwelle = int(Parameter.get_param(
                            "web_rbl.anmeldung_ab_bewertung", "40"))
                    except (TypeError, ValueError):
                        schwelle = 40
                    if schwelle and (eintrag.bewertung or 0) >= schwelle:
                        grund = (f"Bewertung {eintrag.bewertung} "
                                 f"(Schwelle {schwelle}): "
                                 f"{eintrag.bewertung_grund or ''}")

        if grund:
            _logger.info(
                "Web RBL: Anmeldung von %s abgelehnt -- %s", adresse, grund)
            # Dieselbe Meldung wie bei einem falschen Kennwort. Wer
            # abgewiesen wird, soll nicht erfahren, WARUM -- sonst
            # weiss er, dass er nur die Adresse wechseln muss.
            raise AccessDenied()

    def _on_login_cooldown(self, failures, previous):
        """Wer trotz Abkühlung weiterklopft, liest die Meldung nicht.

        DAS IST DAS SCHÄRFERE SIGNAL
        -----------------------------
        Ein falsches Kennwort ist mehrdeutig: Von neun gescheiterten
        Anmeldungen in siebzehn Tagen waren acht Tippfehler eigener
        Mitarbeiter. Deshalb die Schwelle von zehn.

        Was danach kommt, ist es nicht mehr. Odoo antwortet ab dem
        zehnten Fehlversuch mit „Too many login failures, please wait
        a bit before trying again" und lässt sechzig Sekunden
        verstreichen. Ein Mensch liest das und wartet. Wer in dieser
        Minute weiterklopft, hat die Meldung nicht gelesen -- weil ihn
        niemand liest.

        Deshalb ein EIGENES Muster mit Schwelle null: Dieser Treffer
        sperrt sofort. Er kann keinen Kollegen versehentlich treffen,
        denn um überhaupt hierher zu kommen, muss man bereits zehn
        Fehlversuche hinter sich haben UND danach weitermachen.

        Odoos Dokumentation lädt zu dieser Erweiterung ausdrücklich
        ein: „Can be overridden to implement more complex backoff
        strategies."
        """
        in_abkuehlung = super()._on_login_cooldown(failures, previous)
        if in_abkuehlung:
            try:
                self._rbl_fehlversuch_verbuchen(
                    {"login": "(waehrend der Abkuehlung)"},
                    muster="anmeldung_bot")
            except Exception:  # noqa: BLE001
                _logger.exception(
                    "Web RBL: Abkuehlungsversuch nicht verbucht.")
        return in_abkuehlung

    def _rbl_fehlversuch_verbuchen(self, credential, muster=MUSTER):
        # WARUM HIER EINE DIAGNOSEZEILE STEHT
        #
        # Am 25.09.2026 griff dieser Haken bei der Anmeldemaske, aber
        # NICHT bei ``/xmlrpc/2/common`` -- ausgerechnet dem Weg, den
        # der gemessene Angreifer benutzt hat (25 Versuche in sechs
        # Minuten). Die Ursache liess sich nicht erraten: Die Methode
        # bricht an fuenf verschiedenen Stellen still ab, und von
        # aussen sieht jedes Mal dasselbe aus, naemlich nichts.
        #
        # ``exp_authenticate`` baut fuer RPC eine EIGENE Umgebung
        # (``Registry(db).cursor()``, uid=None), also gilt hier nichts
        # von dem, was im Anfrageweg selbstverstaendlich ist.
        #
        # Die Zeile laeuft nur bei einer GESCHEITERTEN Anmeldung --
        # gemessen neun Stueck in siebzehn Tagen. Sie kostet also
        # nichts und beantwortet beim naechsten Versuch in einem Blick,
        # wo es hakt.
        def abbruch(grund):
            _logger.info(
                "Web RBL: Fehlversuch NICHT verbucht (%s). "
                "request=%s, uid=%s", grund, bool(request), self.env.uid)

        if not request:
            # Ohne Anfrage gibt es keine Adresse -- etwa bei einem
            # Aufruf aus einem geplanten Vorgang oder einem Test.
            abbruch("keine Anfrage gebunden")
            return
        Parameter = self.env["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.aktiv", "1") != "1":
            abbruch("Modul abgeschaltet")
            return
        if Parameter.get_param("web_rbl.anmeldung_aktiv", "1") != "1":
            abbruch("Anmeldeueberwachung abgeschaltet")
            return

        Herkunft = self.env["web.rbl.herkunft"].sudo()
        adresse = Herkunft.adresse()
        if not adresse:
            abbruch("Adresse nicht bestimmbar")
            return
        if not Herkunft.sperrbar(adresse):
            abbruch(f"Adresse {adresse} ist nicht sperrbar")
            return

        stufe = Parameter.get_param(f"web_rbl.muster.{muster}", "sperren")
        if stufe not in ("sperren", "zaehlen", "melden"):
            stufe = "sperren"

        # Der Pfad sagt, WELCHER Weg es war -- Maske oder
        # Schnittstelle. Das ist der Unterschied zwischen einem
        # Mitarbeiter am Anmeldefenster und einem Skript.
        try:
            pfad = request.httprequest.path or ""
            host = (request.httprequest.host or "")[:120]
            kennung = (request.httprequest.headers.get("User-Agent")
                       or "")[:255]
        except Exception:  # noqa: BLE001
            pfad, host, kennung = "", "", ""

        # Der Benutzername gehoert MIT in den Vermerk, aber nie das
        # Kennwort. Wer "Florida2026" als Benutzernamen eintraegt, hat
        # sein Kennwort ins falsche Feld getippt -- das sieht man nur,
        # wenn der Name da steht, und es ist der Unterschied zwischen
        # einem Angriff und einem Kollegen.
        benutzer = ""
        try:
            benutzer = str(credential.get("login") or "")[:80]
        except Exception:  # noqa: BLE001
            benutzer = ""
        vermerk = f"{pfad} (Benutzer: {benutzer})" if benutzer else pfad

        # SCHON GESPERRT? DANN NICHT NOCH EINMAL.
        #
        # Ein Bot, der weiterklopft, wuerde sonst je Versuch eine
        # zusaetzliche Datenbankverbindung oeffnen. Genau daran ist am
        # 25.09.2026 um 05:57 schon einmal der Verbindungspool
        # erstickt: 195 Sonden in einer Minute, 28 gescheiterte
        # Anfragen. Die Sperre steht, die Frist laeuft -- ein weiterer
        # Treffer bringt nichts und kostet.
        Eintrag = self.env["web.rbl.eintrag"].sudo()
        if Eintrag.ist_gesperrt(adresse):
            return

        # EIGENE TRANSAKTION, wie bei jeder anderen Verbuchung:
        # Die Anfrage endet mit einer Zugriffsverweigerung, und was in
        # ihrer Transaktion steht, wird dabei zurueckgerollt.
        Eintrag.treffer_eigene_transaktion(
            adresse, vermerk[:255], muster, host, stufe, kennung)
        _logger.info(
            "Web RBL: Fehlversuch verbucht -- %s auf %s (Benutzer: %s).",
            adresse, pfad or "?", benutzer or "?")
