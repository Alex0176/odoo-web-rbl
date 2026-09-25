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
Von den neun gescheiterten Web-Anmeldungen waren acht Tippfehler
eigener Mitarbeiter; einer hat sein Kennwort ins Benutzerfeld
getippt. Eine Sperre beim ersten Fehlversuch haette also fast
ausschliesslich Kollegen getroffen. Deshalb
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
        try:
            return super()._login(credential, user_agent_env)
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
