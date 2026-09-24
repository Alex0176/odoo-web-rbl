# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Erkennung und Abweisung, so früh wie möglich im Anfrageweg.

WARUM ``_match`` UND NICHT ``_pre_dispatch``
--------------------------------------------
``_pre_dispatch`` läuft erst, wenn die Wegfindung eine Route gefunden
hat. Sondierungen zielen aber auf Pfade, die es nicht gibt -- für die
wird ``_pre_dispatch`` nie aufgerufen. ``_match`` dagegen läuft bei
JEDER Anfrage (odoo/http.py:2285), vor der Auflösung.

WAS ES SPART
------------
Heute kostet eine Sonde auf ``/@fs/../../.env`` eine vollständige
Seitendarstellung: Odoo sucht die Fehlerseite, rendert sie, stolpert
beim Bauen der ``og:url`` über die Punkt-Segmente und rendert daraufhin
auch die Fehlerseite der Fehlerseite nicht. Zwei Stapelprotokolle je
Sonde. Gemessen: 28.401 solcher Fehler in siebzehn Tagen, dazu 9.467
Folgefehler beim Rendern.

Hier fällt die Antwort vor der Wegfindung -- ohne Vorlage, ohne
Datenbankzugriff über die Sperrprüfung hinaus, ohne Protokollzeile.
"""

import logging
import re

from werkzeug.exceptions import Forbidden

from odoo import models
from odoo.http import request

_logger = logging.getLogger(__name__)

# Muster, die eindeutig nach Sondierung aussehen. Bewusst eng gefasst:
# Ein falsch erkannter Besucher ist teurer als eine übersehene Sonde.
MUSTER = (
    ("traversal", re.compile(
        r"(\.\./|\.\.%2f|%2e%2e|%252e|\.\.\\)", re.I)),
    ("dotenv", re.compile(
        r"(^|/)\.env(\.|$|\?)|/\.env[a-z.]*$", re.I)),
    ("vcs", re.compile(
        r"(^|/)\.(git|svn|hg)(/|$)", re.I)),
    ("wordpress", re.compile(
        r"(^|/)(wp-admin|wp-includes|wp-content|wp-login|xmlrpc\.php)", re.I)),
    ("php", re.compile(
        r"\.(php[0-9]?|phtml|asp|aspx|jsp|cgi)($|\?)", re.I)),
    ("dbtool", re.compile(
        r"(^|/)(phpmyadmin|pma|adminer|mysqladmin)(/|$)", re.I)),
    ("shell", re.compile(
        r"(^|/)(shell|cmd|backdoor|c99|r57)\.", re.I)),
    ("konfig", re.compile(
        r"(^|/)(config\.(json|yml|yaml|ini|bak)|\.aws/|\.ssh/|id_rsa)", re.I)),
)


class IrHttp(models.AbstractModel):
    _inherit = "ir.http"

    @classmethod
    def _match(cls, path_info):
        """Vor der Wegfindung: gesperrt? sondierend?"""
        try:
            antwort = cls._rbl_pruefen(path_info)
        except Exception:  # noqa: BLE001
            # DIESE ZEILE IST DIE WICHTIGSTE DER DATEI.
            #
            # Was hier auch schiefgeht -- ein Datenbankfehler, ein
            # kaputtes Muster, eine fehlende Tabelle --, es darf die
            # Anfrage nicht aufhalten. Ein Schutzmodul, das bei einem
            # eigenen Fehler die Webseite mitnimmt, ist schlimmer als
            # gar keines.
            _logger.exception("Web RBL: Pruefung gescheitert, Anfrage laeuft "
                              "unveraendert weiter.")
            antwort = None
        if antwort is not None:
            raise antwort
        return super()._match(path_info)

    # ------------------------------------------------------------------
    @classmethod
    def _rbl_pruefen(cls, path_info):
        """Gibt die abzuweisende Antwort zurück, oder None."""
        if not request or not request.env:
            return None
        Parameter = request.env["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.aktiv", "1") != "1":
            return None

        Herkunft = request.env["web.rbl.herkunft"].sudo()
        adresse = Herkunft.adresse()
        if not adresse or not Herkunft.sperrbar(adresse):
            return None

        Eintrag = request.env["web.rbl.eintrag"].sudo()
        sperren = Parameter.get_param("web_rbl.sperren_aktiv", "0") == "1"
        muster = cls._rbl_muster(path_info)

        # 1. IST DIESE ANFRAGE SELBST EINE SONDE?
        #
        # Die wird IMMER abgewiesen, auch im Beobachtungsbetrieb. Das
        # ist kein Sperren, sondern eine Antwort auf eine Anfrage, die
        # es nicht besser verdient: Niemand ruft versehentlich
        # ``/@fs/../../.env`` auf. Und genau hier liegt der Gewinn --
        # eine Sonde kostet damit ein 403 statt einer vollstaendigen
        # Fehlerseite mit zwei Stapelprotokollen.
        if muster:
            Eintrag.treffer_eigene_transaktion(adresse, path_info, muster)
            return cls._rbl_abweisen(Parameter)

        # 2. EINE GEWOEHNLICHE ANFRAGE VON EINER GELISTETEN ADRESSE.
        #
        # Sie zu blockieren ist der eigentliche Eingriff -- und deshalb
        # geschieht er nur, wenn das Sperren ausdruecklich eingeschaltet
        # ist. Im Beobachtungsbetrieb laeuft sie durch.
        #
        # Diese Unterscheidung war im ersten Entwurf nicht da, und sie
        # fehlte an genau der falschen Stelle: Nach der ersten Sonde
        # bekam dieselbe Adresse auf ``/web/login`` ebenfalls ein 403,
        # obwohl das Sperren auf "aus" stand. Wer den Beobachtungs-
        # betrieb waehlt, will beobachten, nicht heimlich sperren.
        if not sperren:
            return None
        if Eintrag.ist_gesperrt(adresse):
            return cls._rbl_abweisen(Parameter)
        return None

    @classmethod
    def _rbl_muster(cls, pfad):
        """Der Name des ersten zutreffenden Musters, sonst ""."""
        pfad = pfad or ""
        for name, regel in MUSTER:
            if regel.search(pfad):
                return name
        return ""

    # ------------------------------------------------------------------
    # Die Antwort
    # ------------------------------------------------------------------
    @classmethod
    def _rbl_abweisen(cls, Parameter):
        """Wie auf eine gesperrte Adresse geantwortet wird."""
        art = Parameter.get_param("web_rbl.antwort", "leise")
        if art == "forbidden":
            return Forbidden()
        return cls._rbl_leise()

    @classmethod
    def _rbl_leise(cls):
        """Ein schlichtes 403 ohne Vorlage.

        WARUM 403 UND NICHT 404 -- EIN IRRTUM UND SEINE KORREKTUR
        ----------------------------------------------------------
        Der erste Entwurf gab ``NotFound`` zurück, mit der Begründung,
        ein 404 sei für einen Scanner die langweiligere Antwort als ein
        403. Die Überlegung stimmt, der Weg dorthin nicht.

        Gemessen: Odoo behandelt ein ``NotFound`` aus der Wegfindung
        nicht als fertige Antwort, sondern als "keine Route gefunden --
        probiere den Rückfall". Es landet in ``_serve_ir_http_fallback``
        -> ``_serve_fallback()``, und das ist genau der teure Pfad mit
        Vorlagensuche und Stapelprotokoll, den dieses Modul vermeiden
        soll. Die Sonden kamen damit weiterhin als 500 zurück.

        ``Forbidden`` dagegen ist eine ECHTE Antwort: Odoo reicht sie
        durch, es gibt keinen Rückfall, keine Vorlage, kein Protokoll.
        Der Scanner erfährt damit zwar, dass hier etwas geschützt ist --
        das ist der Preis, und er ist ihn wert.
        """
        return Forbidden()
