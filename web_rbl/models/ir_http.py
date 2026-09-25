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
#
# WELCHE MUSTER NUR ZÄHLEN UND WELCHE SPERREN
# --------------------------------------------
# Nicht jedes Muster trägt dieselbe Beweislast. ``/.env`` oder
# ``/wp-admin`` ruft niemand versehentlich auf -- ``..`` im Pfad dagegen
# schon: Es genügt, dass ein fremder Webmaster ein Bild relativ falsch
# verlinkt (``/bilder/../logo.png``), und jeder Besucher SEINER Seite
# landet bei uns auf der Sperrliste. Ein Tippfehler, kein Angriff.
#
# Deshalb steht bei jedem Muster, ob es sperrt oder nur zählt, und die
# Vorgabe lässt sich je Muster über einen Systemparameter umstellen:
#
#     web_rbl.muster.traversal = zaehlen | sperren
#
# ``traversal_ziel`` ist die Ausnahme: Verzeichniswechsel ZUSAMMEN mit
# einer lohnenden Zieldatei. Diese Verbindung hat keine harmlose
# Lesart, und sie ist der Fall, der in unseren Protokollen tatsächlich
# vorkommt (``/@fs/../../.env``).
SPERREN, ZAEHLEN = "sperren", "zaehlen"

MUSTER = (
    ("traversal_ziel", SPERREN, re.compile(
        r"(\.\.(/|%2f|%252f|\\)+)[^?]*"
        r"(\.env|\.git|\.aws|\.ssh|passwd|shadow|id_rsa|"
        r"environ|config\.|credentials|\.pem)", re.I)),
    ("traversal", ZAEHLEN, re.compile(
        r"(\.\./|\.\.%2f|%2e%2e|%252e|\.\.\\)", re.I)),
    ("dotenv", SPERREN, re.compile(
        r"(^|/)\.env(\.|$|\?)|/\.env[a-z.]*$", re.I)),
    ("vcs", SPERREN, re.compile(
        r"(^|/)\.(git|svn|hg)(/|$)", re.I)),
    ("wordpress", SPERREN, re.compile(
        r"(^|/)(wp-admin|wp-includes|wp-content|wp-login|xmlrpc\.php)", re.I)),
    ("php", SPERREN, re.compile(
        r"\.(php[0-9]?|phtml|asp|aspx|jsp|cgi)($|\?)", re.I)),
    ("dbtool", SPERREN, re.compile(
        r"(^|/)(phpmyadmin|pma|adminer|mysqladmin)(/|$)", re.I)),
    ("shell", SPERREN, re.compile(
        r"(^|/)(shell|cmd|backdoor|c99|r57)\.", re.I)),
    ("konfig", SPERREN, re.compile(
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

        # 0. HAT JEMAND EINEN KANARIENWERT ABGERUFEN?
        #
        # Das steht VOR der Mustererkennung, weil es die schärfere
        # Aussage ist. Ein Kanarienpfad existiert nur in einer von uns
        # ausgelieferten Fälschung -- wer ihn abruft, hat gelesen und
        # gehandelt. Fehlalarm ausgeschlossen.
        Koeder = request.env["web.rbl.koeder"].sudo()
        angebissen = Koeder.anbiss_pruefen(path_info, adresse)
        if angebissen:
            cls._rbl_hochrisiko(adresse, angebissen)
            return cls._rbl_abweisen(Parameter)

        muster, stufe = cls._rbl_muster(path_info, Parameter)

        # 1. IST DIE ADRESSE SCHON GESPERRT? DANN SOFORT UND BILLIG.
        #
        # Diese Abfrage steht hier, weil das Verbuchen darunter eine
        # EIGENE Datenbankverbindung öffnet. Am 25.09.2026 um 05:57 hat
        # eine einzelne Adresse 195 Sonden in einer Minute geschickt --
        # also 195 zusätzliche Verbindungen. Der Verbindungspool war
        # erschöpft, und danach scheiterten 28 Anfragen mit
        # ``PoolError: The Connection Pool Is Full``. Darunter waren
        # ECHTE BESUCHER, denn sie teilen sich denselben Pool.
        #
        # Das Abwehrmodul hat den Angriff damit in eine Störung
        # verwandelt -- genau das, was es verhindern soll. Der Angreifer
        # kam nicht herein, aber er hat die Seite lahmgelegt.
        #
        # Ist die Adresse bereits gesperrt, ist alles Nötige bekannt.
        # Jeder weitere Treffer kostet eine Verbindung und bringt
        # nichts: Die Sperre steht, die Frist läuft, die Muster sind
        # erfasst. Also wird hier abgewiesen, ohne zu verbuchen.
        #
        # Die Abfrage selbst läuft auf dem Cursor der Anfrage und kostet
        # keine zusätzliche Verbindung.
        if Eintrag.ist_gesperrt(adresse):
            if sperren or muster:
                return cls._rbl_abweisen(Parameter)
            return None

        # 2. IST DIESE ANFRAGE SELBST EINE SONDE?
        #
        # Wer sperrt, wird immer abgewiesen -- auch im
        # Beobachtungsbetrieb. Das ist kein Sperren, sondern eine
        # Antwort auf eine Anfrage, die es nicht besser verdient:
        # Niemand ruft versehentlich ``/@fs/../../.env`` auf.
        #
        # Wer nur ZÄHLT, wird verbucht und durchgelassen. Das ist der
        # Fall ``traversal``: Ein fremder Webmaster mit einem falsch
        # gesetzten relativen Bildpfad soll seine Besucher nicht bei uns
        # aussperren. Der Treffer steht trotzdem in der Liste -- so
        # lässt sich nachsehen, was da eigentlich hereinkommt, bevor man
        # ihn scharf schaltet.
        if muster:
            Eintrag.treffer_eigene_transaktion(adresse, path_info, muster)
            if stufe != SPERREN:
                return None
            # Köder statt Abweisung -- nur wenn eingeschaltet und die
            # Obergrenze je Adresse noch nicht erreicht ist.
            koeder = cls._rbl_koeder(adresse, path_info, muster)
            if koeder is not None:
                return koeder
            return cls._rbl_abweisen(Parameter)

        # 3. Eine gewoehnliche Anfrage von einer noch nicht gesperrten
        #    Adresse: nichts zu tun. Der Fall "gelistet" ist oben unter
        #    Punkt 1 bereits erledigt.
        return None

    @classmethod
    def _rbl_muster(cls, pfad, Parameter=None):
        """(Name, Stufe) des ersten zutreffenden Musters, sonst ("", "").

        Die Reihenfolge in ``MUSTER`` entscheidet: ``traversal_ziel``
        steht vor ``traversal``, damit ``/@fs/../../.env`` als das
        schärfere von beiden erkannt wird und nicht als der harmlose
        Verzeichniswechsel.

        Die Stufe je Muster lässt sich über einen Systemparameter
        umstellen, ohne den Code anzufassen::

            web_rbl.muster.traversal  = sperren
            web_rbl.muster.php        = zaehlen
        """
        pfad = pfad or ""
        for name, vorgabe, regel in MUSTER:
            if not regel.search(pfad):
                continue
            stufe = vorgabe
            if Parameter is not None:
                gesetzt = Parameter.get_param(f"web_rbl.muster.{name}")
                if gesetzt in (SPERREN, ZAEHLEN):
                    stufe = gesetzt
            return name, stufe
        return "", ""

    # ------------------------------------------------------------------
    # Die Antwort
    # ------------------------------------------------------------------
    @classmethod
    def _rbl_hochrisiko(cls, adresse, koeder):
        """Den Anbiss in einer eigenen Transaktion festhalten.

        Wie beim Treffer: Die Anfrage bricht gleich mit ``Forbidden``
        ab, und deren Transaktion wird zurückgerollt. Ohne eigenen
        Cursor wäre die wichtigste Erkenntnis des ganzen Moduls die
        einzige, die verlorengeht.
        """
        try:
            Eintrag = request.env["web.rbl.eintrag"].sudo()
            Eintrag.hochrisiko_eigene_transaktion(adresse, koeder.kanarie)
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Hochrisiko fuer %s konnte nicht vermerkt werden.",
                adresse)

    @classmethod
    def _rbl_koeder(cls, adresse, pfad, muster):
        """Eine Köderantwort, oder None.

        Gibt eine fertige Antwort zurück; der Aufrufer reicht sie als
        Ausnahme weiter, damit sie wie jede andere Abweisung den
        teuren Weg über die Webseitenvorlagen umgeht.
        """
        Koeder = request.env["web.rbl.koeder"].sudo()
        gebaut = Koeder.auslegen(adresse, pfad, muster)
        if not gebaut:
            return None
        inhalt, typ = gebaut
        from werkzeug.wrappers import Response as WerkzeugResponse
        from werkzeug.exceptions import HTTPException

        class _Koederantwort(HTTPException):
            """Eine 200er-Antwort im Gewand einer Ausnahme.

            ``_match`` kann nur durch eine Ausnahme aus dem normalen
            Weg ausbrechen. Eine HTTPException mit eigener Antwort ist
            der vorgesehene Weg dafür -- Odoo reicht sie unverändert
            durch, ohne Vorlage und ohne Protokollzeile.
            """
            code = 200

            def get_response(self, environ=None, scope=None):
                return WerkzeugResponse(
                    inhalt, status=200, content_type=typ)

        return _Koederantwort()

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
