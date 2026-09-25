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
#
# DIE DRITTE STUFE: MELDEN
# -------------------------
# Zwischen "sperren" und "zaehlen" fehlte eine Aussage. Nicht jede
# Anfrage, die ins Leere läuft, ist ein Angriff -- manche sind ein
# DEFEKT, und zwar einer, den jemand beheben sollte.
#
# Gemessen über siebzehn Tage:
#     605  /cgi-bin/filemanager/qsyncPrepare.cgi
#     581  /cgi-bin/qsync/qsyncsrvPrepare.cgi
#     193  /cgi-bin/authLogin.cgi
#      65  /autodiscover/autodiscover.xml (alle Schreibweisen)
#
# Das sind keine Sondierungen. Das ist ein Qsync-Client, der seit
# Wochen glaubt, unsere Webseite sei sein NAS, und ein Outlook, das
# uns für seinen Exchange hält. Beides Fehlkonfigurationen bei einem
# Kunden oder bei uns -- beides behebbar, sobald man WEISS, welche
# Adresse es betrifft.
#
# "melden" verbucht solche Anfragen mit einem Befund und sperrt NIE.
# Ein defekter Sync-Client ist kein Angreifer; ihn auszusperren behebt
# nichts, sondern verbirgt nur den Defekt.
SPERREN, ZAEHLEN, MELDEN = "sperren", "zaehlen", "melden"

# Was der Befund dem Menschen sagt, der die Liste ansieht. Ohne diesen
# Satz ist ein Eintrag nur eine Adresse mit einem Pfad; mit ihm ist er
# ein Anruf beim Kunden.
BEFUND = {
    "qnap": "QNAP-NAS: Qsync-Client oder Anmeldung zeigt auf diese "
            "Webseite statt auf das NAS. Beim Anschlussinhaber die "
            "Serveradresse im Qsync-Client richtigstellen.",
    "autodiscover": "Outlook/Exchange-Autodiscover fragt diese Domain "
                    "ab. Entweder ein falsch eingerichtetes Postfach "
                    "oder ein fehlender Autodiscover-Eintrag im DNS.",
    "activesync": "ActiveSync-Gerät (Handy/Tablet) zeigt auf diese "
                  "Domain statt auf den Mailserver.",
    "webdav": "WebDAV-/CalDAV-/CardDAV-Client (Nextcloud, ownCloud, "
              "Kalender) zeigt auf diese Domain.",
    "synology": "Synology-NAS: DSM-Web-API zeigt auf diese Webseite "
                "statt auf das NAS.",
    "pflichtseite_fehlt": "Abruf einer Seite, die es auf diesem Server "
                          "nicht gibt und auf die nichts verweist -- "
                          "also geraten. ACHTUNG: Wird eine solche "
                          "Seite angelegt, muss "
                          "web_rbl.muster.pflichtseite_fehlt wieder "
                          "auf 'zaehlen' stehen, sonst sperrt man "
                          "Besucher von der eigenen neuen Seite aus.",
    "freiliste": "Diese Adresse steht auf der Freiliste und wird "
                 "deshalb nie gesperrt -- gemeldet schon. Nachsehen, "
                 "ob dort etwas klemmt oder ob der Freilisteneintrag "
                 "nicht mehr stimmt.",
    "pflichtseite": "Impressum, Kontakt oder Datenschutz in einer "
                    "Schreibweise, die es bei uns nicht gibt -- das "
                    "Muster eines Sammlers, der Pflichtangaben "
                    "durchprobiert. Siehe web_rbl.muster.pflichtseite.",
}

MUSTER = (
    ("traversal_ziel", SPERREN, re.compile(
        r"(\.\.(/|%2f|%252f|\\)+)[^?]*"
        r"(\.env|\.git|\.aws|\.ssh|passwd|shadow|id_rsa|"
        r"environ|config\.|credentials|\.pem)", re.I)),
    ("traversal", ZAEHLEN, re.compile(
        r"(\.\./|\.\.%2f|%2e%2e|%252e|\.\.\\)", re.I)),

    # ---- FEHLKONFIGURATIONEN -----------------------------------------
    #
    # Diese Muster stehen VOR ``php`` und ``konfig``, weil sonst
    # ``/remote.php/dav`` als PHP-Sonde gälte und ein Nextcloud-Client
    # gesperrt würde. Sie stehen HINTER ``traversal``, damit
    # ``/cgi-bin/../../.env`` die Sonde bleibt, die es ist -- der
    # Verzeichniswechsel wiegt schwerer als das Verzeichnis.
    #
    # Alle Muster nennen EXAKTE Dateinamen, nie nur ein Verzeichnis.
    # ``/cgi-bin/`` allein taugt nicht: Dort liegen gemessene 605
    # Qsync-Aufrufe neben 28 ``info.cgi`` und 27 ``printenv.pl``, und
    # die beiden letzten sind Sonden.
    # Bewusst BREITER gefasst als die vier gemessenen Dateinamen.
    #
    # Sobald ``.cgi`` wieder sperrt (siehe Muster ``cgi`` weiter
    # unten), entscheidet dieses Muster darueber, ob das NAS eines
    # Kunden gesperrt wird oder gemeldet. Genau daran ist am
    # 24.09.2026 eine IPsec-Gegenstelle gescheitert.
    #
    # Die vier Dateinamen sind das, was WIR gesehen haben -- ein
    # anderes QNAP-Modell oder eine andere Firmware ruft andere auf.
    # Deshalb gilt jeder ``.cgi``-Aufruf in einem QNAP-typischen
    # Verzeichnis als Fehlkonfiguration. Diese Verzeichnisse kommen in
    # Sondierungen nicht vor; die zielen auf /cgi-bin/ selbst
    # (printenv.pl, info.cgi, test-cgi).
    ("qnap", MELDEN, re.compile(
        r"/cgi-bin/("
        r"(filemanager|qsync|qpkg|mgmt|application|photo|music|video)/"
        r"[^/?]*\.cgi"
        r"|(authLogin|sysinfoReq|qsyncPrepare|qsyncsrvPrepare)\.cgi"
        r")", re.I)),
    ("autodiscover", MELDEN, re.compile(
        r"/autodiscover/autodiscover\.(xml|json)", re.I)),
    ("activesync", MELDEN, re.compile(
        r"/Microsoft-Server-ActiveSync", re.I)),
    ("webdav", MELDEN, re.compile(
        r"(/remote\.php/(dav|webdav)|/ocs/v[12]\.php|"
        r"/\.well-known/(caldav|carddav)|^/principals/)", re.I)),
    ("synology", MELDEN, re.compile(
        r"/(webapi/(auth|entry|query)\.cgi|webman/index\.cgi)", re.I)),
    # -------------------------------------------------------------------

    ("dotenv", SPERREN, re.compile(
        r"(^|/)\.env(\.|$|\?)|/\.env[a-z.]*$", re.I)),
    ("vcs", SPERREN, re.compile(
        r"(^|/)\.(git|svn|hg)(/|$)", re.I)),
    ("wordpress", SPERREN, re.compile(
        r"(^|/)(wp-admin|wp-includes|wp-content|wp-login|xmlrpc\.php)", re.I)),
    # ``.cgi`` steht hier BEWUSST NICHT MEHR.
    #
    # Gemessen am 25.09.2026 ueber siebzehn Tage Echtverkehr:
    #     603  /cgi-bin/filemanager/qsyncPrepare.cgi
    #     578  /cgi-bin/qsync/qsyncsrvPrepare.cgi
    #     186  /cgi-bin/authLogin.cgi
    #       8  echte Sonden (webmin, dana-na)
    #
    # Die ersten drei sind die Web-API eines QNAP-NAS: Qsync-Client und
    # Anmeldung. Sie kamen von oesterreichischen Kundenadressen und aus
    # unserem eigenen Netz -- eine Adresse allein 962 mal. Ein
    # Sync-Client, dessen Ziel nicht mehr stimmt, klopft eben weiter.
    #
    # 1367 legitime Anfragen gegen acht echte Sonden: ``.cgi`` ist kein
    # Angriffsmerkmal, sondern ein Fehlalarmgenerator. Es hat am
    # 24.09.2026 einen Kunden gesperrt.
    ("php", SPERREN, re.compile(
        r"\.(php[0-9]?|phtml)($|\?)", re.I)),
    # ``.asp``, ``.aspx`` und ``.jsp`` sperren NICHT, sie zaehlen nur.
    #
    # Gemessen ueber siebzehn Tage: 48 Anfragen sehen nach alten Links
    # auf unsere EIGENEN Seiten aus (22x /SiteMap.aspx, 20x
    # /impressum.asp, 6x /index.aspx -- Reste einer frueheren
    # ASP-Fassung), gegen 25, die nach Sonden aussehen. Bei ``.php``
    # steht es 14.012 zu einer Handvoll; dort traegt die Endung, hier
    # nicht.
    #
    # Eine Sperre allein wegen einer Dateiendung trifft bei alten Links
    # auf die eigenen Seiten immer wieder Unbeteiligte.
    ("altendung", ZAEHLEN, re.compile(
        r"\.(asp|aspx|jsp|jspa)($|\?)", re.I)),
    # ``.cgi`` SPERRT WIEDER -- aber erst hier, nach den
    # Fehlkonfigurationen.
    #
    # Am 25.09.2026 frueh hatte ich ``.cgi`` ersatzlos gestrichen,
    # weil es eine IPsec-Gegenstelle gesperrt hatte. Das war die
    # richtige Sofortmassnahme und die falsche Dauerloesung: Odoo
    # liefert kein einziges CGI aus, also ist JEDER ``.cgi``-Aufruf
    # entweder eine Sondierung oder ein Geraet, das uns verwechselt.
    #
    # Die Unterscheidung leistet jetzt die Reihenfolge: Was nach QNAP
    # oder Synology aussieht, ist oben schon als "melden" abgefangen
    # und kommt hier gar nicht an. Was uebrig bleibt, ist
    # /cgi-bin/printenv.pl, /cgi-bin/info.cgi, /cgi-bin/test-cgi --
    # Sonden aus den Neunzigern, die bis heute jeder Scanner mitfuehrt.
    ("cgi", SPERREN, re.compile(
        r"\.(cgi|pl)($|\?|/)", re.I)),
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

        # DIE FREILISTE STEHT VOR ALLEM ANDEREN.
        #
        # Nicht jede falsch beurteilte Adresse kostet gleich viel. Ein
        # Scanner aus einem Rechenzentrum kostet nichts -- die
        # Gegenstelle eines Standorttunnels kostet den Standort. Am
        # 24.09.2026 hat ein zu breites Muster genau das getroffen:
        # 4.649 verworfene Pakete, und der Tunnel stand nur deshalb
        # noch, weil seine Sicherheitsverbindung aelter war als der
        # Listeneintrag.
        #
        # Wer hier steht, wird weiterhin geprueft und weiterhin
        # verbucht -- nur die Folge entfaellt. Das ist der Unterschied
        # zu einer Ausnahme in der Firewall: Die macht blind, diese
        # macht nur geduldig.
        freigestellt = request.env["web.rbl.freiliste"].sudo().ist_frei(
            adresse)

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
        if freigestellt and stufe == SPERREN:
            # Erfassen ja, sperren nein. Der Treffer steht damit als
            # Befund in der Liste, und jemand kann beim Kunden
            # anrufen, statt dass der Tunnel stirbt.
            stufe = MELDEN

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
        if not freigestellt and Eintrag.ist_gesperrt(adresse):
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
            # Die Domain gehoert zum Treffer, nicht nur der Pfad.
            #
            # Wir betreiben fuenf Webseiten hinter einem HAProxy. Ohne
            # den Host sagt ein Eintrag nur, DASS jemand klopft -- mit
            # ihm sagt er, WO. Das entscheidet zwei Fragen, die sich
            # sonst nicht beantworten lassen:
            #
            # * Bei einer Fehlkonfiguration: welchem Kunden gehoert die
            #   Domain, auf die sein NAS zeigt? Ohne das ist der Befund
            #   ein Achselzucken.
            # * Bei einem Sammler: greift er EINE Seite an oder alle
            #   fuenf? Der Rundumschlag ueber nicht zusammenhaengende
            #   Hosts ist genau die Signatur der Abmahnwelle 2022.
            #
            # Das Zugriffsprotokoll von werkzeug enthaelt den Host
            # NICHT -- nachtraeglich ist das nicht zu ermitteln. Nur
            # hier, zur Laufzeit, ist er zu haben.
            try:
                host = (request.httprequest.host or "")[:120]
            except Exception:  # noqa: BLE001
                host = ""
            # DIE KENNUNG KOMMT HIER GENAUSO AN WIE DER HOST.
            #
            # Odoo bekommt beide Kopfzeilen -- den Host braucht es
            # sogar zwingend, sonst koennte es bei fuenf Webseiten gar
            # nicht die richtige auswaehlen. Nur das Zugriffsprotokoll
            # von werkzeug schreibt keine von beiden mit.
            #
            # Daraus folgt: Fuer alles, was Odoo erreicht, braucht es
            # keinen Mitschnitt am Reverse Proxy, um zu wissen, WER da
            # klopft. Die Kennung trennt einen erklaerten Crawler
            # (GPTBot, Googlebot) von einem Headless-Browser und von
            # etwas Selbstgebautem -- und das ist der Unterschied
            # zwischen einem Gast, den man einlaedt, und einem, den
            # man aussperrt.
            try:
                kennung = (
                    request.httprequest.headers.get("User-Agent") or "")[:255]
            except Exception:  # noqa: BLE001
                kennung = ""
            # JE ANFRAGE NUR EINMAL VERBUCHEN.
            #
            # ``_match`` wird für DIESELBE Anfrage mehrfach aufgerufen,
            # sobald sie weiterläuft: Odoos Wegfindung probiert
            # Sprachpräfixe und Rückfallpfade durch. Bei einem
            # sperrenden Muster fällt das nicht auf, weil die erste
            # Abweisung die Anfrage beendet -- bei "zaehlen" und
            # "melden" aber schon.
            #
            # Gemessen am 25.09.2026 nach dem Neustart: EINE Anfrage
            # auf /impressum.php erzeugte FÜNF Trefferzeilen und
            # treffer_anzahl 5; eine einzige Anfrage hob einen Eintrag
            # von 3 auf 8. Die Zähler der Fehlkonfigurations- und
            # Sammlereinträge waren damit rund fünffach zu hoch.
            #
            # Schlimmer als die falsche Zahl ist der Preis: Jede
            # Verbuchung öffnet eine eigene Datenbankverbindung. Fünf
            # je Anfrage ist genau die Verstärkung, an der am selben
            # Morgen schon der Verbindungspool erstickt ist -- und
            # ausgerechnet bei der Stufe, die billig sein sollte, weil
            # sie den Verkehr durchlässt.
            #
            # Die Markierung liegt in ``environ``: Das ist das
            # Wörterbuch dieser einen Anfrage, es lebt genau so lange
            # wie sie, und es ist unabhängig davon, ob Odoo dasselbe
            # ``request``-Objekt wiederverwendet. Gesetzt wird sie VOR
            # der Verbuchung -- scheitert die, soll es bei einem
            # Versuch bleiben und nicht bei fünf.
            umgebung = getattr(
                getattr(request, "httprequest", None), "environ", None)
            schon_gebucht = bool(
                isinstance(umgebung, dict) and umgebung.get("web_rbl.gebucht"))
            if not schon_gebucht:
                if isinstance(umgebung, dict):
                    umgebung["web_rbl.gebucht"] = True
                Eintrag.treffer_eigene_transaktion(
                    adresse, path_info, muster, host, stufe, kennung)
            if stufe != SPERREN:
                # "zaehlen" und "melden" lassen durch. Ein defekter
                # Sync-Client wird nicht ausgesperrt, sondern gemeldet:
                # Sperren behebt den Defekt nicht, es verbirgt ihn.
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

    # Seiten, die es auf einer Firmenwebseite geben MUSS und die
    # Pruefdienste in allen Schreibweisen durchprobieren. Gemessen am
    # 25.09.2026: 92.205.178.32 rief /impressum, /Impressum,
    # /impressum/, /impressum.php, /impressum.html, /impressum.htm und
    # /impressum.asp ab -- offensichtlich ein Impressumspruefer, wie ihn
    # Rechtsdienste einsetzen. Gesperrt hat ihn ausgerechnet die
    # ``.php``-Variante.
    #
    # Wer das Impressum sucht, greift nicht an. Diese Namen sind
    # deshalb von jedem Muster ausgenommen.
    # WARUM DAS IMPRESSUM NICHT HARMLOS IST
    # --------------------------------------
    # Die erste Fassung nahm Pflichtseiten von JEDEM Muster aus: "Wer
    # das Impressum sucht, greift nicht an." Das ist zu gutgläubig.
    #
    # In Österreich lief 2022 eine Abmahnwelle wegen eingebundener
    # Google-Fonts. Die Analyse der Hosting-Protokolle zeigte damals,
    # dass die Schreiben nicht aus Einzelbesuchen stammten, sondern aus
    # einem automatisierten Rundumschlag: verschiedene, nicht
    # zusammenhängende Hosts IM ABSTAND VON MILLISEKUNDEN, offenkundig
    # ein Headless-Browser. Das Impressum ist dabei kein Beiwerk,
    # sondern das Ziel -- dort steht der Name, an den der Brief geht.
    #
    # Eine Pflichtangabe ist öffentlich, aber ihre maschinelle Ernte im
    # Bestand ist etwas anderes als ein Mensch, der nachsieht, mit wem
    # er es zu tun hat. Wer die Daten redlich braucht, bekommt sie aus
    # Firmenbuch, GISA oder WKO-Verzeichnis -- nicht durch Abgrasen
    # fremder Webseiten.
    #
    # ZWEI SÄTZE, DIE BEIDE GELTEN MÜSSEN
    # ------------------------------------
    # 1. Das Impressum MUSS für Menschen erreichbar bleiben. Es ist
    #    gesetzlich gefordert; eine Sperre, die es verdeckt, schafft
    #    genau den Verstoß, den der Sammler sucht. Gemessen: 2.836
    #    Aufrufe von ``/contactus``, 496 von ``/kontakt``, aus 999
    #    verschiedenen Adressen. Das sind Besucher.
    # 2. Wer Pflichtangaben MASCHINELL durchprobiert, gibt sich zu
    #    erkennen -- durch Schreibweisen, die es bei uns nicht gibt.
    #    Gemessen: ``/impressum.php`` 24, ``.htm`` 22, ``.asp`` 21,
    #    ``.html`` 30. Unsere Seiten haben keine Dateiendungen.
    #
    # Deshalb wird hier nicht ausgenommen, sondern HERABGESTUFT: Trifft
    # irgendein Muster auf eine Pflichtseite, heißt der Treffer
    # ``pflichtseite`` und bekommt dessen Stufe. Die Vorgabe ist
    # ``melden`` -- erfassen, durchlassen, sichtbar machen. Wer die
    # Ernte nicht will, stellt einen Parameter um::
    #
    #     web_rbl.muster.pflichtseite = sperren
    #
    # Der kanonische Pfad ``/impressum`` trifft auf KEIN Muster und
    # kommt hier gar nicht erst an -- er bleibt auch dann erreichbar,
    # wenn gesperrt wird. Betroffen sind nur die Schreibweisen, die
    # ein Mensch nie eintippt.
    # NICHT JEDE PFLICHTSEITE TRAEGT EINEN NAMEN.
    #
    # Gemessen am 25.09.2026 ueber siebzehn Tage: Von 24 Adressen, die
    # Pflichtseiten in fremden Schreibweisen abriefen, entfielen 14 auf
    # den Bereich 57.141.20.x -- Meta -- mit je genau einem Aufruf von
    # ``/SiteMap.aspx``. Das ist ein Suchmaschinen-Crawler, der einem
    # alten Link auf unsere fruehere ASP-Fassung folgt. Wer die
    # Sammlersperre einschaltet, wuerde ihn mitnehmen.
    #
    # Der Unterschied ist inhaltlich, nicht technisch: ``sitemap.xml``
    # und ``robots.txt`` sind Maschinendateien ohne eine einzige
    # personenbezogene Angabe. Sie zu holen ist die Aufgabe jedes
    # Crawlers. Das Impressum dagegen ist genau die Seite, auf der der
    # Name und die Anschrift stehen -- das, was ein Abmahnschreiben
    # braucht.
    #
    # Deshalb zwei Ausdruecke: Der eine kann auf Wunsch sperren, der
    # andere nie.
    IDENTITAETSSEITEN = re.compile(
        r"/(impressum|imprint|kontakt\w*|contact(us|s|-us)?|datenschutz|"
        r"privacy|agbs?|terms)([./]|$)", re.I)
    MASCHINENSEITEN = re.compile(
        r"/(sitemap\w*|robots|\.well-known/security)([./]|$)", re.I)

    # EINE SEITE, DIE ES NICHT GIBT UND AUF DIE NICHTS VERWEIST.
    #
    # Wer sie abruft, hat sie geraten. Auf diesem Server gibt es weder
    # /impressum noch /datenschutz -- gemessen am 25.09.2026 ueber alle
    # fuenf Webseiten, 404 auf jeder, und in website.page existiert
    # keine Seite mit einem dieser Namen. Es verweist auch nichts
    # darauf: Die Pflichtangaben stehen unter /contactus.
    #
    # Deshalb ist der Aufruf hier ein Ratevorgang wie /wp-admin. Der
    # Unterschied zu einer echten Sonde ist nur, dass er hoeflicher
    # aussieht.
    #
    # ABSICHTLICH NICHT DABEI: /kontakt, /contactus, /agbs, /terms.
    # Die GIBT es, und sie werden benutzt -- 2.836 Aufrufe von
    # /contactus und 496 von /kontakt in siebzehn Tagen, aus 999
    # verschiedenen Adressen. Sie hier aufzunehmen hiesse, Besucher
    # auszusperren.
    #
    # DIE VORGABE IST "ZAEHLEN", UND DAS MUSS SO BLEIBEN.
    # In einer gewoehnlichen Odoo-Installation GIBT es ein Impressum;
    # dort waere ein sperrendes Muster ein Fehlalarmgenerator. Nur wo
    # die Seite nachweislich fehlt, ist es richtig -- und dort per
    # Parameter:
    #
    #     web_rbl.muster.pflichtseite_fehlt = sperren
    #
    # WER DIESE SEITEN ANLEGT, MUSS DEN PARAMETER ZURUECKSTELLEN.
    # Sonst sperrt man Besucher von der eigenen, frisch angelegten
    # Impressumsseite aus -- und merkt es nicht, weil die Seite ja da
    # ist und fuer einen selbst funktioniert.
    # ``/privacy`` STEHT HIER BEWUSST NICHT.
    #
    # Es ist die Ausnahme, die die Regel bestaetigt: Die Seite gibt es
    # zwar ebenfalls nicht (404 auf allen fuenf Webseiten), aber die
    # Fusszeile ``theme_alan.alan_footer_1`` VERLINKT sie, und die
    # nutzen drei unserer Seiten.
    #
    # Wer dort auf "Datenschutz" klickt, waere damit fuer 24 Stunden
    # von allen fuenf Webseiten ausgesperrt worden -- fuer einen Klick
    # auf einen Link, den wir selbst gesetzt haben. Das waere der
    # schlimmste Fehlalarm, den dieses Modul bauen kann: einer, der
    # ausgerechnet die gewissenhaften Besucher trifft.
    #
    # Der richtige Weg ist umgekehrt: den toten Verweis reparieren
    # oder entfernen. Bis dahin bleibt /privacy unberuehrt.
    #
    # Die Lehre daraus gilt allgemein: "Es gibt die Seite nicht" ist
    # NICHT dasselbe wie "niemand kann darauf stossen". Bevor ein
    # weiterer Name hier hereinkommt, ist zu pruefen, ob irgendeine
    # Ansicht ihn verlinkt.
    FEHLENDE_SEITEN = re.compile(
        r"/(impressum|imprint|datenschutz|legal)([./]|$)", re.I)

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
            # Eine Pflichtseite wird herabgestuft, egal welches Muster
            # sie getroffen hat. Das ist zugleich das Sicherheitsnetz
            # fuer jedes kuenftige Muster: Das Impressum kann nicht
            # versehentlich gesperrt werden, sondern nur absichtlich.
            if cls.MASCHINENSEITEN.search(pfad):
                # sitemap/robots: immer nur zaehlen, nie sperrbar.
                # Kein Parameter hebt das auf -- ein Crawler, der
                # robots.txt holt, tut genau das, was wir von ihm
                # wollen.
                return "maschinenseite", ZAEHLEN
            if cls.IDENTITAETSSEITEN.search(pfad):
                name, vorgabe = "pflichtseite", MELDEN
            stufe = vorgabe
            if Parameter is not None:
                gesetzt = Parameter.get_param(f"web_rbl.muster.{name}")
                if gesetzt in (SPERREN, ZAEHLEN, MELDEN):
                    stufe = gesetzt
            return name, stufe

        # Kein Muster getroffen -- aber vielleicht eine Seite, die es
        # hier gar nicht gibt. Diese Pruefung steht ganz unten, damit
        # sie nie einem echten Muster vorgreift.
        if cls.FEHLENDE_SEITEN.search(pfad):
            stufe = ZAEHLEN
            if Parameter is not None:
                gesetzt = Parameter.get_param(
                    "web_rbl.muster.pflichtseite_fehlt")
                if gesetzt in (SPERREN, ZAEHLEN, MELDEN):
                    stufe = gesetzt
            return "pflichtseite_fehlt", stufe
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
