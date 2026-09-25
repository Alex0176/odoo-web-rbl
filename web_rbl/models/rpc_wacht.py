# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Gescheiterte Anmeldungen über XML-RPC und JSON-RPC.

WARUM DAS NICHT IN ``res.users._login`` GEHT
---------------------------------------------
Der Haken in ``_login`` greift bei der Anmeldemaske, bei RPC aber
nicht. Am 25.09.2026 gemessen, auf Test und Produktion gleich::

    Web RBL: Fehlversuch NICHT verbucht (keine Anfrage gebunden).
    request=False, uid=None

Die Ursache steht in ``odoo/http.py`` und ist kein Versehen::

    def dispatch_rpc(service_name, method, params):
        ...
        with borrow_request():
            ...
            return dispatch(method, params)

``borrow_request`` nimmt die Anfrage vom Stapel und legt sie erst im
``finally`` zurück. Innerhalb des RPC-Aufrufs gibt es also
absichtlich keine Anfrage -- und damit keine Adresse. Odoo selbst hat
dasselbe Problem und schreibt bei RPC ``n/a`` ins Protokoll
(``res_users.py``: ``ip = ... if request else 'n/a'``).

DESHALB EINE EBENE HÖHER
-------------------------
``dispatch_rpc`` wird aus dem Controller gerufen, und DORT ist die
Anfrage gebunden. Vor und nach dem Aufruf, nur nicht mittendrin. Also
umschließen wir die Funktion, statt uns in sie hineinzuhängen.

WARUM KEIN CONTROLLER-ERBE
---------------------------
Naheliegender wäre, ``odoo.addons.rpc.controllers.xmlrpc.XMLRPC`` zu
beerben. Das hat aber eine unangenehme Nebenwirkung: Liegt das Modul
``rpc`` auf dem Pfad, ist aber NICHT installiert, würde unsere
Unterklasse dessen Routen trotzdem anmelden -- wir schalteten also
eine Schnittstelle frei, die der Betreiber abgeschaltet hat. Bei
einem Modul, das Angriffe abwehren soll, wäre das die falsche
Richtung.

Diese Umhüllung meldet keine Route an und ändert kein Verhalten. Wird
``dispatch_rpc`` nie gerufen, tut sie nichts.

WAS ALS FEHLVERSUCH GILT
-------------------------
``exp_authenticate`` fängt ``AccessDenied`` selbst ab und gibt
``False`` zurück -- über HTTP kommt dann ein ganz gewöhnliches 200
mit ``<boolean>0</boolean>``. Genau deshalb verrät der Statuscode
nichts, und genau deshalb blieb der Angriff vom 14.09. unsichtbar:
25 Anmeldungen in sechs Minuten, alle mit HTTP 200.

Ein falscher Rückgabewert ist hier also der Befund, nicht die
Ausnahme.
"""
import logging

import odoo
from odoo import SUPERUSER_ID, api
from odoo.exceptions import AccessDenied
from odoo.http import request

_logger = logging.getLogger(__name__)

MUSTER = "anmeldung"

# Dienst und Methode, bei denen ein falscher Rueckgabewert eine
# gescheiterte Anmeldung bedeutet. "login" ist die alte Schreibweise
# und ruft intern dasselbe.
ANMELDEMETHODEN = {("common", "authenticate"), ("common", "login")}

_MERKMAL = "_web_rbl_umhuellt"


def _angaben(service_name, params):
    """(Datenbank, Benutzervermerk) je Dienst -- NIE aus blindem Index.

    HIER LIEGT EINE FALLE, UND SIE IST SCHARF
    ------------------------------------------
    Die Parameterliste bedeutet bei jedem Dienst etwas anderes, und
    beim Datenbankverwalter steht an vorderster Stelle das
    HAUPTKENNWORT::

        dispatch_rpc('db', 'drop', [master_pwd, name])
        dispatch_rpc('db', 'change_admin_password', ["admin", master_pwd])

    Wer hier ``params[1]`` als Benutzernamen verbucht, schreibt das
    Hauptkennwort im Klartext in die Sperrliste -- und von dort in
    jede Sicherung. Genau das wäre beim ersten Entwurf passiert.

    Deshalb wird je Dienst ausdrücklich entschieden, was gelesen
    werden darf, statt sich auf eine Position zu verlassen. Für den
    Datenbankverwalter wird aus den Parametern GAR NICHTS gelesen.
    """
    if service_name == "db":
        # Aus params nichts. Die Datenbank kommt aus der Anfrage oder
        # der Konfiguration, der Vermerk ist ein fester Text.
        datenbank = ""
        try:
            datenbank = request.db or ""
        except Exception:  # noqa: BLE001
            datenbank = ""
        if not datenbank:
            konfiguriert = odoo.tools.config.get("db_name") or ""
            if isinstance(konfiguriert, (list, tuple)):
                konfiguriert = konfiguriert[0] if konfiguriert else ""
            datenbank = str(konfiguriert).split(",")[0].strip()
        return datenbank, "(Hauptkennwort des Datenbankverwalters)"

    # common/authenticate: (db, login, password, env)
    # object/execute_kw:   (db, uid, password, modell, methode, ...)
    # In beiden Faellen ist [2] das Geheimnis -- es wird nie gelesen.
    try:
        datenbank = str(params[0]) if params else ""
        benutzer = str(params[1])[:80] if len(params) > 1 else ""
    except Exception:  # noqa: BLE001
        return "", ""
    return datenbank, benutzer


def _verbuchen(service_name, params, pfad):
    """Den Fehlversuch in einer eigenen Umgebung festhalten.

    ``dispatch_rpc`` hat keine Umgebung -- es bekommt nur den
    Datenbanknamen in den Parametern. Die bauen wir uns hier, und zwar
    bewusst eine EIGENE: Was hier geschrieben wird, soll den Abbruch
    der Anfrage überleben, genau wie bei jeder anderen Verbuchung.
    """
    if not request:
        return
    datenbank, benutzer = _angaben(service_name, params)
    if not datenbank:
        return

    registry = odoo.modules.registry.Registry(datenbank)
    with registry.cursor() as cr:
        umgebung = api.Environment(cr, SUPERUSER_ID, {})
        Parameter = umgebung["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.aktiv", "1") != "1":
            return
        if Parameter.get_param("web_rbl.anmeldung_aktiv", "1") != "1":
            return

        Herkunft = umgebung["web.rbl.herkunft"].sudo()
        adresse = Herkunft.adresse()
        if not adresse or not Herkunft.sperrbar(adresse):
            _logger.info(
                "Web RBL: RPC-Fehlversuch nicht verbucht, Adresse "
                "unklar oder nicht sperrbar (%s).", adresse or "keine")
            return

        Eintrag = umgebung["web.rbl.eintrag"].sudo()
        if Eintrag.ist_gesperrt(adresse):
            # Schon gesperrt: Ein weiterer Treffer kostet eine
            # Verbindung und bringt nichts. Dieselbe Ueberlegung wie
            # im Anfrageweg, und aus demselben Anlass -- am
            # 25.09.2026 um 05:57 hat genau das den Verbindungspool
            # erschoepft.
            return

        stufe = Parameter.get_param(f"web_rbl.muster.{MUSTER}", "sperren")
        if stufe not in ("sperren", "zaehlen", "melden"):
            stufe = "sperren"
        try:
            host = (request.httprequest.host or "")[:120]
            kennung = (request.httprequest.headers.get("User-Agent")
                       or "")[:255]
        except Exception:  # noqa: BLE001
            host, kennung = "", ""

        vermerk = f"{pfad} (Benutzer: {benutzer})" if benutzer else pfad
        Eintrag.treffer_eigene_transaktion(
            adresse, vermerk[:255], MUSTER, host, stufe, kennung)
        _logger.info(
            "Web RBL: RPC-Fehlversuch verbucht -- %s auf %s (Benutzer: %s).",
            adresse, pfad or "?", benutzer or "?")


def _umhuellen():
    """``odoo.http.dispatch_rpc`` einmalig umschließen."""
    original = getattr(odoo.http, "dispatch_rpc", None)
    if original is None or getattr(original, _MERKMAL, False):
        return

    def dispatch_rpc(service_name, method, params):
        try:
            ergebnis = original(service_name, method, params)
        except AccessDenied:
            # Der andere Weg, auf dem eine Anmeldung scheitern kann.
            #
            # ``object`` ist der Objektdienst -- dort scheitert ein
            # falscher Schluessel oder ein falsches Kennwort mit einer
            # Ausnahme statt mit False.
            #
            # ``db`` ist der Datenbankverwalter. Jeder Aufruf dort
            # prueft zuerst das HAUPTKENNWORT; ein Fehlschlag ist der
            # Versuch, an die Datenbanken selbst zu kommen. Das ist
            # der schwerwiegendste Anmeldeversuch, den es hier gibt --
            # und er laeuft ueber denselben Weg wie alles andere,
            # seit die Umhuellung auch in
            # ``web.controllers.database`` greift.
            if (service_name, method) in ANMELDEMETHODEN or \
                    service_name in ("object", "db"):
                _sicher_verbuchen(params, service_name, method)
            raise
        if (service_name, method) in ANMELDEMETHODEN and not ergebnis:
            # ``exp_authenticate`` gibt bei falschem Kennwort False
            # zurueck, nicht eine Ausnahme. Ueber HTTP ist das ein
            # gewoehnliches 200 -- der Statuscode verraet also nichts.
            _sicher_verbuchen(params, service_name, method)
        return ergebnis

    setattr(dispatch_rpc, _MERKMAL, True)
    odoo.http.dispatch_rpc = dispatch_rpc

    # ES GENUEGT NICHT, ``odoo.http.dispatch_rpc`` ZU ERSETZEN.
    #
    # Die Controller holen die Funktion mit
    # ``from odoo.http import dispatch_rpc`` -- damit ist der NAME in
    # ihrem Modul beim Import an die Originalfunktion gebunden. Ein
    # spaeterer Austausch des Attributs in ``odoo.http`` erreicht ihn
    # nicht mehr.
    #
    # Und genau so ist es gekommen: Am 25.09.2026 lud die Umhuellung
    # sauber ("RPC-Anmeldungen werden ueberwacht"), griff aber nie.
    # Das Modul ``rpc`` laedt vor uns (base -> web -> rpc -> web_rbl),
    # also stand der Name dort laengst.
    #
    # Deshalb zusaetzlich die bereits geladenen Module durchgehen.
    # Gesucht wird nicht nach Namen, sondern nach der IDENTITAET der
    # Funktion: Wer dieselbe Funktion gebunden hat, bekommt die
    # Umhuellung. Das trifft ``rpc.controllers.xmlrpc`` und
    # ``.jsonrpc`` ebenso wie jedes Fremdmodul, das denselben Weg
    # geht -- ohne dass wir eines davon voraussetzen muessten.
    #
    # Laedt ein Modul spaeter, bindet es ohnehin schon die Umhuellung.
    # Beide Richtungen sind damit abgedeckt.
    import sys
    umgebogen = []
    for name, modul in list(sys.modules.items()):
        if modul is None or name == "odoo.http":
            continue
        try:
            if getattr(modul, "dispatch_rpc", None) is original:
                modul.dispatch_rpc = dispatch_rpc
                umgebogen.append(name)
        except Exception:  # noqa: BLE001
            # Manche Module wehren sich gegen getattr oder setattr.
            # Das ist kein Grund, den Rest nicht zu erledigen.
            continue

    _logger.info(
        "Web RBL: RPC-Anmeldungen werden ueberwacht%s.",
        f" ({', '.join(umgebogen)})" if umgebogen
        else " -- ACHTUNG: kein Controller gefunden, der dispatch_rpc "
             "gebunden hat; bei installiertem Modul 'rpc' ist das ein "
             "Hinweis auf eine geaenderte Ladereihenfolge")


def _sicher_verbuchen(params, service_name, method):
    """Nie die RPC-Antwort gefährden.

    Eine gescheiterte Anmeldung muss als gescheiterte Anmeldung enden.
    Ein Fehler in unserer Buchhaltung darf daraus keinen Serverfehler
    machen -- schon gar nicht auf einer Schnittstelle, an der
    Integrationen hängen.
    """
    try:
        pfad = ""
        try:
            pfad = request.httprequest.path or ""
        except Exception:  # noqa: BLE001
            pfad = f"/{service_name}/{method}"
        _verbuchen(service_name, params,
                   pfad or f"/{service_name}/{method}")
    except Exception:  # noqa: BLE001
        _logger.exception(
            "Web RBL: RPC-Fehlversuch konnte nicht verbucht werden.")


_umhuellen()
