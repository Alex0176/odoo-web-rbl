# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Scanner an ihrem Verhalten erkennen, nicht an bekannten Pfaden.

WOZU, WENN ES DOCH MUSTER GIBT
-------------------------------
Die Mustererkennung ist genau und billig, aber sie kennt nur, was
jemand schon einmal gesehen hat. Gemessen am 25.09.2026 über siebzehn
Tage: Von 193.130 fehlgeschlagenen Anfragen traf ein Muster auf
107.333 -- die übrigen **85.797 verteilten sich auf 7.066 Pfade**, für
die es kein Muster gab und für die es auch keines geben wird. Jeder
Baukasten erfindet neue Namen.

Wer sie trotzdem fangen will, muss aufhören, den Pfad zu bewerten, und
anfangen, das VERHALTEN zu bewerten: Ein Scanner probiert viele Pfade
durch und trifft fast nie einen. Ein Besucher trifft fast immer.

DIE REGEL, UND WIE SIE ENTSTANDEN IST
--------------------------------------
Drei Entwürfe, jeder an echten Daten geprüft, zwei verworfen:

1. *Zahl der Fehlschläge in einem Zeitfenster.* Verworfen: Bei
   20 Fehlschlägen in fünf Minuten hätte es 251 Adressen getroffen,
   davon 136 mit echtem Verkehr -- darunter eine mit 3.164
   erfolgreichen Seitenaufrufen.

2. *Folge von Fehlschlägen ohne zwischenzeitlichen Erfolg.* Ebenfalls
   verworfen: 238 Adressen, davon 137 mit echtem Verkehr. Ein
   Suchmaschinen-Crawler, der eine Reihe verschwundener Seiten
   abklappert, sieht genauso aus.

3. **Fehlschläge UND Erfolge im selben Fenster.** Das trennt:

       >= 20 Fehlschläge in 300 Sekunden
       UND <= 2 Erfolge im selben Fenster

   135 Adressen, davon nur sieben mit nennenswertem echtem Verkehr --
   und sechs davon waren bei der Durchsicht eindeutig Scanner
   (Erfolge nur auf ``/`` und Sitzungsdateien, Fehlschläge auf
   ``/.env``, ``/$(pwd)/.env``, kodierte Traversals).

   Die siebte war ein Suchmaschinen-Crawler, der an
   ``/fr/shop/product/...`` scheiterte -- an einem Sprachpräfix, das
   es hier nicht gibt. Dieser Fall ist inzwischen an der Wurzel
   behoben; solche Adressen liefern jetzt eine Umleitung statt eines
   Fehlschlags und tauchen hier gar nicht mehr auf.

WARUM IM ARBEITSSPEICHER UND NICHT IN DER DATENBANK
----------------------------------------------------
Gemessen: 179.428 Fehlschläge in siebzehn Tagen, im Mittel sieben je
Minute -- aber mit **Spitzen von 867 in einer einzigen Minute**. Ein
Datenbankschreibvorgang je Fehlschlag wäre damit genau die
Verstärkung, an der der Verbindungspool am 25.09.2026 um 05:57 schon
einmal erstickt ist.

Deshalb zählt dieses Modul im Speicher und schreibt erst, wenn die
Schwelle fällt. Der Zähler ist damit je Arbeitsprozess -- bei mehreren
Prozessen greift die Regel entsprechend später. Das ist bewusst in
Kauf genommen: Die FOLGE der Sperre steht in der Datenbank und gilt
sofort für alle Prozesse.
"""
import logging
import threading
import time

from odoo import models
from odoo.http import request

_logger = logging.getLogger(__name__)

MUSTER = "scanner"

# Vorgaben. Alle über Systemparameter umstellbar.
FENSTER = 300      # Sekunden
FEHLER = 20        # so viele Fehlschläge im Fenster
ERFOLGE = 2        # bei höchstens so vielen Erfolgen
RUHE = 600         # nach einer Meldung so lange nicht erneut melden

# Obergrenze, damit ein verteilter Ansturm den Speicher nicht füllt.
# 4.351 verschiedene Adressen haben in siebzehn Tagen einen Fehlschlag
# erzeugt; 20.000 ist also reichlich und trotzdem begrenzt.
HOECHSTZAHL = 20000

_sperre = threading.Lock()
_fenster = {}      # adresse -> [(zeitpunkt, ist_fehler), ...]
_gemeldet = {}     # adresse -> zeitpunkt der letzten Meldung


def _aufraeumen(jetzt, fenster_s):
    """Alles wegwerfen, was aus dem Fenster gefallen ist."""
    grenze = jetzt - fenster_s
    for adresse in list(_fenster):
        eintraege = [e for e in _fenster[adresse] if e[0] >= grenze]
        if eintraege:
            _fenster[adresse] = eintraege
        else:
            del _fenster[adresse]
    for adresse in list(_gemeldet):
        if _gemeldet[adresse] < jetzt - RUHE:
            del _gemeldet[adresse]


class IrHttp(models.AbstractModel):
    _inherit = "ir.http"

    # ------------------------------------------------------------------
    @classmethod
    def _rbl_verhalten_merken(cls, ist_fehler):
        """Einen Ausgang vermerken und bei Bedarf melden.

        JE ANFRAGE GENAU EINMAL.
        ------------------------
        ``_serve_fallback`` wird fuer DIESELBE Anfrage mehrfach
        gerufen -- Odoos Wegfindung probiert Sprachpraefixe und
        Rueckfallpfade durch. Ohne Markierung zaehlt jeder Fehlschlag
        doppelt, und die Schwelle von zwanzig wirkt wie zehn.

        Gemessen am 25.09.2026 auf der Testinstanz: Eine Adresse mit
        25 erfundenen Pfaden wurde bereits nach der ZEHNTEN Anfrage
        gesperrt.

        Das ist besonders schlecht, weil die Schwelle nicht geraten,
        sondern an echten Daten gemessen ist: Bei zwanzig traf die
        Regel 135 Adressen, davon sieben mit echtem Verkehr. Bei zehn
        ist es eine andere Regel, die niemand gemessen hat -- und der
        einzige Zweck der Messung war, genau das zu vermeiden.

        Dieselbe Falle gab es am selben Tag schon einmal in
        ``_match``; die Markierung dort heisst ``web_rbl.gebucht``.
        Eine Lehre, die nur an der Stelle gilt, an der man sie gelernt
        hat, ist keine.
        """
        if not request or not request.env:
            return
        umgebung = getattr(
            getattr(request, "httprequest", None), "environ", None)
        if isinstance(umgebung, dict):
            if umgebung.get("web_rbl.verhalten"):
                return
            umgebung["web_rbl.verhalten"] = True
        Parameter = request.env["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.aktiv", "1") != "1":
            return
        if Parameter.get_param("web_rbl.scanner_aktiv", "1") != "1":
            return

        Herkunft = request.env["web.rbl.herkunft"].sudo()
        adresse = Herkunft.adresse()
        if not adresse:
            return

        def zahl(schluessel, vorgabe):
            try:
                return int(Parameter.get_param(schluessel, vorgabe))
            except (TypeError, ValueError):
                return vorgabe

        fenster_s = zahl("web_rbl.scanner_fenster", FENSTER)
        genug_fehler = zahl("web_rbl.scanner_fehler", FEHLER)
        hoechst_erfolge = zahl("web_rbl.scanner_erfolge", ERFOLGE)

        jetzt = time.time()
        melden = False
        with _sperre:
            # Ein Erfolg von einer Adresse, die wir gar nicht
            # beobachten, kostet nichts: Er wird nicht vermerkt. So
            # geraten gewoehnliche Besucher nie in die Buchfuehrung.
            if not ist_fehler and adresse not in _fenster:
                return
            if ist_fehler and len(_fenster) >= HOECHSTZAHL \
                    and adresse not in _fenster:
                _aufraeumen(jetzt, fenster_s)
                if len(_fenster) >= HOECHSTZAHL:
                    return

            _fenster.setdefault(adresse, []).append((jetzt, ist_fehler))

            # Nur die eigene Adresse beschneiden; alles andere waere
            # Arbeit im Anfrageweg, die niemand bestellt hat. Das
            # vollstaendige Aufraeumen passiert oben, wenn es eng wird.
            grenze = jetzt - fenster_s
            eintraege = [e for e in _fenster[adresse] if e[0] >= grenze]
            _fenster[adresse] = eintraege

            if ist_fehler and _gemeldet.get(adresse, 0) < jetzt - RUHE:
                fehler = sum(1 for e in eintraege if e[1])
                erfolge = len(eintraege) - fehler
                if fehler >= genug_fehler and erfolge <= hoechst_erfolge:
                    melden = True
                    _gemeldet[adresse] = jetzt
                    _fenster.pop(adresse, None)

        if melden:
            cls._rbl_scanner_melden(adresse, Parameter, Herkunft)

    @classmethod
    def _rbl_scanner_melden(cls, adresse, Parameter, Herkunft):
        """Jetzt erst die Datenbank anfassen -- einmal, nicht je Anfrage."""
        try:
            if not Herkunft.sperrbar(adresse):
                return
            stufe = Parameter.get_param(f"web_rbl.muster.{MUSTER}", "sperren")
            if stufe not in ("sperren", "zaehlen", "melden"):
                stufe = "sperren"

            # DIE FREILISTE GILT AUCH HIER.
            #
            # Im Anfrageweg wird sie in ``_rbl_pruefen`` geprueft --
            # dieser Weg laeuft aber daran vorbei, und das ist beim
            # Testen aufgefallen: Eine Adresse VON der Freiliste bekam
            # einen Eintrag mit Zustand "gesperrt". Die Sperre wirkte
            # zwar nicht, weil ``_match`` sie freistellt, aber der
            # Eintrag war falsch -- und ein Ticketlauf oder eine
            # Auswertung haette sie als gesperrt gefuehrt.
            #
            # Die Schranke beim Aufnehmen in die Freiliste hilft hier
            # nicht: Sie loest BESTEHENDE Sperren, und diese entsteht
            # erst danach.
            #
            # Verbucht wird trotzdem, nur als Meldung: Dass eine
            # Gegenstelle ploetzlich zwanzig Pfade durchprobiert, will
            # man wissen. Es kann ein uebernommener Anschluss sein
            # oder ein Geraet dahinter, das jemand gekapert hat.
            if request.env["web.rbl.freiliste"].sudo().ist_frei(adresse):
                stufe = "melden"
            try:
                pfad = request.httprequest.path or ""
                host = (request.httprequest.host or "")[:120]
                kennung = (request.httprequest.headers.get("User-Agent")
                           or "")[:255]
            except Exception:  # noqa: BLE001
                pfad, host, kennung = "", "", ""
            Eintrag = request.env["web.rbl.eintrag"].sudo()
            if Eintrag.ist_gesperrt(adresse):
                return
            Eintrag.treffer_eigene_transaktion(
                adresse, pfad[:255], MUSTER, host, stufe, kennung)
            _logger.info(
                "Web RBL: Scanner erkannt -- %s (zuletzt %s)", adresse,
                pfad or "?")
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Scannermeldung fuer %s gescheitert.", adresse)

    # ------------------------------------------------------------------
    @classmethod
    def _serve_fallback(cls):
        """Hier steht fest: keine Route gefunden, es wird ein 404."""
        try:
            cls._rbl_verhalten_merken(True)
        except Exception:  # noqa: BLE001
            _logger.exception("Web RBL: Fehlschlag nicht vermerkt.")
        return super()._serve_fallback()

    @classmethod
    def _post_dispatch(cls, response):
        """Ein Erfolg setzt das Bild zurecht.

        Wer zwischendurch echte Seiten bekommt, ist kein Scanner --
        das ist der ganze Unterschied zu einer blossen Zaehlung von
        Fehlschlaegen, und er ist an echten Daten gemessen.
        """
        try:
            status = getattr(response, "status_code", 200) or 200
            if 200 <= status < 400:
                cls._rbl_verhalten_merken(False)
        except Exception:  # noqa: BLE001
            _logger.exception("Web RBL: Erfolg nicht vermerkt.")
        return super()._post_dispatch(response)
