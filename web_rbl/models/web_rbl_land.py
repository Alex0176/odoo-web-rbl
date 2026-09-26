# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Herkunftsland: anzeigen immer, sperren nur auf ausdrücklichen Wunsch.

WOZU DAS LAND GUT IST
---------------------
Zum Beurteilen. Eine Adresse in der Liste ist eine Zahlenfolge; mit
dem Land daneben ist sie ein Befund. Ein Anmeldeversuch aus Österreich
um zehn Uhr vormittags ist etwas anderes als einer aus einem Land, in
dem wir keinen einzigen Kunden haben.

WOZU ES NICHT TAUGT
-------------------
Zum pauschalen Aussperren, und das sagen die eigenen Zahlen deutlich.
Die Angreifer, die am 25.09.2026 in unserer Liste standen, kamen
überwiegend aus Google-Cloud-Bereichen (``34.x``, ``35.x``) -- und die
liegen in Belgien, Finnland und den Niederlanden. Eine Sperre für
alles ausserhalb des deutschsprachigen Raums hätte sie **nicht**
getroffen.

Getroffen hätte sie: eigene Mitarbeiter im Urlaub, Kunden auf
Geschäftsreise, Suchmaschinen-Crawler aus den USA. Und was ein
Angreifer umgeht, indem er einen Server in Frankfurt mietet, kostet
ihn zwölf Euro im Monat.

Deshalb ist die Sperre nach Land eine **Option, die niemand
voreingestellt bekommt**. Wer sie einschaltet, soll einen konkreten
Anlass haben -- etwa eine Angriffswelle aus einem Bereich, in dem man
nachweislich keine Kunden hat.

WAS ES BRAUCHT
--------------
Die GeoLite2-Datenbank von MaxMind, kostenlos, aber mit Konto. Odoo
sucht sie an dem Ort, den ``geoip_country_db`` in der Konfiguration
nennt (Vorgabe ``/usr/share/GeoIP/GeoLite2-Country.mmdb``). Fehlt
sie, bleibt das Feld schlicht leer und alles andere arbeitet
unverändert weiter -- das Modul setzt sie nirgends voraus.

Das Modul kann die Datei selbst nachführen: Mit einem Lizenzschlüssel
in ``web_rbl.geolite2_schluessel`` holt ``_cron_geolite2_abgleichen``
wöchentlich die aktuelle Ausgabe und legt sie an genau diesem Ort ab,
sofern der Odoo-Benutzer dort schreiben darf. Ohne Schlüssel tut der
Lauf nichts. Eine Datei, die neu ERSCHEINT, sieht der laufende Dienst
sofort -- Odoo versucht das Öffnen bei jeder Anfrage erneut, solange es
scheitert. Eine Datei, die ERSETZT wird, sieht er erst nach dem
nächsten Neustart: Der Leser hält die alte im Speicher. Für Länder,
die sich alle paar Monate um ein paar Netze verschieben, ist das
unerheblich.

Und eine Einordnung, die in Europa dazugehört: Eine IP-Adresse einem
Ort zuzuordnen ist Verarbeitung personenbezogener Daten. Das gehört
ins Verarbeitungsverzeichnis, auch wenn die Abfrage örtlich
stattfindet und niemand erfährt, wonach man fragt.
"""
import datetime
import io
import logging
import os
import tarfile
import tempfile

from odoo import api, fields, models, tools

_logger = logging.getLogger(__name__)

# Der Bezugsweg von MaxMind. Der Schlüssel steht NUR in der Adresse;
# er darf in keiner Meldung und keinem Log auftauchen.
GEOLITE2_URL = ("https://download.maxmind.com/app/geoip_download"
                "?edition_id={ausgabe}&license_key={schluessel}&suffix=tar.gz")
GEOLITE2_HOECHSTGROESSE = 96 * 1024 * 1024   # City ist ~60 MB gepackt


class WebRblLand(models.Model):
    _name = "web.rbl.land"
    _description = "Regel für ein Herkunftsland"
    _order = "stufe, country_id"
    _rec_name = "country_id"

    country_id = fields.Many2one(
        "res.country", string="Land", required=True, ondelete="cascade",
        index=True)
    code = fields.Char(related="country_id.code", store=True, index=True)
    stufe = fields.Selection(
        [("sperren", "Ganz sperren"),
         ("kein_backend", "Kein Zugang zur Anmeldung"),
         ("melden", "Nur melden"),
         ("frei", "Nie sperren")],
        string="Regel", default="melden", required=True,
        help="'Nie sperren' ist die Ausnahme in die andere Richtung: "
             "Verkehr aus diesem Land wird von keiner Länderregel "
             "erfasst. Nützlich, wenn man eine ganze Weltregion sperrt "
             "und einzelne Länder davon ausnehmen will.")
    bemerkung = fields.Char(
        help="Warum gibt es diese Regel? In einem Jahr ist das die "
             "einzige Frage, die zählt.")
    aktiv = fields.Boolean(string="Aktiv", default=True)

    _land_eindeutig = models.Constraint(
        "unique(country_id)", "Für dieses Land gibt es bereits eine Regel.")

    # ------------------------------------------------------------------
    @api.model
    @tools.ormcache()
    def _regeln(self):
        """{Länderkürzel: Stufe} -- zwischengespeichert.

        Die Abfrage läuft bei jeder Anfrage. Ein Wörterbuch mit
        höchstens ein paar Dutzend Einträgen ist dafür genau richtig.
        """
        regeln = {}
        for satz in self.sudo().search([("aktiv", "=", True)]):
            if satz.code:
                regeln[satz.code.upper()] = satz.stufe
        return regeln

    @api.model
    def stufe_fuer(self, land):
        """Welche Regel gilt für dieses Land? "" wenn keine."""
        if not land:
            return ""
        return self._regeln().get(land.upper(), "")

    def _cache_leeren(self):
        self.env.registry.clear_cache()
        registry = self.env.registry

        def benachrichtigen():
            try:
                if registry.ready:
                    registry.signal_changes()
            except Exception:  # noqa: BLE001
                _logger.warning(
                    "Web RBL: Länderregel geändert, andere Prozesse "
                    "konnten aber nicht benachrichtigt werden.")
        try:
            self.env.cr.postcommit.add(benachrichtigen)
        except AttributeError:
            benachrichtigen()

    @api.model_create_multi
    def create(self, werteliste):
        saetze = super().create(werteliste)
        saetze._cache_leeren()
        return saetze

    def write(self, werte):
        ergebnis = super().write(werte)
        self._cache_leeren()
        return ergebnis

    def unlink(self):
        ergebnis = super().unlink()
        self._cache_leeren()
        return ergebnis

    # ------------------------------------------------------------------
    # GeoLite2 nachführen
    # ------------------------------------------------------------------
    @api.model
    def _geolite2_stand(self, pfad):
        """Erstellungsdatum der Datei unter ``pfad``, None wenn unlesbar."""
        try:
            import geoip2.database
            with geoip2.database.Reader(pfad) as leser:
                return leser.metadata().build_epoch
        except Exception:  # noqa: BLE001 -- fehlt, kaputt, kein geoip2
            return None

    @api.model
    def _cron_geolite2_abgleichen(self):
        """Die GeoLite2-Datei holen und ablegen, wenn sie neuer ist.

        Läuft wöchentlich; MaxMind veröffentlicht dienstags und
        freitags. Der Ablauf ist so gebaut, dass zu keinem Zeitpunkt
        eine halbe Datei am Zielort liegt: herunterladen, entpacken,
        mit dem Leser öffnen, Stand vergleichen, erst dann per
        ``rename`` an die Stelle setzen.
        """
        Param = self.env["ir.config_parameter"].sudo()
        schluessel = (Param.get_param("web_rbl.geolite2_schluessel") or "").strip()
        if not schluessel:
            _logger.debug("Web RBL: kein GeoLite2-Schlüssel, Abgleich übersprungen.")
            return True
        ausgabe = (Param.get_param("web_rbl.geolite2_ausgabe") or "GeoLite2-Country").strip()
        ziel = tools.config.get("geoip_country_db")
        if "City" in ausgabe:
            ziel = tools.config.get("geoip_city_db")
        if not ziel:
            _logger.warning("Web RBL: geoip_country_db ist in der Konfiguration leer.")
            return True

        verzeichnis = os.path.dirname(ziel)
        if not os.path.isdir(verzeichnis) or not os.access(verzeichnis, os.W_OK):
            _logger.warning(
                "Web RBL: GeoLite2 kann nicht abgelegt werden -- %s fehlt oder "
                "ist für diesen Benutzer nicht beschreibbar.", verzeichnis)
            return True

        import urllib.error
        import urllib.request
        url = GEOLITE2_URL.format(ausgabe=ausgabe, schluessel=schluessel)
        try:
            anfrage = urllib.request.Request(
                url, headers={"User-Agent": "odoo-web-rbl"})
            with urllib.request.urlopen(anfrage, timeout=120) as antwort:
                roh = antwort.read(GEOLITE2_HOECHSTGROESSE + 1)
        except urllib.error.HTTPError as fehler:
            # 401: Schlüssel falsch oder abgelaufen. 400: Ausgabe unbekannt.
            _logger.warning("Web RBL: GeoLite2-Bezug abgewiesen (HTTP %s).",
                            fehler.code)
            return True
        except (urllib.error.URLError, OSError) as fehler:
            _logger.warning("Web RBL: GeoLite2-Bezug gescheitert: %s",
                            str(fehler).replace(schluessel, "***")[:200])
            return True
        if len(roh) > GEOLITE2_HOECHSTGROESSE:
            _logger.warning("Web RBL: GeoLite2-Antwort grösser als erlaubt, verworfen.")
            return True

        try:
            with tarfile.open(fileobj=io.BytesIO(roh), mode="r:gz") as archiv:
                glieder = [g for g in archiv.getmembers()
                           if g.isfile() and g.name.endswith(".mmdb")]
                if len(glieder) != 1:
                    _logger.warning("Web RBL: GeoLite2-Archiv enthält %s .mmdb-Dateien, "
                                    "erwartet eine.", len(glieder))
                    return True
                inhalt = archiv.extractfile(glieder[0]).read()
        except (tarfile.TarError, OSError, EOFError) as fehler:
            _logger.warning("Web RBL: GeoLite2-Archiv unlesbar: %s", fehler)
            return True

        # Erst in eine Nachbardatei, dann prüfen, dann umbenennen.
        handle, vorlaeufig = tempfile.mkstemp(
            dir=verzeichnis, prefix=".geolite2-", suffix=".mmdb")
        try:
            with os.fdopen(handle, "wb") as datei:
                datei.write(inhalt)
            os.chmod(vorlaeufig, 0o644)
            neu = self._geolite2_stand(vorlaeufig)
            if neu is None:
                _logger.warning("Web RBL: heruntergeladene GeoLite2-Datei ist "
                                "kein gültiger Datenbestand, verworfen.")
                return True
            alt = self._geolite2_stand(ziel)
            if alt is not None and alt >= neu:
                Param.set_param("web_rbl.geolite2_stand",
                                str(datetime.date.fromtimestamp(alt)))
                _logger.info("Web RBL: GeoLite2 (%s) ist auf dem Stand vom %s, "
                             "nichts zu tun.", ausgabe,
                             datetime.date.fromtimestamp(alt))
                return True
            os.replace(vorlaeufig, ziel)
            vorlaeufig = None
        finally:
            if vorlaeufig and os.path.exists(vorlaeufig):
                os.unlink(vorlaeufig)

        stand = str(datetime.date.fromtimestamp(neu))
        Param.set_param("web_rbl.geolite2_stand", stand)
        _logger.info(
            "Web RBL: GeoLite2 (%s) auf Stand %s abgelegt unter %s.%s",
            ausgabe, stand, ziel,
            "" if alt is None else
            " Laufende Prozesse sehen den neuen Stand erst nach dem Neustart.")
        return True
