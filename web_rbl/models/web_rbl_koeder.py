# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Der Köder: unsinnige Antworten mit einem Kanarienwert darin.

WOZU ÜBERHAUPT ANTWORTEN
-------------------------
Ein 403 beendet die Sonde und sagt uns nichts Neues. Dass jemand
``/.env`` abruft, wussten wir schon -- dafür braucht es keine Antwort.

Wertvoll wird eine Antwort erst, wenn sie etwas enthält, **das es sonst
nirgends gibt**. Wer daraufhin einen Pfad abruft, den er nur aus
unserer erfundenen Datei haben kann, hat nicht bloß gesucht, sondern
gefunden und gehandelt. Das ist kein Verdacht, sondern ein Beweis --
mit null Fehlalarmrisiko, weil der Wert aus keiner anderen Quelle
stammen kann.

Genau das trägt die Hochrisiko-Liste. Und sie erwischt sogar den
Zweitverwerter: Scanner sammeln, verkaufen weiter, ein Dritter nutzt.
Ruft der fremde Dritte unseren Kanarienpfad ab, wissen wir nicht nur,
dass er böswillig ist, sondern auch, **von wem** er die Daten hat.

WAS BEWUSST NICHT DRINSTEHT
----------------------------
Nichts, was plausibel genug wäre, um gehandelt zu werden. Keine
Zugangsdaten in üblicher Form, keine echten Hostnamen, keine Schlüssel
mit gültiger Prüfsumme. Der Inhalt ist erkennbar Unsinn -- das ist
Absicht und keine Nachlässigkeit: Ein glaubwürdig gefälschter
Schlüsselbund landet in Scanner-Datenbanken und bringt uns mehr
Verkehr statt weniger.

Der Kanarienwert ist deshalb immer etwas, das man **bei uns abruft** --
ein Pfad, ein Token in der Adresszeile. Ein erfundener Datenbankname
sieht echt aus, beweist aber nie etwas, weil wir nie erfahren, ob ihn
jemand benutzt hat.

DIE OBERGRENZE
--------------
Nach ``web_rbl.koeder_max`` Antworten ist Schluss und es gibt wieder
403. Wer bis dahin nicht angebissen hat, beißt nicht mehr an -- und
eine Sonde wie die gemessene mit 9.413 Anfragen soll uns nicht 9.413
erfundene Dateien kosten.
"""

import logging
import secrets

from odoo import _, api, fields, models

_logger = logging.getLogger(__name__)

PARAM_AKTIV = "web_rbl.koeder_aktiv"
PARAM_MAX = "web_rbl.koeder_max"
MAX_VORGABE = 5

# Der Kanarienpfad beginnt immer so. Daran erkennen wir ihn später
# wieder, ohne die ganze Tabelle durchsuchen zu müssen.
KANARIE_PRAEFIX = "/cp-"


class WebRblKoeder(models.Model):
    _name = "web.rbl.koeder"
    _description = "Ausgelegter Köder samt Kanarienwert"
    _order = "id desc"

    eintrag_id = fields.Many2one(
        "web.rbl.eintrag", string="Adresse", required=True,
        ondelete="cascade", index=True)
    pfad = fields.Char(string="Angefragter Pfad", readonly=True)
    art = fields.Char(string="Art des Köders", readonly=True)
    kanarie = fields.Char(
        string="Kanarienwert", required=True, index=True, readonly=True,
        help="Dieser Pfad existiert nur in der ausgelieferten Fälschung. "
             "Wird er je abgerufen, hat jemand den Köder gelesen.")
    ausgelegt_am = fields.Datetime(
        string="Ausgelegt", default=fields.Datetime.now, readonly=True)
    angebissen_am = fields.Datetime(string="Angebissen", readonly=True)
    angebissen_von = fields.Char(
        string="Angebissen von", readonly=True,
        help="Die Adresse, die den Kanarienwert abgerufen hat. Weicht sie "
             "von der ab, der wir den Köder gaben, wurden die Daten "
             "weitergegeben.")

    # ------------------------------------------------------------------
    # Auslegen
    # ------------------------------------------------------------------
    @api.model
    def aktiv(self):
        return self.env["ir.config_parameter"].sudo().get_param(
            PARAM_AKTIV, "0") == "1"

    @api.model
    def hoechstzahl(self):
        try:
            return int(self.env["ir.config_parameter"].sudo().get_param(
                PARAM_MAX, MAX_VORGABE))
        except (TypeError, ValueError):
            return MAX_VORGABE

    @api.model
    def auslegen(self, adresse, pfad, muster):
        """Einen Köder erzeugen. Gibt (Inhalt, Typ) zurück oder None.

        ALLES IN EINER EIGENEN TRANSAKTION, UND ZWAR AUS EINEM GRUND,
        DER MICH SCHON EINMAL ERWISCHT HAT
        -------------------------------------------------------------
        Der Treffer wird in einer eigenen, sofort festgeschriebenen
        Transaktion verbucht -- er muss den Abbruch der Anfrage
        überleben. Die Transaktion der ANFRAGE sieht diese Zeile wegen
        REPEATABLE READ aber nicht: Ihr Snapshot ist älter.

        Der erste Entwurf reichte den frisch angelegten Eintrag an
        diese Methode weiter und legte den Köder in der Anfrage an.
        Ergebnis: Fremdschlüsselverletzung auf eine Zeile, die es aus
        Sicht dieser Transaktion nicht gab, gefangen vom
        Sicherheitsnetz in ``_match`` -- und die erste Sonde einer
        Adresse bekam statt des Köders eine 500. Derselbe
        Transaktionsfehler wie kurz zuvor beim Geocode-Zwischenspeicher,
        nur an anderer Stelle.

        Deshalb bekommt diese Methode die ADRESSE, nicht den Datensatz,
        und erledigt Suchen, Zählen und Anlegen geschlossen im eigenen
        Cursor.

        ``None`` heißt: kein Köder, der Aufrufer weist normal ab.
        """
        if not self.aktiv() or not adresse:
            return None
        bauer = self._bauer_fuer(muster)
        if not bauer:
            return None

        kanarie = f"{KANARIE_PRAEFIX}{secrets.token_hex(5)}"
        try:
            with self.pool.cursor() as cr:
                eigene = self.env(cr=cr, su=True)
                eintrag = eigene["web.rbl.eintrag"].search(
                    [("adresse", "=", adresse)], limit=1)
                if not eintrag:
                    return None
                bisher = eigene["web.rbl.koeder"].search_count(
                    [("eintrag_id", "=", eintrag.id)])
                if bisher >= self.hoechstzahl():
                    return None
                eigene["web.rbl.koeder"].create({
                    "eintrag_id": eintrag.id,
                    "pfad": (pfad or "")[:255],
                    "art": muster,
                    "kanarie": kanarie,
                })
                cr.commit()
        except Exception:  # noqa: BLE001
            _logger.exception(
                "Web RBL: Koeder fuer %s nicht ausgelegt.", adresse)
            return None

        _logger.info(
            "Web RBL: Koeder %r fuer %s ausgelegt, Kanarie %s",
            muster, adresse, kanarie)
        return bauer(kanarie)

    def _bauer_fuer(self, muster):
        return {
            "dotenv": self._koeder_dotenv,
            "vcs": self._koeder_git,
            "konfig": self._koeder_konfig,
            "traversal": self._koeder_verzeichnis,
            "traversal_ziel": self._koeder_verzeichnis,
        }.get(muster)

    # ------------------------------------------------------------------
    # Die Fälschungen
    # ------------------------------------------------------------------
    def _koeder_dotenv(self, kanarie):
        """Eine .env, die nach nichts schmeckt.

        Struktur stimmt -- jeder Parser liest sie --, Inhalt nicht. Kein
        Hostname, der existiert, kein Schlüssel mit gültiger Form. Der
        einzige verwertbare Wert ist der Kanarienpfad, und genau darauf
        kommt es an.
        """
        return ("\n".join([
            "APP_NAME=Commodore",
            "APP_ENV=production",
            "APP_DEBUG=false",
            f"ADMIN_PATH={kanarie}",
            "DB_CONNECTION=cbm",
            "DB_HOST=8050.local",
            "DB_PORT=1541",
            "DB_DATABASE=basic_v2",
            "DB_USERNAME=load",
            'DB_PASSWORD="$*",8,1',
            "CACHE_DRIVER=petscii",
            "SESSION_LIFETIME=64",
            "",
        ]), "text/plain; charset=utf-8")

    def _koeder_git(self, kanarie):
        """Eine .git/config ohne Fernziel, das je existiert hat."""
        return ("\n".join([
            "[core]",
            "\trepositoryformatversion = 0",
            "\tfilemode = true",
            "\tbare = false",
            '[remote "origin"]',
            f"\turl = https://localhost{kanarie}/basic.git",
            "\tfetch = +refs/heads/*:refs/remotes/origin/*",
            '[branch "main"]',
            "\tremote = origin",
            "",
        ]), "text/plain; charset=utf-8")

    def _koeder_konfig(self, kanarie):
        return ('{\n'
                '  "system": "Commodore 500",\n'
                '  "kernal": "901227-03",\n'
                f'  "admin": "{kanarie}",\n'
                '  "basic": "V2.0",\n'
                '  "memory": 65536\n'
                '}\n'), "application/json; charset=utf-8"

    def _koeder_verzeichnis(self, kanarie):
        """Die Wurzel eines Dateisystems, das es nie gab.

        Der Auftraggeber wollte ein durchklickbares Dateisystem eines
        Commodore 500 -- ein Gerät, das nie gebaut wurde. Das ist der
        Vorzug, nicht der Schönheitsfehler: Niemand kann behaupten, wir
        hätten ihn in etwas hineingelockt, was wie ein echtes System
        aussah.
        """
        eintraege = [
            ("basic/", "&lt;DIR&gt;"),
            ("kernal/", "&lt;DIR&gt;"),
            (kanarie.lstrip("/") + "/", "&lt;DIR&gt;"),
            ("autoexec.prg", "2 BLOCKS"),
            ("readme.seq", "1 BLOCK"),
        ]
        zeilen = "\n".join(
            f'<li><a href="{name}">{name}</a> {groesse}</li>'
            for name, groesse in eintraege)
        return (
            "<html><head><title>INDEX OF /</title></head><body>"
            "<h1>COMMODORE 500 BASIC V2.0</h1>"
            "<p>64K RAM SYSTEM &nbsp;38911 BASIC BYTES FREE</p>"
            f"<ul>{zeilen}</ul>"
            "<p>READY.</p></body></html>",
            "text/html; charset=utf-8")

    # ------------------------------------------------------------------
    # Der Anbiss
    # ------------------------------------------------------------------
    @api.model
    def anbiss_pruefen(self, pfad, adresse):
        """Hat jemand einen ausgelegten Kanarienwert abgerufen?

        Gibt den Köder zurück, wenn ja. Die Prüfung ist absichtlich
        billig: Nur Pfade, die mit dem Präfix beginnen, werden
        überhaupt nachgeschlagen.
        """
        if not pfad or KANARIE_PRAEFIX not in pfad:
            return self.browse()
        # Der Kanarienwert ist ``/cp-...``, beginnt also mit einem
        # Schrägstrich. Ein ``split("/")[0]`` auf dem Rest ab dieser
        # Stelle liefert deshalb eine LEERE Zeichenkette -- der erste
        # Versuch fand nie etwas. Den führenden Schrägstrich beim
        # Zerlegen überspringen und danach wieder ansetzen.
        rest = pfad[pfad.index(KANARIE_PRAEFIX) + 1:]
        teil = KANARIE_PRAEFIX[0] + rest.split("/")[0].split("?")[0]
        koeder = self.sudo().search([("kanarie", "=", teil)], limit=1)
        if not koeder:
            return self.browse()

        # NUR LESEN. Das Vermerken geschieht in
        # ``hochrisiko_eigene_transaktion`` mit eigenem Cursor -- diese
        # Anfrage bricht gleich mit 403 ab, und ein Schreibvorgang in
        # ihrer Transaktion wuerde mit zurueckgerollt. Genau das ist beim
        # ersten Versuch passiert: Der Hochrisiko-Eintrag ueberlebte,
        # der Anbiss am Koeder nicht.
        weitergegeben = adresse and adresse != koeder.eintrag_id.adresse
        _logger.warning(
            "Web RBL: Koeder %s angebissen von %s%s", teil, adresse,
            _(" -- ausgelegt war er fuer %(wem)s, die Daten wurden also "
              "weitergegeben.", wem=koeder.eintrag_id.adresse)
            if weitergegeben else "")
        return koeder
