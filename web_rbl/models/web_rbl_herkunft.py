# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Die echte Absenderadresse bestimmen - und wann man ihr trauen darf.

DIE GEFÄHRLICHSTE STELLE DES GANZEN MODULS
-------------------------------------------
Steht ein Proxy davor, ist ``remote_addr`` die Adresse des PROXY, nicht
die des Besuchers. Wer auf dieser Grundlage sperrt, sperrt den Proxy --
und damit jeden Besucher aller Webseiten auf einmal. Aus einem
Schutzmodul wird so ein Ausfall.

Deshalb ist die Reihenfolge hier umgekehrt zur üblichen: Es wird nicht
gefragt "welche Adresse nehme ich?", sondern zuerst "darf ich überhaupt
sperren?". Im Zweifel lautet die Antwort nein.

WIE ODOO MIT PROXYS UMGEHT (nachgelesen, nicht vermutet)
---------------------------------------------------------
``odoo/http.py`` Zeile 2830::

    if odoo.tools.config['proxy_mode'] and environ.get("HTTP_X_FORWARDED_HOST"):
        ProxyFix(fake_app)(environ, fake_start_response)

Beide Bedingungen müssen erfüllt sein. Erst dann schreibt ProxyFix die
Umgebung um, und ``request.httprequest.remote_addr`` ist der echte
Besucher. Das Modul wertet den Kopfzeileninhalt also **nicht selbst
aus** -- es prüft nur, ob Odoo es getan hat.

``ProxyFix`` ist dabei mit ``x_for=1`` gebunden (http.py:190): Vertraut
wird genau EIN Proxy-Sprung. Stehen zwei Proxys hintereinander, nimmt
Odoo den falschen Eintrag, und dieses Modul mit ihm. Wer die Kette
verlängert, muss ``x_for`` anpassen -- darauf weist die Prüfung unten
hin, indem sie die Anzahl der Einträge in ``X-Forwarded-For`` meldet.

WARUM EIGENE NETZE NIE GESPERRT WERDEN
---------------------------------------
Private Adressbereiche nach RFC 1918, Loopback und die
Link-Local-Bereiche bleiben grundsätzlich außen vor. Eine Sperre dort
trifft entweder den Proxy, einen Kollegen im Haus oder den Server
selbst -- nie einen Angreifer aus dem Netz.
"""

import ipaddress
import logging

from odoo import _, api, models
from odoo.http import request
from odoo.tools import config

_logger = logging.getLogger(__name__)

# Niemals sperren. Trifft nur eigene Infrastruktur.
NIE_SPERREN = (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "127.0.0.0/8", "::1/128",                           # Loopback
    "169.254.0.0/16", "fe80::/10",                      # Link-Local
    "100.64.0.0/10",                                    # CGNAT
)


class WebRblHerkunft(models.AbstractModel):
    _name = "web.rbl.herkunft"
    _description = "Herkunft einer Anfrage bestimmen"

    # ------------------------------------------------------------------
    # Darf gesperrt werden?
    # ------------------------------------------------------------------
    @api.model
    def betriebsbereit(self):
        """(bereit, grund) - ist die Adressbestimmung verlässlich?

        Wird sowohl beim Sperren gefragt als auch in der Oberfläche
        angezeigt. Der Grund ist Klartext und für Menschen gedacht.
        """
        if not request:
            return False, _("Kein Web-Zugriff.")

        proxy_modus = bool(config.get("proxy_mode"))
        umgebung = request.httprequest.environ
        weitergeleitet = umgebung.get("HTTP_X_FORWARDED_FOR")
        weiterleit_host = umgebung.get("HTTP_X_FORWARDED_HOST")

        if proxy_modus and weiterleit_host:
            # Der Normalfall hinter einem Proxy: Odoo hat ProxyFix
            # angewandt, remote_addr ist der echte Besucher.
            sprunge = len((weitergeleitet or "").split(",")) if weitergeleitet else 1
            if sprunge > 1:
                # x_for=1 - Odoo nimmt nur einen Sprung. Bei mehreren
                # Proxys ist die gewaehlte Adresse die des vorletzten
                # Proxys, nicht die des Besuchers.
                return False, _(
                    "X-Forwarded-For enthält %(anzahl)s Einträge, Odoo wertet "
                    "aber nur einen aus (ProxyFix x_for=1). Die ermittelte "
                    "Adresse wäre die eines Zwischenproxys. Es wird nicht "
                    "gesperrt.", anzahl=sprunge)
            return True, ""

        if proxy_modus and not weiterleit_host:
            # proxy_mode ist an, aber diese Anfrage kam ohne
            # Weiterleitungskopf. Entweder direkt am Proxy vorbei oder
            # der Proxy setzt die Kopfzeile nicht. In beiden Faellen
            # ist remote_addr nicht zu gebrauchen.
            return False, _(
                "proxy_mode ist aktiv, aber diese Anfrage trägt keinen "
                "X-Forwarded-Host. Die Adresse ist damit nicht belastbar.")

        if weitergeleitet and not proxy_modus:
            # DER GEFAEHRLICHE FALL. Ein Proxy ist da, Odoo weiss nichts
            # davon. remote_addr ist die Proxy-Adresse - sperren wuerde
            # alle Besucher auf einmal aussperren.
            return False, _(
                "Es kommen X-Forwarded-For-Kopfzeilen an, aber "
                "proxy_mode steht in der odoo.conf nicht auf True. "
                "Odoo sieht deshalb nur die Adresse des Proxys. Es wird "
                "NICHT gesperrt — sonst träfe die Sperre den Proxy und "
                "damit jeden Besucher. Bitte proxy_mode = True setzen.")

        # Kein Proxy im Spiel: remote_addr ist der Besucher.
        return True, ""

    # ------------------------------------------------------------------
    # Die Adresse
    # ------------------------------------------------------------------
    @api.model
    def adresse(self):
        """Die Adresse des Besuchers, oder "" wenn sie unklar ist."""
        bereit, grund = self.betriebsbereit()
        if not bereit:
            self._einmal_warnen(grund)
            return ""
        roh = (request.httprequest.remote_addr or "").strip()
        return roh if self._gueltig(roh) else ""

    @api.model
    def _gueltig(self, roh):
        try:
            ipaddress.ip_address(roh)
        except ValueError:
            return False
        return True

    @api.model
    def sperrbar(self, adresse):
        """Darf diese Adresse überhaupt auf die Liste?"""
        if not adresse or not self._gueltig(adresse):
            return False
        try:
            ip = ipaddress.ip_address(adresse)
        except ValueError:
            return False
        for netz in NIE_SPERREN:
            try:
                if ip in ipaddress.ip_network(netz):
                    return False
            except (ValueError, TypeError):
                continue
        return True

    # ------------------------------------------------------------------
    # Hinweis
    # ------------------------------------------------------------------
    @api.model
    def _einmal_warnen(self, grund):
        """Den Grund ins Protokoll, aber nicht bei jeder Anfrage.

        Ohne diese Bremse schriebe ausgerechnet das Modul, das den
        Protokollmüll beseitigen soll, bei jeder einzelnen Anfrage eine
        Zeile.
        """
        merker = "web_rbl.letzte_warnung"
        Parameter = self.env["ir.config_parameter"].sudo()
        if Parameter.get_param(merker) == grund:
            return
        Parameter.set_param(merker, grund)
        _logger.warning("Web RBL sperrt nicht: %s", grund)
