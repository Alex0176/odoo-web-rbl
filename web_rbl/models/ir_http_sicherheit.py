# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services GmbH
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Sicherheits-Header fuer Webseiten- und Asset-Antworten.

``ir.http._post_dispatch`` laeuft fuer jede geroutete Antwort, auch fuer
die, die ein Seitencache aus ``_dispatch`` liefert. Backend-, API- und
Websocket-Pfade bleiben unberuehrt. Dieses Modul ueberschreibt KEIN
``_dispatch`` und kein ``_match``/``_handle_error`` -- das Sperr- und
Meldeverhalten bleibt davon unabhaengig.

Systemparameter (Vorgabe 1): ``web_rbl.security_headers``,
``web_rbl.security_hsts``.
"""
import logging

import werkzeug.serving

from odoo import models
from odoo.http import request

_logger = logging.getLogger(__name__)

PARAM_HEADERS = "web_rbl.security_headers"
PARAM_HSTS = "web_rbl.security_hsts"

# Nie angefasst: Backend, API-Clients, Websocket, JSON-RPC.
SEC_SKIP_PREFIXES = (
    "/odoo", "/web", "/ortung", "/websocket", "/jsonrpc", "/xmlrpc",
    "/longpolling", "/mail", "/api", "/json", "/calendar", "/mail_plugin",
)
# ... ausser diesen /web-Pfaden, die Assets und Bilder der Webseite liefern.
SEC_WEB_ERLAUBT = ("/web/assets/", "/web/image", "/web/static/",
                   "/web/content")
# Fahrer-App: braucht Kamera (QR) und Standort der eigenen Herkunft.
SEC_SELF_PREFIXES = ("/fahrer",)

SEC_PERMISSIONS = "camera=(), microphone=(), geolocation=(), payment=()"
SEC_PERMISSIONS_SELF = ("camera=(self), microphone=(), geolocation=(self), "
                        "payment=()")
SEC_HSTS = "max-age=31536000"
SEC_COOKIES = ("session_id", "frontend_lang")


def _version_string(self):
    return "odoo"


# Den ``Server``-Header schreibt der HTTP-Server selbst (setzt die
# Anwendung einen eigenen, steht er doppelt) -- also an der Quelle kuerzen.
werkzeug.serving.WSGIRequestHandler.version_string = _version_string


def sec_im_geltungsbereich(path):
    if path.startswith(SEC_WEB_ERLAUBT):
        return True
    for prefix in SEC_SKIP_PREFIXES:
        if path == prefix or path.startswith(prefix + "/") \
                or path.startswith(prefix + "?"):
            return False
    return True


def sec_header_setzen(headers, path, https, hsts):
    """Setzt die Header auf ``headers`` (werkzeug Headers); setzt nie
    einen schon vorhandenen Header um."""
    if https and hsts and "Strict-Transport-Security" not in headers:
        headers["Strict-Transport-Security"] = SEC_HSTS
    if "Referrer-Policy" not in headers:
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if "Permissions-Policy" not in headers:
        selbst = path.startswith(SEC_SELF_PREFIXES)
        headers["Permissions-Policy"] = (
            SEC_PERMISSIONS_SELF if selbst else SEC_PERMISSIONS)
    if (headers.get("Content-Type") or "").startswith("text/html"):
        csp = headers.get("Content-Security-Policy")
        if "X-Frame-Options" not in headers \
                and not (csp and "frame-ancestors" in csp):
            headers["X-Frame-Options"] = "SAMEORIGIN"
        if not csp:
            headers["Content-Security-Policy"] = "frame-ancestors 'self'"


def sec_cookies_sichern(headers):
    cookies = headers.getlist("Set-Cookie")
    if not cookies:
        return
    geaendert = False
    neu = []
    for cookie in cookies:
        name = cookie.split("=", 1)[0].strip()
        if name in SEC_COOKIES:
            lower = cookie.lower()
            if "; secure" not in lower:
                cookie += "; Secure"
                geaendert = True
            # SameSite nur fuer das Sprachcookie: das Sitzungscookie behaelt
            # den Browser-Standard, damit Ruecksprung von Zahlungsanbietern
            # (fremde Herkunft) die Sitzung behaelt.
            if name == "frontend_lang" and "samesite" not in lower:
                cookie += "; SameSite=Lax"
                geaendert = True
        neu.append(cookie)
    if geaendert:
        headers.remove("Set-Cookie")
        for cookie in neu:
            headers.add("Set-Cookie", cookie)


class IrHttpSicherheit(models.AbstractModel):
    _inherit = "ir.http"

    @classmethod
    def _post_dispatch(cls, response):
        super()._post_dispatch(response)
        try:
            cls._sec_anwenden(response)
        except Exception:  # noqa: BLE001
            _logger.exception("Web RBL Sicherheits-Header: nicht gesetzt")

    @classmethod
    def _sec_param(cls, name):
        # get_param ist ormcached: keine Abfrage je Anfrage
        wert = request.env["ir.config_parameter"].sudo().get_param(name, "1")
        return wert not in ("0", "False", "false", "")

    @classmethod
    def _sec_anwenden(cls, response):
        path = request.httprequest.path or "/"
        if not sec_im_geltungsbereich(path) \
                or not cls._sec_param(PARAM_HEADERS):
            return
        https = request.httprequest.scheme == "https"
        sec_header_setzen(response.headers, path, https,
                          cls._sec_param(PARAM_HSTS))
        if https:
            sec_cookies_sichern(response.headers)
