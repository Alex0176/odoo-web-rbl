# -*- coding: utf-8 -*-
from werkzeug.datastructures import Headers

from odoo.tests.common import HttpCase, TransactionCase, tagged

from ..models.ir_http_sicherheit import (
    sec_cookies_sichern, sec_header_setzen, sec_im_geltungsbereich)


@tagged("post_install", "-at_install")
class TestSicherheitHeader(TransactionCase):

    def test_geltungsbereich(self):
        for p in ("/", "/shop", "/blog/x", "/contactus", "/fahrer",
                  "/web/assets/1/a.css", "/web/image/3", "/web/static/x"):
            self.assertTrue(sec_im_geltungsbereich(p), p)
        for p in ("/odoo", "/odoo/x", "/web/login", "/web", "/websocket",
                  "/ortung/api/v1", "/jsonrpc", "/mail/x", "/web/session/x"):
            self.assertFalse(sec_im_geltungsbereich(p), p)

    def test_html(self):
        h = Headers([("Content-Type", "text/html; charset=utf-8")])
        sec_header_setzen(h, "/shop", True, True)
        self.assertEqual(h["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(h["X-Frame-Options"], "SAMEORIGIN")
        self.assertEqual(h["Content-Security-Policy"], "frame-ancestors 'self'")
        self.assertIn("camera=()", h["Permissions-Policy"])

    def test_nicht_html_und_http(self):
        h = Headers([("Content-Type", "text/css")])
        sec_header_setzen(h, "/web/assets/x.css", False, True)
        self.assertNotIn("X-Frame-Options", h)
        self.assertNotIn("Content-Security-Policy", h)
        self.assertNotIn("Strict-Transport-Security", h)
        self.assertIn("Referrer-Policy", h)

    def test_fahrer_und_vorhandene_header(self):
        h = Headers([("Content-Type", "text/html"),
                     ("Content-Security-Policy", "default-src 'self'")])
        sec_header_setzen(h, "/fahrer", True, False)
        self.assertIn("camera=(self)", h["Permissions-Policy"])
        self.assertIn("geolocation=(self)", h["Permissions-Policy"])
        self.assertEqual(h["Content-Security-Policy"], "default-src 'self'")
        self.assertNotIn("Strict-Transport-Security", h)
        vorher = h["Permissions-Policy"]
        sec_header_setzen(h, "/fahrer", True, False)
        self.assertEqual(h["Permissions-Policy"], vorher)
        self.assertEqual(len(h.getlist("Permissions-Policy")), 1)

    def test_cookies(self):
        h = Headers()
        h.add("Set-Cookie", "session_id=abc; HttpOnly; Path=/")
        h.add("Set-Cookie", "frontend_lang=de_DE; Path=/")
        h.add("Set-Cookie", "other=1; Path=/")
        sec_cookies_sichern(h)
        c = h.getlist("Set-Cookie")
        self.assertTrue(c[0].endswith("; Secure"))
        self.assertNotIn("SameSite", c[0])
        self.assertIn("; Secure", c[1])
        self.assertIn("SameSite=Lax", c[1])
        self.assertEqual(c[2], "other=1; Path=/")


@tagged("post_install", "-at_install")
class TestListenToken(HttpCase):
    """Die Sperrliste gibt es nur mit Token im Kopf; in der Adresse nur auf Wunsch."""

    def test_token_im_kopf_statt_in_der_adresse(self):
        Param = self.env["ir.config_parameter"].sudo()
        Param.set_param("web_rbl.token", "geheim-fuer-den-test")
        Param.set_param("web_rbl.token_url_erlaubt", "0")
        kopf = {"Authorization": "Bearer geheim-fuer-den-test"}
        self.assertEqual(self.url_open("/web_rbl/liste", headers=kopf).status_code, 200)
        self.assertEqual(self.url_open(
            "/web_rbl/liste", headers={"Authorization": "Bearer falsch"}).status_code, 404)
        self.assertEqual(self.url_open("/web_rbl/liste").status_code, 404)
        self.assertEqual(self.url_open(
            "/web_rbl/liste?token=geheim-fuer-den-test").status_code, 404)
        Param.set_param("web_rbl.token_url_erlaubt", "1")
        self.assertEqual(self.url_open(
            "/web_rbl/liste?token=geheim-fuer-den-test").status_code, 200)
        self.assertEqual(self.url_open("/web_rbl/liste?token=falsch").status_code, 404)
