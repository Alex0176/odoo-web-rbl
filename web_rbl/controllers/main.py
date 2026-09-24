# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Die Sperrliste veröffentlichen - für HAProxy, nftables und ipset.

DAS FORMAT IST ABSICHTLICH DAS ÄRMSTE
--------------------------------------
Eine Adresse je Zeile, sonst nichts. Kein JSON, kein XML, keine
Kopfzeile. Genau das lesen alle drei Abnehmer ohne Umweg::

    HAProxy   acl gesperrt src -f /etc/haproxy/rbl.lst
    nftables  nft -f - <<< "add element inet filter rbl { ... }"
    ipset     ipset restore

Ein reicheres Format hätte hier keinen Abnehmer, aber jeden von ihnen
einen Parser gekostet.

ZUGANG
------
Der Endpunkt ist öffentlich erreichbar, aber über einen Token in der
Adresse geschützt (``web_rbl.token``). Eine Sperrliste ist kein
Geheimnis -- wer sie liest, erfährt nur, wer uns angegriffen hat. Der
Token verhindert, dass sie beiläufig eingesammelt und anderswo
eingespielt wird: Unsere Beobachtung ist unsere Beobachtung, und eine
falsch übernommene Sperre trifft bei einem Dritten womöglich einen
echten Besucher.
"""

import logging

from odoo import fields, http
from odoo.http import request

_logger = logging.getLogger(__name__)


class WebRblController(http.Controller):

    @http.route("/web_rbl/liste", type="http", auth="public",
                methods=["GET"], csrf=False, save_session=False)
    def liste(self, token=None, **kw):
        """Die gesperrten Adressen als Textliste."""
        if not self._token_gueltig(token):
            # 404 statt 403: Wer den Token nicht hat, soll nicht einmal
            # erfahren, dass es den Endpunkt gibt.
            return request.not_found()

        adressen = self._gesperrte()
        text = "\n".join(adressen)
        if text:
            text += "\n"
        return request.make_response(text, headers=[
            ("Content-Type", "text/plain; charset=utf-8"),
            ("X-Rbl-Count", str(len(adressen))),
            ("X-Rbl-Generated", fields.Datetime.to_string(
                fields.Datetime.now())),
            # Kein Zwischenspeichern: Eine Sperrliste, die zehn Minuten
            # alt ist, sperrt zehn Minuten zu wenig.
            ("Cache-Control", "no-store"),
        ])

    @http.route("/web_rbl/liste/hochrisiko", type="http", auth="public",
                methods=["GET"], csrf=False, save_session=False)
    def liste_hochrisiko(self, token=None, **kw):
        """Nur die nachweislich Aktiven.

        Auf dieser Liste steht nur, wer einen Kanarienwert abgerufen hat
        -- einen Pfad, den es ausschliesslich in einer von uns
        ausgelieferten Faelschung gab. Hier ist kein Fehlalarm moeglich,
        und hier gibt es keine Frist.

        Getrennt von der Hauptliste, weil die Folgen andere sind: Auf
        der grossen Liste stehen auch Adressen, die morgen jemand
        anderem gehoeren. Diese hier kann man ohne schlechtes Gewissen
        dauerhaft in eine Firewall haengen.
        """
        if not self._token_gueltig(token):
            return request.not_found()
        Eintrag = request.env["web.rbl.eintrag"].sudo()
        adressen = sorted({
            e["adresse"] for e in Eintrag.search_read(
                [("zustand", "=", "hochrisiko")], ["adresse"])
            if e["adresse"]})
        text = "\n".join(adressen)
        if text:
            text += "\n"
        return request.make_response(text, headers=[
            ("Content-Type", "text/plain; charset=utf-8"),
            ("X-Rbl-Count", str(len(adressen))),
            ("X-Rbl-Kind", "hochrisiko"),
            ("Cache-Control", "no-store"),
        ])

    @http.route("/web_rbl/liste.json", type="http", auth="public",
                methods=["GET"], csrf=False, save_session=False)
    def liste_json(self, token=None, **kw):
        """Dieselbe Liste mit Zusatzangaben, für eigene Auswertungen."""
        if not self._token_gueltig(token):
            return request.not_found()
        import json
        Eintrag = request.env["web.rbl.eintrag"].sudo()
        jetzt = fields.Datetime.now()
        eintraege = Eintrag.search([
            "|", "|",
            ("zustand", "=", "dauerhaft"),
            ("zustand", "=", "hochrisiko"),
            "&", ("zustand", "=", "gesperrt"), ("gesperrt_bis", ">", jetzt),
        ])
        daten = [{
            "adresse": e.adresse,
            "zustand": e.zustand,
            "treffer": e.treffer_anzahl,
            "tage": e.tage_auffaellig,
            "gesperrt_bis": fields.Datetime.to_string(e.gesperrt_bis) or None,
            "letzter_pfad": e.letzter_pfad,
        } for e in eintraege]
        return request.make_response(
            json.dumps({"stand": fields.Datetime.to_string(jetzt),
                        "anzahl": len(daten), "eintraege": daten},
                       ensure_ascii=False, indent=1),
            headers=[("Content-Type", "application/json; charset=utf-8"),
                     ("Cache-Control", "no-store")])

    # ------------------------------------------------------------------
    def _token_gueltig(self, token):
        erwartet = request.env["ir.config_parameter"].sudo().get_param(
            "web_rbl.token")
        if not erwartet:
            _logger.warning(
                "Web RBL: Es ist kein Token gesetzt (web_rbl.token) -- die "
                "Liste wird nicht ausgeliefert.")
            return False
        # Vergleich in konstanter Zeit, damit sich der Token nicht über
        # die Antwortdauer erraten laesst.
        import hmac
        return hmac.compare_digest(str(token or ""), str(erwartet))

    def _gesperrte(self):
        """Die Adressen, eine je Zeile, sortiert."""
        Eintrag = request.env["web.rbl.eintrag"].sudo()
        jetzt = fields.Datetime.now()
        # Hochrisiko gehoert AUCH auf die Hauptliste. Wer sie in eine
        # Firewall haengt, soll die schaerfste Stufe nicht deshalb
        # verpassen, weil es fuer sie noch eine eigene Liste gibt.
        eintraege = Eintrag.search_read([
            "|", "|",
            ("zustand", "=", "dauerhaft"),
            ("zustand", "=", "hochrisiko"),
            "&", ("zustand", "=", "gesperrt"), ("gesperrt_bis", ">", jetzt),
        ], ["adresse"], order="adresse")
        return sorted({e["adresse"] for e in eintraege if e["adresse"]})
