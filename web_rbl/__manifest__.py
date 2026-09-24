# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
{
    "name": "Web RBL - Sperrliste für Angriffsverkehr",
    "summary": "Erkennt Sondierungsanfragen, führt eine Sperrliste und "
               "veröffentlicht sie für HAProxy, nftables oder ipset.",
    "description": """
Web RBL
=======

Öffentliche Webseiten werden dauerhaft nach bekannten Schwachstellen
abgesucht: ``.env``, ``.git/config``, WordPress-Pfade, Verzeichniswechsel
mit ``..``. Auf einer gemessenen Installation waren das **13 Prozent
aller Anfragen** über siebzehn Tage.

Teuer ist daran nicht die Abwehr, sondern der Weg dorthin: Odoo versucht
für jede dieser Anfragen eine vollständige Fehlerseite zu rendern, und
bei Verzeichniswechseln scheitert auch das noch einmal. Aus einer
einzigen Sonde werden so zwei Stapelprotokolle.

Dieses Modul erkennt solche Anfragen am frühestmöglichen Punkt, führt
Buch und kann die Quelle sperren. Die Sperrliste wird als schlichte
Textliste veröffentlicht, wie HAProxy, nftables und ipset sie lesen.
    """,
    "version": "19.0.1.0.0",
    "category": "Website",
    "author": "Biricon IT Services e.u",
    "website": "https://www.biricon.eu/",
    "license": "AGPL-3",
    "depends": ["base", "web"],
    "data": [
        "security/web_rbl_groups.xml",
        "security/ir.model.access.csv",
        "data/web_rbl_data.xml",
        "views/web_rbl_views.xml",
        "views/web_rbl_menu.xml",
    ],
    "installable": True,
    "application": True,
}
