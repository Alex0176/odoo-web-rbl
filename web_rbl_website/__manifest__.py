# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
{
    "name": "Web RBL - Falle für die Website",
    "summary": "Legt einen für Menschen unsichtbaren, mit rel=nofollow "
               "versehenen Verweis in jede Seite -- wer ihm folgt, ist "
               "praktisch garantiert kein Besucher.",
    "description": """
Web RBL - Falle für die Website
================================

Ein eigenes, kleines Modul, damit ``web_rbl`` selbst ohne das
``website``-Modul installierbar bleibt.

Legt einen Verweis in jede ausgelieferte Seite, den kein Mensch sehen
kann: für Menschen unsichtbar positioniert, mit ``rel="nofollow"``
versehen. Eine Suchmaschine, die sich an die Regeln hält, findet ihn
nie oder folgt ihm nicht -- **Indexieren ist kein Angriff.** Wer eine
Seite roh einliest und jedem Verweis folgt, ohne auf Sichtbarkeit oder
``nofollow`` zu achten, tut etwas anderes.

Der Pfad wird beim ersten Seitenaufruf einmalig erzeugt und in
``web_rbl.falle_pfad`` abgelegt. Jeder Abruf dieses Pfades wird von
``web_rbl`` sofort und ohne Schwelle gesperrt.
    """,
    "version": "19.0.1.0.0",
    "category": "Website",
    "author": "Biricon IT Services e.u",
    "website": "https://www.biricon.eu/",
    "license": "AGPL-3",
    "depends": ["web_rbl", "website"],
    "data": [
        "views/web_rbl_falle_templates.xml",
    ],
    "installable": True,
    "auto_install": False,
}
