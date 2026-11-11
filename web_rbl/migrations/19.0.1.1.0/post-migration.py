# -*- coding: utf-8 -*-
"""Uebernimmt Werte des aufgegangenen Moduls website_security_headers."""


def migrate(cr, version):
    for alt, neu in (("website_security_headers.enabled", "web_rbl.security_headers"),
                     ("website_security_headers.hsts", "web_rbl.security_hsts")):
        cr.execute("SELECT value FROM ir_config_parameter WHERE key = %s", (alt,))
        row = cr.fetchone()
        if not row or row[0] is None:
            continue
        cr.execute("SELECT 1 FROM ir_config_parameter WHERE key = %s", (neu,))
        if cr.fetchone():
            continue
        cr.execute("INSERT INTO ir_config_parameter (key, value, create_date, write_date) "
                   "VALUES (%s, %s, now(), now())", (neu, row[0]))
