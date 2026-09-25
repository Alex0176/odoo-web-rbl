# -*- coding: utf-8 -*-
# Copyright 2026 Biricon IT Services e.u
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl).
"""Die Freiliste: Adressen und Netze, die NIE gesperrt werden.

WARUM ES DIESE LISTE GIBT
--------------------------
Am 24.09.2026 hat die Sperrliste die IPsec-Gegenstelle eines Kunden
erwischt. Die Firewall verwarf 4.649 Pakete; der Tunnel stand nur
deshalb noch, weil seine Sicherheitsverbindung aelter war als der
Listeneintrag. Beim naechsten Rekey waere er gefallen.

Die Ursache war ein zu breites Muster, und das ist behoben. Aber die
Lehre ist die allgemeinere: Ein Muster kann sich immer irren, und der
Preis dieses Irrtums ist nicht bei allen Adressen gleich. Bei einem
Scanner aus einem Rechenzentrum kostet ein Fehlalarm nichts. Bei der
Gegenstelle eines Standorttunnels kostet er den Standort.

Deshalb eine zweite Liste, die vor der ersten steht.

WAS SIE TUT UND WAS NICHT
--------------------------
Sie sperrt nicht -- und sie schaltet auch nichts stumm. Eine Adresse
auf der Freiliste wird weiterhin geprueft und weiterhin verbucht; nur
die Folge entfaellt. Was auffaellt, erscheint als Befund in der
Sperrliste, und jemand kann anrufen.

Das ist der Unterschied zu einer Ausnahme in der Firewall: Die macht
blind. Diese hier macht nur geduldig.

WARUM NICHT EINFACH DEN ZUSTAND "FREI" NEHMEN
----------------------------------------------
"frei" ist eine Entscheidung ueber EINE Adresse, nachdem etwas
passiert ist. Die Freiliste ist eine Entscheidung ueber ein NETZ,
bevor etwas passiert -- und sie ueberlebt das Aufraeumen alter
Eintraege. Beides wird gebraucht.
"""
import bisect
import ipaddress
import logging

from odoo import api, fields, models, tools
from odoo.exceptions import ValidationError

_logger = logging.getLogger(__name__)


class WebRblFreiliste(models.Model):
    _name = "web.rbl.freiliste"
    _description = "Freiliste (nie sperren)"
    _order = "quelle, bereich"
    _rec_name = "bereich"

    bereich = fields.Char(
        string="Adresse oder Netz", required=True, index=True,
        help="Einzelne Adresse (81.223.169.254) oder Netz in "
             "CIDR-Schreibweise (81.223.169.0/24). IPv6 ebenso.")
    bemerkung = fields.Char(
        string="Bemerkung",
        help="Wem gehört das und warum steht es hier? In einem Jahr "
             "ist das die einzige Frage, die zählt.")
    partner_id = fields.Many2one(
        "res.partner", string="Kunde", index=True, ondelete="set null",
        help="Wem gehört dieser Anschluss? Damit wird aus einem Befund "
             "ein Anruf: Das Ticket zu einer Fehlkonfiguration weiß "
             "dann von selbst, wen es betrifft.")
    quelle = fields.Selection(
        [("vpn", "VPN-Gegenstelle"),
         ("suchmaschine", "Suchmaschine"),
         ("kunde", "Kundenanschluss"),
         ("eigen", "Eigenes Netz"),
         ("hand", "Von Hand")],
        string="Herkunft", default="hand", required=True, index=True)
    aktiv = fields.Boolean(string="Aktiv", default=True, index=True)

    _bereich_eindeutig = models.Constraint(
        "unique(bereich)",
        "Dieser Bereich steht bereits auf der Freiliste.")

    @api.constrains("bereich")
    def _pruefe_bereich(self):
        for satz in self:
            try:
                ipaddress.ip_network(satz.bereich.strip(), strict=False)
            except ValueError as fehler:
                raise ValidationError(
                    "%s ist keine gültige Adresse und kein gültiges "
                    "Netz: %s" % (satz.bereich, fehler)) from fehler

    # ------------------------------------------------------------------
    # Die Abfrage im Anfrageweg
    # ------------------------------------------------------------------
    @api.model
    @tools.ormcache()
    def _netze(self):
        """Die Freiliste als Tupel von Netzen, zwischengespeichert.

        Sie wird bei JEDER Anfrage gebraucht, die ein Muster trifft,
        und aendert sich fast nie. Sie bei jedem Treffer aus der
        Datenbank zu holen waere die teuerste Art, fast immer dasselbe
        zu erfahren.

        ``ormcache`` gilt je Arbeitsprozess; ``clear_caches`` beim
        Schreiben raeumt ihn in allen ab.
        """
        bereiche = {4: [], 6: []}
        for satz in self.sudo().search([("aktiv", "=", True)]):
            try:
                netz = ipaddress.ip_network(satz.bereich.strip(), strict=False)
            except ValueError:
                _logger.warning(
                    "Web RBL: Freiliste enthaelt einen unbrauchbaren "
                    "Bereich: %s", satz.bereich)
                continue
            bereiche[netz.version].append(
                (int(netz.network_address), int(netz.broadcast_address)))
        # Sortiert und verschmolzen: Danach genuegt eine binaere Suche
        # statt eines Durchlaufs durch die ganze Liste.
        #
        # Der Aufwand lohnt, seit die Suchmaschinenbereiche dazukamen:
        # Die Liste wuchs von 99 auf 1.774 Eintraege, und sie wird
        # weiter wachsen. Gemessen wurden 423 Mikrosekunden je Abfrage
        # bei linearem Durchlauf -- bei jeder Anfrage, die ein Muster
        # trifft.
        for version in (4, 6):
            geordnet = sorted(bereiche[version])
            verschmolzen = []
            for anfang, ende in geordnet:
                if verschmolzen and anfang <= verschmolzen[-1][1] + 1:
                    verschmolzen[-1] = (verschmolzen[-1][0],
                                        max(verschmolzen[-1][1], ende))
                else:
                    verschmolzen.append((anfang, ende))
            bereiche[version] = tuple(verschmolzen)
        return (bereiche[4], bereiche[6])

    @api.model
    def eintrag_zu(self, adresse):
        """Der Freilisteneintrag, der diese Adresse abdeckt, oder leer.

        Anders als ``ist_frei`` liefert das den Datensatz selbst --
        gebraucht für den Kunden dahinter. Bewusst NICHT
        zwischengespeichert: Das läuft nur, wenn ohnehin verbucht
        wird, nicht bei jeder Anfrage.

        Bei mehreren Treffern gewinnt der engste Bereich: Eine
        einzelne Adresse sagt mehr über den Anschlussinhaber aus als
        das /16 drumherum.
        """
        if not adresse:
            return self.browse()
        try:
            geprueft = ipaddress.ip_address(adresse)
        except ValueError:
            return self.browse()
        bester, beste_breite = self.browse(), -1
        for satz in self.sudo().search([("aktiv", "=", True)]):
            try:
                netz = ipaddress.ip_network(satz.bereich.strip(), strict=False)
            except ValueError:
                continue
            if geprueft.version != netz.version or geprueft not in netz:
                continue
            if netz.prefixlen > beste_breite:
                bester, beste_breite = satz, netz.prefixlen
        return bester

    @api.model
    def ist_frei(self, adresse):
        """Steht diese Adresse auf der Freiliste?

        Binaere Suche in vorsortierten, verschmolzenen Bereichen. Das
        laeuft bei jeder Anfrage, die ein Muster trifft -- ein
        Durchlauf durch die ganze Liste waere dort am falschen Platz.
        """
        if not adresse:
            return False
        try:
            geprueft = ipaddress.ip_address(adresse)
        except ValueError:
            return False
        v4, v6 = self._netze()
        bereiche = v4 if geprueft.version == 4 else v6
        if not bereiche:
            return False
        wert = int(geprueft)
        # Der letzte Bereich, dessen Anfang nicht groesser ist als die
        # gesuchte Adresse -- nur der kann sie enthalten, weil die
        # Bereiche sortiert und ueberschneidungsfrei sind.
        i = bisect.bisect_right(bereiche, (wert, float("inf"))) - 1
        if i < 0:
            return False
        return bereiche[i][0] <= wert <= bereiche[i][1]

    # ------------------------------------------------------------------
    def _cache_leeren(self):
        """Den Zwischenspeicher leeren -- und die anderen Prozesse auch.

        ``clear_cache`` MARKIERT nur; benachrichtigt wird erst durch
        ``signal_changes``, und das ruft bei einem Schreibvorgang
        ausserhalb des Anfrageweges niemand. Odoo tut es nach einer
        Anfrage (``service/model.py``) und nach einem Cronlauf
        (``ir_cron.py``) -- in einem Skript oder einer eigenen
        Transaktion aber nicht.

        Gemessen am 25.09.2026 auf der Testinstanz: Eine Adresse frisch
        auf die Freiliste gesetzt, danach sofort eine Anfrage von
        dieser Adresse -- und sie wurde trotzdem gesperrt. Der
        laufende Dienst kannte die Liste noch in der alten Fassung.
        Genau das darf bei einer Freiliste nicht passieren: Wer eine
        Adresse freistellt, tut das meist, WEIL sie gerade
        ausgesperrt ist.

        NACH dem Festschreiben, nicht davor. Wer zuerst benachrichtigt
        und dann schreibt, bringt die anderen Prozesse dazu, ihren
        Zwischenspeicher zu leeren und sofort den ALTEN Stand neu
        einzulesen -- danach halten sie ihn fuer frisch. Deshalb
        haengt der Ruf am ``postcommit`` des Cursors.
        """
        self.env.registry.clear_cache()
        registry = self.env.registry

        def benachrichtigen():
            try:
                if registry.ready:
                    registry.signal_changes()
            except Exception:  # noqa: BLE001
                # Misslingt die Benachrichtigung, ist die Liste im
                # eigenen Prozess trotzdem richtig und in den anderen
                # spaetestens nach deren naechstem Neustart. Ein
                # Fehler hier darf den Schreibvorgang nicht umwerfen.
                _logger.warning(
                    "Web RBL: Freiliste geaendert, andere Prozesse "
                    "konnten aber nicht benachrichtigt werden.")

        try:
            self.env.cr.postcommit.add(benachrichtigen)
        except AttributeError:
            # Aeltere Cursor kennen postcommit nicht.
            benachrichtigen()

    @api.model_create_multi
    def create(self, werteliste):
        saetze = super().create(werteliste)
        saetze._cache_leeren()
        # Wer neu auf die Freiliste kommt, soll nicht wegen einer
        # alten Sperre draussen bleiben. Eine bestehende Sperre wird
        # deshalb sofort aufgehoben -- sonst waere die Freiliste eine
        # Zusage, die erst morgen gilt.
        saetze._bestehende_sperren_loesen()
        return saetze

    def write(self, werte):
        ergebnis = super().write(werte)
        self._cache_leeren()
        if werte.get("aktiv", True):
            self._bestehende_sperren_loesen()
        return ergebnis

    def unlink(self):
        ergebnis = super().unlink()
        self._cache_leeren()
        return ergebnis

    # ------------------------------------------------------------------
    # Zyklischer Abgleich mit der Firewall
    # ------------------------------------------------------------------
    @api.model
    def _cron_gegenstellen_abgleichen(self):
        """Die VPN-Gegenstellen von der Firewall holen und abgleichen.

        WARUM ZYKLISCH UND NICHT VON HAND
        ----------------------------------
        Eine Freiliste, die jemand von Hand pflegt, ist am Tag ihrer
        Anlage richtig. Ein neuer Standorttunnel entsteht aber, ohne
        dass jemand an die Sperrliste denkt -- und faellt dann beim
        ersten falsch beurteilten Muster aus. Genau diese Luecke soll
        die Liste schliessen, also muss sie sich selbst nachfuehren.

        DIE WICHTIGSTE REGEL STEHT UNTEN: NIE LEEREN
        ---------------------------------------------
        Antwortet die Gegenseite nicht, antwortet sie leer oder
        unverstaendlich, bleibt die Liste UNVERAENDERT. Eine
        Freiliste, die sich bei einer Stoerung selbst loescht, nimmt
        im schlechtesten Moment alle Tunnel mit: Die Firewall ist
        nicht erreichbar, also sind auch die Gegenstellen nicht mehr
        geschuetzt -- und ein Fehlalarm trifft dann alles auf einmal.

        Ein veralteter Eintrag kostet hoechstens eine uebersehene
        Sonde. Ein geloeschter kostet einen Standort.

        EINZURICHTEN
        ------------
            web_rbl.freiliste_quelle_url    = http://10.10.10.105/...
            web_rbl.freiliste_quelle_token  = <optional>
        """
        Parameter = self.env["ir.config_parameter"].sudo()
        adresse = (Parameter.get_param("web_rbl.freiliste_quelle_url") or
                   "").strip()
        if not adresse:
            return True

        gelesen = self._quelle_lesen(adresse, Parameter)
        if gelesen is None:
            # Schon gemeldet. Liste bleibt, wie sie ist.
            return True
        if not gelesen:
            _logger.warning(
                "Web RBL: Die Gegenstellenquelle %s hat eine LEERE Liste "
                "geliefert. Die Freiliste bleibt unveraendert -- eine "
                "leere Antwort wird nie als 'keine Gegenstellen mehr' "
                "gedeutet.", adresse)
            return True

        vorhanden = {
            satz.bereich.strip(): satz
            for satz in self.sudo().search([("quelle", "=", "vpn")])
        }
        neu = angepasst = 0
        for bereich, bemerkung in gelesen.items():
            satz = vorhanden.pop(bereich, None)
            if satz is None:
                self.sudo().create({
                    "bereich": bereich,
                    "bemerkung": bemerkung,
                    "quelle": "vpn",
                    "aktiv": True,
                })
                neu += 1
            elif not satz.aktiv or satz.bemerkung != bemerkung:
                satz.write({"aktiv": True, "bemerkung": bemerkung})
                angepasst += 1

        # Was die Firewall nicht mehr nennt, wird STILLGELEGT, nicht
        # geloescht. Der Eintrag bleibt sichtbar, mitsamt Bemerkung --
        # wer nachsieht, warum eine Adresse ploetzlich wieder gesperrt
        # werden kann, findet hier die Antwort statt einer Luecke.
        entfallen = 0
        for satz in vorhanden.values():
            if satz.aktiv:
                satz.write({
                    "aktiv": False,
                    "bemerkung": (satz.bemerkung or "")
                                 + " [von der Firewall nicht mehr genannt]",
                })
                entfallen += 1

        if neu or angepasst or entfallen:
            _logger.info(
                "Web RBL: Gegenstellen abgeglichen -- %s neu, %s angepasst, "
                "%s stillgelegt (Quelle nannte %s).",
                neu, angepasst, entfallen, len(gelesen))
        return True

    # Die Betreiber veröffentlichen die Adressbereiche ihrer Crawler
    # selbst, damit man sie sicher erkennen kann. Das ist die einzige
    # verlässliche Art: Die Kennung im User-Agent kann jeder
    # hinschreiben.
    SUCHMASCHINEN = (
        ("Googlebot",
         "https://developers.google.com/search/apis/ipranges/googlebot.json"),
        ("Google Sonderdienste",
         "https://developers.google.com/search/apis/ipranges/"
         "special-crawlers.json"),
        ("Google benutzerausgelöst",
         "https://developers.google.com/search/apis/ipranges/"
         "user-triggered-fetchers.json"),
        ("Bingbot",
         "https://www.bing.com/toolbox/bingbot.json"),
    )

    @api.model
    def _cron_suchmaschinen_abgleichen(self):
        """Die Adressbereiche der Suchmaschinen holen.

        WARUM DAS SEIN MUSS
        -------------------
        Eine Sperrliste, die einen Suchmaschinen-Crawler erwischt,
        richtet mehr Schaden an als der Angriff, den sie verhindert:
        Die Seite verschwindet aus dem Index, und zwar lautlos. Man
        merkt es erst Wochen später am ausbleibenden Verkehr.

        Besonders gefährdet ist die Verhaltenserkennung. Sie schaut
        nicht auf Pfade, sondern auf das Verhältnis von Fehlschlägen
        zu Treffern &ndash; und ein Crawler, der eine Reihe
        verschwundener Seiten abklappert, sieht für einen Moment
        genauso aus wie ein Scanner.

        WARUM ÜBER DIE ADRESSBEREICHE UND NICHT ÜBER DIE KENNUNG
        ---------------------------------------------------------
        ``Googlebot`` in den User-Agent zu schreiben kostet nichts,
        und genau das tun Scanner, die nicht auffallen wollen. Google
        und Microsoft veröffentlichen ihre Adressbereiche deshalb
        selbst. Nur wer aus einem dieser Bereiche kommt, ist es auch.

        Die Bereiche ändern sich; deshalb täglich.
        """
        Parameter = self.env["ir.config_parameter"].sudo()
        if Parameter.get_param("web_rbl.suchmaschinen_aktiv", "1") != "1":
            return True

        import json
        import urllib.error
        import urllib.request

        gefunden = {}
        for name, adresse in self.SUCHMASCHINEN:
            try:
                with urllib.request.urlopen(adresse, timeout=20) as antwort:
                    roh = antwort.read(1024 * 512).decode("utf-8", "replace")
                daten = json.loads(roh)
            except (urllib.error.URLError, OSError, ValueError) as fehler:
                # Eine Quelle, die heute nicht antwortet, darf die
                # anderen nicht aufhalten -- und schon gar nicht die
                # bestehende Liste leeren.
                _logger.warning(
                    "Web RBL: Adressbereiche von %s nicht abrufbar: %s",
                    name, fehler)
                continue
            for eintrag in daten.get("prefixes", []):
                bereich = eintrag.get("ipv4Prefix") or eintrag.get("ipv6Prefix")
                if bereich:
                    gefunden[bereich.strip()] = name

        if not gefunden:
            # Dieselbe Regel wie bei den Gegenstellen: Eine leere
            # Antwort heisst "nicht erfahren", nie "gibt es nicht
            # mehr". Eine Sperrliste, die sich bei einer Stoerung
            # selbst die Suchmaschinen entzieht, waere die teuerste
            # Art von Stille.
            _logger.warning(
                "Web RBL: Keine einzige Suchmaschinenquelle war "
                "abrufbar. Die Freiliste bleibt unveraendert.")
            return True

        vorhanden = {
            satz.bereich.strip(): satz
            for satz in self.sudo().search([("quelle", "=", "suchmaschine")])
        }
        neu = angepasst = 0
        for bereich, name in gefunden.items():
            satz = vorhanden.pop(bereich, None)
            if satz is None:
                self.sudo().create({
                    "bereich": bereich,
                    "bemerkung": name,
                    "quelle": "suchmaschine",
                    "aktiv": True,
                })
                neu += 1
            elif not satz.aktiv or satz.bemerkung != name:
                satz.write({"aktiv": True, "bemerkung": name})
                angepasst += 1

        entfallen = 0
        for satz in vorhanden.values():
            if satz.aktiv:
                satz.write({
                    "aktiv": False,
                    "bemerkung": (satz.bemerkung or "")
                                 + " [nicht mehr veröffentlicht]",
                })
                entfallen += 1

        if neu or angepasst or entfallen:
            _logger.info(
                "Web RBL: Suchmaschinen abgeglichen -- %s neu, %s angepasst, "
                "%s stillgelegt (Quellen nannten %s Bereiche).",
                neu, angepasst, entfallen, len(gefunden))
        return True

    @api.model
    def _quelle_lesen(self, adresse, Parameter):
        """Holt die Liste. Gibt ein Verzeichnis oder None zurück.

        ``None`` heisst ausdruecklich "nicht erfahren" und NICHT
        "nichts vorhanden". Nur so kann der Aufrufer den Unterschied
        machen, an dem hier alles haengt.

        Angenommen werden zwei Formen, damit die Gegenseite die
        einfachere waehlen kann:

        * JSON: ``{"gegenstellen": [{"bereich": "...",
          "bemerkung": "..."}]}`` oder schlicht eine Liste von
          Zeichenketten.
        * Text: eine Adresse je Zeile, wahlweise mit ``#`` und einer
          Bemerkung dahinter. Leerzeilen und Kommentarzeilen werden
          uebergangen.
        """
        import json
        import urllib.error
        import urllib.request

        token = (Parameter.get_param("web_rbl.freiliste_quelle_token") or
                 "").strip()
        anfrage = urllib.request.Request(adresse)
        if token:
            anfrage.add_header("Authorization", "Bearer %s" % token)
        try:
            with urllib.request.urlopen(anfrage, timeout=15) as antwort:
                roh = antwort.read(1024 * 256).decode("utf-8", "replace")
        except (urllib.error.URLError, OSError, ValueError) as fehler:
            _logger.warning(
                "Web RBL: Gegenstellen nicht abrufbar (%s): %s. Die "
                "Freiliste bleibt unveraendert.", adresse, fehler)
            return None

        gelesen = {}
        roh = roh.strip()
        if roh.startswith("{") or roh.startswith("["):
            try:
                daten = json.loads(roh)
            except ValueError as fehler:
                _logger.warning(
                    "Web RBL: Antwort von %s ist kein brauchbares JSON: "
                    "%s. Die Freiliste bleibt unveraendert.",
                    adresse, fehler)
                return None
            if isinstance(daten, dict):
                daten = daten.get("gegenstellen", [])
            for eintrag in daten or []:
                if isinstance(eintrag, str):
                    gelesen[eintrag.strip()] = ""
                elif isinstance(eintrag, dict):
                    bereich = (eintrag.get("bereich") or "").strip()
                    if bereich:
                        gelesen[bereich] = (
                            eintrag.get("bemerkung") or "")[:200]
        else:
            for zeile in roh.splitlines():
                zeile = zeile.strip()
                if not zeile or zeile.startswith("#"):
                    continue
                bereich, _, bemerkung = zeile.partition("#")
                bereich = bereich.strip()
                if bereich:
                    gelesen[bereich] = bemerkung.strip()[:200]

        # Unbrauchbares gleich hier aussortieren, damit ein einzelner
        # Tippfehler in der Quelle nicht den ganzen Abgleich abbricht.
        geprueft = {}
        for bereich, bemerkung in gelesen.items():
            try:
                ipaddress.ip_network(bereich, strict=False)
            except ValueError:
                _logger.warning(
                    "Web RBL: Gegenstellenquelle nennt einen "
                    "unbrauchbaren Bereich, uebergangen: %s", bereich)
                continue
            geprueft[bereich] = bemerkung
        return geprueft

    def _bestehende_sperren_loesen(self):
        Eintrag = self.env["web.rbl.eintrag"].sudo()
        gesperrt = Eintrag.search([
            ("zustand", "in", ("gesperrt", "dauerhaft", "hochrisiko")),
        ])
        betroffen = gesperrt.filtered(lambda e: self.ist_frei(e.adresse))
        if not betroffen:
            return
        for eintrag in betroffen:
            eintrag.write({
                "zustand": "frei",
                "gesperrt_bis": False,
                "notiz": (eintrag.notiz or "")
                         + ("\n" if eintrag.notiz else "")
                         + "Freigegeben, weil die Adresse auf die "
                           "Freiliste aufgenommen wurde.",
            })
        _logger.info(
            "Web RBL: %s Sperre(n) wegen Aufnahme in die Freiliste "
            "geloest.", len(betroffen))
