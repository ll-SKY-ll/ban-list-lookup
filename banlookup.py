from __future__ import annotations

import fnmatch
import html
import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from pkg_resources import resource_string
from aiohttp import web
from mautrix.types import EventType, StateEvent
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper
from maubot import Plugin, MessageEvent
from maubot.handlers import command, event, web as web_handler

POLICY_USER = EventType.find("m.policy.rule.user", t_class=EventType.Class.STATE)
POLICY_SERVER = EventType.find("m.policy.rule.server", t_class=EventType.Class.STATE)
POLICY_ROOM = EventType.find("m.policy.rule.room", t_class=EventType.Class.STATE)

LEGACY = [
    (EventType.find(f"{ns}.rule.{kind}", t_class=EventType.Class.STATE), kind)
    for ns in ("org.matrix.mjolnir", "m.room")
    for kind in ("user", "server", "room")
]

RULE_TYPES: dict[EventType, str] = {
    POLICY_USER: "user",
    POLICY_SERVER: "server",
    POLICY_ROOM: "room",
}
for _t, _kind in LEGACY:
    RULE_TYPES[_t] = _kind

_VALID_ENTITY = re.compile(r"^[A-Za-z0-9_.:@#!*?/+=-]{1,255}$")


@dataclass
class Match:
    room_id: str
    room_name: str
    room_topic: str
    label: str
    rule_type: str
    entity: str
    recommendation: str
    reason: str
    sender: str
    origin_ts: int
    contacts: list[str] = field(default_factory=list)


def classify(entity: str) -> str:
    """Cheapest matching strategy an entity needs."""
    if "*" not in entity and "?" not in entity:
        return "exact"
    rest = entity[2:]
    if entity.startswith("*:") and "*" not in rest and "?" not in rest:
        return "server_suffix"
    if entity.startswith("*.") and "*" not in rest and "?" not in rest:
        return "dot_suffix"
    return "regex"


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        helper.copy("command_prefix")
        helper.copy("respond_in_rooms")
        helper.copy("show_sender")
        helper.copy("max_inline_matches")
        helper.copy("rate_limit_count")
        helper.copy("rate_limit_window")
        helper.copy("rate_limit_exempt")
        helper.copy("admins")
        helper.copy("contacts")
        helper.copy("room_labels")
        helper.copy("web_brand")


class BanLookupBot(Plugin):
    db: sqlite3.Connection
    _regex_rules: list[tuple[re.Pattern, str]]
    _rl_hits: dict[str, deque]   # mxid -> timestamps of recent commands

    _index_html: str = resource_string("banlookup", "web/index.html").decode("utf-8")

    async def start(self) -> None:
        self.config.load_and_update()
        db_path = self._resolve_db_path()
        self.log.info(f"banlookup SQLite at {db_path}")
        self.db = sqlite3.connect(db_path)
        self.db.row_factory = sqlite3.Row
        self._init_db()
        self._regex_rules = []
        self._rl_hits = defaultdict(deque)
        await self._build_index()
        self._load_regex_cache()

    async def stop(self) -> None:
        try:
            self.db.commit()
            self.db.close()
        except Exception:
            pass

    def _resolve_db_path(self) -> str:
        for attr_owner, attr in ((self, "data_dir"), (self.loader, "data_dir"),
                                 (self.loader, "basepath")):
            d = getattr(attr_owner, attr, None)
            if d:
                try:
                    os.makedirs(d, exist_ok=True)
                    return os.path.join(d, "banlookup.db")
                except Exception:
                    continue
        return "banlookup.db"

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    def _init_db(self) -> None:
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS rules (
            room_id        TEXT NOT NULL,
            state_key      TEXT NOT NULL,
            entity         TEXT NOT NULL,
            entity_lower   TEXT NOT NULL,
            kind           TEXT NOT NULL,
            rule_type      TEXT NOT NULL,
            recommendation TEXT,
            reason         TEXT,
            sender         TEXT,
            origin_ts      INTEGER,
            PRIMARY KEY (room_id, state_key)
        );
        CREATE INDEX IF NOT EXISTS idx_rules_exact
            ON rules(entity_lower) WHERE kind='exact';
        CREATE INDEX IF NOT EXISTS idx_rules_kind ON rules(kind);
        CREATE TABLE IF NOT EXISTS room_meta (
            room_id TEXT PRIMARY KEY,
            name    TEXT,
            topic   TEXT,
            alias   TEXT
        );
        """)
        # Idempotent migration for DBs created before the alias column existed.
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(room_meta)")}
        if "alias" not in cols:
            self.db.execute("ALTER TABLE room_meta ADD COLUMN alias TEXT")
        self.db.commit()

    def _load_regex_cache(self) -> None:
        self._regex_rules = []
        cur = self.db.execute("SELECT room_id, state_key, entity FROM rules WHERE kind='regex'")
        for row in cur:
            try:
                pat = re.compile(fnmatch.translate(row["entity"]))
            except re.error:
                continue
            self._regex_rules.append((pat, f'{row["room_id"]}\x00{row["state_key"]}'))

    @staticmethod
    def _cget(content, key: str, default: str = "") -> str:
        try:
            val = content[key]
        except (KeyError, TypeError):
            val = getattr(content, key, None)
        if val is None:
            return default
        if isinstance(val, str):
            return val
        s = str(val)
        return s if s and s != "{}" else default

    async def _build_index(self) -> None:
        self.db.execute("DELETE FROM rules")
        self.db.execute("DELETE FROM room_meta")
        self.db.commit()
        joined = await self.client.get_joined_rooms()
        for room_id in joined:
            await self._scan_room(room_id)
        self.db.commit()
        n_rules = self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        n_rooms = self._policy_room_count()
        self.log.info(f"Indexed {n_rules} policy rules across {n_rooms} policy rooms")

    async def _scan_room(self, room_id: str) -> None:
        try:
            state = await self.client.get_state(room_id)
        except Exception as e:
            self.log.warning(f"Could not fetch state for {room_id}: {e}")
            return
        name, topic, alias = "", "", ""
        rows = []
        saw_alias_event = False
        for evt in state:
            if evt.type == EventType.ROOM_NAME:
                name = self._cget(evt.content, "name", "")
            elif evt.type == EventType.ROOM_TOPIC:
                topic = self._cget(evt.content, "topic", "")
            elif evt.type == EventType.ROOM_CANONICAL_ALIAS:
                saw_alias_event = True
                alias = self._cget(evt.content, "canonical_alias", "") \
                    or self._cget(evt.content, "alias", "")
            elif evt.type in RULE_TYPES:
                row = self._rule_row(evt)
                if row:
                    rows.append(row)
        if rows:
            self.db.executemany(
                "INSERT OR REPLACE INTO rules "
                "(room_id, state_key, entity, entity_lower, kind, rule_type, "
                " recommendation, reason, sender, origin_ts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
            self.db.execute(
                "INSERT OR REPLACE INTO room_meta (room_id, name, topic, alias) "
                "VALUES (?,?,?,?)", (room_id, name, topic, alias))
            if not name:
                self.log.debug(
                    f"{room_id}: name={name!r} alias={alias!r} "
                    f"(canonical_alias event seen: {saw_alias_event})")

    def _rule_row(self, evt: StateEvent):
        entity = self._cget(evt.content, "entity", "")
        if not entity:
            return None
        return (
            str(evt.room_id), str(evt.state_key), entity, entity.lower(),
            classify(entity), RULE_TYPES.get(evt.type, "user"),
            self._cget(evt.content, "recommendation", ""),
            self._cget(evt.content, "reason", ""),
            str(evt.sender), evt.timestamp or 0,
        )

    @event.on(POLICY_USER)
    @event.on(POLICY_SERVER)
    @event.on(POLICY_ROOM)
    async def _on_policy(self, evt: StateEvent) -> None:
        row = self._rule_row(evt)
        if row is None:
            self.db.execute("DELETE FROM rules WHERE room_id=? AND state_key=?",
                            (str(evt.room_id), str(evt.state_key)))
        else:
            self.db.execute(
                "INSERT OR REPLACE INTO rules "
                "(room_id, state_key, entity, entity_lower, kind, rule_type, "
                " recommendation, reason, sender, origin_ts) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)", row)
            if not self.db.execute("SELECT 1 FROM room_meta WHERE room_id=?",
                                   (str(evt.room_id),)).fetchone():
                self.db.execute(
                    "INSERT OR REPLACE INTO room_meta (room_id, name, topic, alias) "
                    "VALUES (?,?,?,?)", (str(evt.room_id), "", "", ""))
        self.db.commit()
        if (row and row[4] == "regex") or row is None:
            self._load_regex_cache()

    @event.on(EventType.ROOM_NAME)
    async def _on_name(self, evt: StateEvent) -> None:
        if self.db.execute("SELECT 1 FROM room_meta WHERE room_id=?",
                           (str(evt.room_id),)).fetchone():
            self.db.execute("UPDATE room_meta SET name=? WHERE room_id=?",
                            (self._cget(evt.content, "name", ""), str(evt.room_id)))
            self.db.commit()

    @event.on(EventType.ROOM_TOPIC)
    async def _on_topic(self, evt: StateEvent) -> None:
        if self.db.execute("SELECT 1 FROM room_meta WHERE room_id=?",
                           (str(evt.room_id),)).fetchone():
            self.db.execute("UPDATE room_meta SET topic=? WHERE room_id=?",
                            (self._cget(evt.content, "topic", ""), str(evt.room_id)))
            self.db.commit()

    @event.on(EventType.ROOM_CANONICAL_ALIAS)
    async def _on_alias(self, evt: StateEvent) -> None:
        if self.db.execute("SELECT 1 FROM room_meta WHERE room_id=?",
                           (str(evt.room_id),)).fetchone():
            alias = self._cget(evt.content, "canonical_alias", "") \
                or self._cget(evt.content, "alias", "")
            self.db.execute("UPDATE room_meta SET alias=? WHERE room_id=?",
                            (alias, str(evt.room_id)))
            self.db.commit()

    @event.on(EventType.ROOM_MEMBER)
    async def _on_member(self, evt: StateEvent) -> None:
        # Only care about the bot's own membership changing.
        if str(evt.state_key) != str(self.client.mxid):
            return
        membership = self._cget(evt.content, "membership", "")
        if membership in ("leave", "ban"):
            self._forget_room(str(evt.room_id))

    def _forget_room(self, room_id: str) -> None:
        """Drop all rules and metadata for a room we're no longer in."""
        had = self.db.execute("SELECT 1 FROM room_meta WHERE room_id=?",
                              (room_id,)).fetchone()
        self.db.execute("DELETE FROM rules WHERE room_id=?", (room_id,))
        self.db.execute("DELETE FROM room_meta WHERE room_id=?", (room_id,))
        self.db.commit()
        if had:
            self.log.info(f"Left {room_id}, purged its policies from the index")
        # rebuild regex cache in case any of the dropped rules were regex
        self._load_regex_cache()

    def _meta(self, room_id: str) -> tuple[str, str]:
        row = self.db.execute("SELECT name, topic FROM room_meta WHERE room_id=?",
                              (room_id,)).fetchone()
        return (row["name"] or "", row["topic"] or "") if row else ("", "")

    def _alias_for_room(self, room_id: str) -> str:
        row = self.db.execute("SELECT alias FROM room_meta WHERE room_id=?",
                              (room_id,)).fetchone()
        return (row["alias"] or "") if row else ""

    def _label_for(self, room_id: str) -> str:
        contacts = self.config["contacts"] or {}
        if room_id in contacts and contacts[room_id].get("label"):
            return contacts[room_id]["label"]
        labels = self.config["room_labels"] or {}
        if room_id in labels:
            return labels[room_id]
        name, _ = self._meta(room_id)
        if name:
            return name
        alias = self._alias_for_room(room_id)
        if alias:
            return alias
        return room_id

    def _contacts_for(self, room_id: str) -> list[str]:
        contacts = self.config["contacts"] or {}
        entry = contacts.get(room_id)
        return list(entry.get("methods", [])) if entry else []

    def _row_to_match(self, row) -> Match:
        name, topic = self._meta(row["room_id"])
        return Match(
            room_id=row["room_id"], room_name=name, room_topic=topic,
            label=self._label_for(row["room_id"]), rule_type=row["rule_type"],
            entity=row["entity"], recommendation=row["recommendation"] or "",
            reason=row["reason"] or "", sender=row["sender"] or "",
            origin_ts=row["origin_ts"] or 0, contacts=self._contacts_for(row["room_id"]),
        )

    def lookup(self, entity: str) -> list[Match]:
        q = entity.lower()
        seen: set[tuple[str, str]] = set()
        results: list[Match] = []

        def add(row):
            key = (row["room_id"], row["state_key"])
            if key not in seen:
                seen.add(key)
                results.append(self._row_to_match(row))

        for row in self.db.execute("SELECT * FROM rules WHERE entity_lower=?", (q,)):
            add(row)
        for row in self.db.execute("SELECT * FROM rules WHERE kind='server_suffix'"):
            dom = row["entity_lower"][2:]
            if q == dom or q.endswith(":" + dom):
                add(row)
        for row in self.db.execute("SELECT * FROM rules WHERE kind='dot_suffix'"):
            dom = row["entity_lower"][2:]
            if q == dom or q.endswith("." + dom):
                add(row)
        for pat, ident in self._regex_rules:
            if pat.match(entity):
                room_id, state_key = ident.split("\x00", 1)
                row = self.db.execute(
                    "SELECT * FROM rules WHERE room_id=? AND state_key=?",
                    (room_id, state_key)).fetchone()
                if row:
                    add(row)

        results.sort(key=lambda m: (m.label.lower(), m.origin_ts))
        return results

    def _policy_room_count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM room_meta").fetchone()[0]

    def _distinct_policy_count(self) -> int:
        return self.db.execute("SELECT COUNT(DISTINCT entity_lower) FROM rules").fetchone()[0]

    @staticmethod
    def _sanitize(raw) -> str | None:
        if not isinstance(raw, str):
            return None
        entity = raw.strip()
        if not entity or not _VALID_ENTITY.match(entity):
            return None
        return entity

    def _rate_limited(self, mxid: str) -> float:
        """Return seconds until the user may issue another command, or 0 if allowed."""
        count = self.config["rate_limit_count"]
        window = self.config["rate_limit_window"]
        if not count or count <= 0:
            return 0.0
        if mxid in (self.config["rate_limit_exempt"] or []):
            return 0.0
        now = time.monotonic()
        hits = self._rl_hits[mxid]
        cutoff = now - window
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= count:
            return window - (now - hits[0])
        hits.append(now)
        # opportunistic cleanup so the dict doesn't grow unbounded
        if len(self._rl_hits) > 10000:
            for k in [k for k, v in self._rl_hits.items() if not v]:
                del self._rl_hits[k]
        return 0.0

    def _enabled(self) -> bool:
        return bool(self.config["respond_in_rooms"])

    async def _gate_lookup(self, evt: MessageEvent) -> bool:
        """For lookups only: enabled check + per-user rate limit."""
        if not self._enabled():
            return False
        wait = self._rate_limited(str(evt.sender))
        if wait > 0:
            await evt.reply(f"rate limited \u2014 try again in {int(wait) + 1}s.")
            return False
        return True

    @command.new(name=lambda self: self.config["command_prefix"],
                 require_subcommand=False, arg_fallthrough=False)
    @command.argument("entity", required=False, pass_raw=True)
    async def base(self, evt: MessageEvent, entity: str = "") -> None:
        if not self._enabled():
            return
        if entity and entity.strip():
            await self._do_lookup(evt, entity)
        else:
            await evt.respond(self._help_html(), allow_html=True, markdown=False)

    @base.subcommand("help", help="Show available commands")
    async def cmd_help(self, evt: MessageEvent) -> None:
        if not self._enabled():
            return
        await evt.respond(self._help_html(), allow_html=True, markdown=False)

    @base.subcommand("lookup", help="Check an entity against all lists")
    @command.argument("entity", required=True, pass_raw=True)
    async def cmd_lookup(self, evt: MessageEvent, entity: str) -> None:
        if not self._enabled():
            return
        await self._do_lookup(evt, entity)

    async def _do_lookup(self, evt: MessageEvent, entity: str) -> None:
        if not await self._gate_lookup(evt):
            return
        clean = self._sanitize(entity)
        if clean is None:
            await evt.reply("invalid entity. expected a user ID, server name, or room ID.")
            return
        await evt.respond(self._render_html(clean, self.lookup(clean)),
                          allow_html=True, markdown=False)

    @base.subcommand("status", help="Show how many lists and policies are known")
    async def cmd_status(self, evt: MessageEvent) -> None:
        if not self._enabled():
            return
        rooms = self._policy_room_count()
        policies = self._distinct_policy_count()
        total = self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0]
        await evt.respond(
            f"\U0001F4CA <b>status</b><br>"
            f"&nbsp;&nbsp;\u2022 policy rooms joined: <b>{rooms}</b><br>"
            f"&nbsp;&nbsp;\u2022 distinct policies known: <b>{policies}</b><br>"
            f"&nbsp;&nbsp;\u2022 total rule entries: <b>{total}</b>",
            allow_html=True, markdown=False)

    @base.subcommand("lists", help="List all policy rooms the bot is in")
    async def cmd_lists(self, evt: MessageEvent) -> None:
        if not self._enabled():
            return
        rows = self.db.execute(
            "SELECT room_id, name FROM room_meta ORDER BY name COLLATE NOCASE").fetchall()
        if not rows:
            await evt.respond("I'm not in any policy rooms yet.",
                              allow_html=True, markdown=False)
            return
        parts = [f"\U0001F4DA <b>{len(rows)} policy room{'s' if len(rows) != 1 else ''}:</b><br>"]
        for row in rows:
            rid = row["room_id"]
            label = self._label_for(rid)
            n = self.db.execute("SELECT COUNT(*) FROM rules WHERE room_id=?",
                                (rid,)).fetchone()[0]
            parts.append(f"&nbsp;&nbsp;\u2022 <b>{html.escape(label)}</b> "
                         f"(<code>{html.escape(rid)}</code>) \u2014 {n} rules<br>")
        await evt.respond("".join(parts), allow_html=True, markdown=False)

    @base.subcommand("reindex", help="Force a full rebuild of the index (admin only)")
    async def cmd_reindex(self, evt: MessageEvent) -> None:
        if not self._enabled():
            return
        if str(evt.sender) not in self._admins():
            await evt.reply("that command is restricted.")
            return
        await evt.reply("rebuilding index\u2026")
        await self._build_index()
        self._load_regex_cache()
        rooms = self._policy_room_count()
        policies = self._distinct_policy_count()
        await evt.respond(
            f"\u2705 reindex complete \u2014 {rooms} policy rooms, {policies} distinct policies.",
            allow_html=True, markdown=False)

    def _admins(self) -> list[str]:
        # dedicated admins list, falling back to the rate-limit exempt list.
        admins = self.config["admins"] or []
        if admins:
            return admins
        return self.config["rate_limit_exempt"] or []

    def _brand(self) -> str:
        # The configurable brand word shown before "list lookup" everywhere.
        # Falls back to "codestorm" if the key is unset/empty.
        return self.config["web_brand"] or "codestorm"

    def _help_html(self) -> str:
        p = self.config["command_prefix"]
        brand = html.escape(self._brand())
        return (
            f"\U0001F6E1\uFE0F <b>{brand} list lookup</b><br>"
            f"&nbsp;&nbsp;<code>!{p} &lt;entity&gt;</code> \u2014 check a user ID / server / room<br>"
            f"&nbsp;&nbsp;<code>!{p} lookup &lt;entity&gt;</code> \u2014 same, explicit<br>"
            f"&nbsp;&nbsp;<code>!{p} status</code> \u2014 counts of rooms &amp; policies<br>"
            f"&nbsp;&nbsp;<code>!{p} lists</code> \u2014 all policy rooms I'm in<br>"
            f"&nbsp;&nbsp;<code>!{p} help</code> \u2014 this message"
        )

    def _render_html(self, entity: str, matches: list[Match]) -> str:
        e = html.escape(entity)
        if not matches:
            return f"<code>{e}</code> is not listed on any list I'm joined to. \u2705"
        show_sender = self.config["show_sender"]
        limit = self.config["max_inline_matches"]
        n = len(matches)
        parts = [f"<code>{e}</code> matched on {n} list{'s' if n != 1 else ''}:<br><br>"]
        for m in matches[:limit]:
            parts.append(self._render_match_html(m, show_sender))
        if n > limit:
            parts.append(f"<i>\u2026and {n - limit} more (see web page).</i>")
        return "".join(parts)

    def _render_match_html(self, m: Match, show_sender: bool) -> str:
        label = html.escape(m.label)
        room = html.escape(m.room_id)
        ts = time.strftime("%Y-%m-%d", time.gmtime(m.origin_ts / 1000)) if m.origin_ts else "?"
        lines = [
            f"\U0001F4CB <b>{label}</b> (<code>{room}</code>)<br>",
            f"&nbsp;&nbsp;\u2022 entity: <code>{html.escape(m.entity)}</code> "
            f"({html.escape(m.rule_type)})<br>",
            f"&nbsp;&nbsp;\u2022 recommendation: <code>{html.escape(m.recommendation)}</code><br>",
            f"&nbsp;&nbsp;\u2022 reason: {html.escape(m.reason) or '<i>none given</i>'}<br>",
        ]
        if show_sender:
            lines.append(f"&nbsp;&nbsp;\u2022 issued by: <code>{html.escape(m.sender)}</code><br>")
        lines.append(f"&nbsp;&nbsp;\u2022 {ts}<br>")
        if m.contacts:
            joined = " / ".join(html.escape(c) for c in m.contacts)
            lines.append(f"&nbsp;&nbsp;\U0001F4DE contact: {joined}<br>")
        topic = html.escape(m.room_topic) if m.room_topic else "<i>no topic</i>"
        lines.append(f"<details><summary>room topic</summary>{topic}</details><br>")
        return "".join(lines)

    @web_handler.get("/")
    async def web_index(self, req: web.Request) -> web.Response:
        # Inject the configurable brand at serve time. The HTML template carries
        # a __BRAND__ placeholder; config isn't available when _index_html is
        # read at class-definition time, so substitution has to happen here.
        page = self._index_html.replace("__BRAND__", html.escape(self._brand()))
        return web.Response(text=page, content_type="text/html")

    @web_handler.post("/api/lookup")
    async def web_lookup(self, req: web.Request) -> web.Response:
        try:
            data = await req.json()
        except Exception:
            return web.json_response({"error": "invalid json"}, status=400)
        if not isinstance(data, dict):
            return web.json_response({"error": "invalid json"}, status=400)
        clean = self._sanitize(data.get("entity", ""))
        if clean is None:
            return web.json_response({"error": "invalid entity"}, status=400)
        show_sender = self.config["show_sender"]
        out = []
        for m in self.lookup(clean):
            item = {
                "label": m.label, "room_id": m.room_id, "entity": m.entity,
                "rule_type": m.rule_type, "recommendation": m.recommendation,
                "reason": m.reason, "origin_ts": m.origin_ts,
                "room_topic": m.room_topic, "contacts": m.contacts,
            }
            if show_sender:
                item["sender"] = m.sender
            out.append(item)
        return web.json_response({"entity": clean, "count": len(out), "matches": out})

    @web_handler.get("/api/status")
    async def web_status(self, req: web.Request) -> web.Response:
        return web.json_response({
            "policy_rooms": self._policy_room_count(),
            "distinct_policies": self._distinct_policy_count(),
            "total_rules": self.db.execute("SELECT COUNT(*) FROM rules").fetchone()[0],
        })