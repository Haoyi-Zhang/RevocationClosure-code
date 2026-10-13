"""Three ordinary local policies, explicit write transactions, owned SQLite only.

The budget counts authorization records, not physical SQLite allocation. A fixed
metadata row, indexes, transient buffers, WAL and SHM are outside that count.
"""
from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

from fixtures import (N, MAX_CHAIN, integer, hexid, packed, owned, valid_event,
                      target, horizon, receipt)

POLICIES = ("append", "reservation", "replacement")
FAILPOINTS = {None, "before_transaction", "before_commit", "after_commit_before_reply"}


class CapacityError(ValueError):
    pass


class CapacityStore:
    def __init__(self, path, policy, budget, unseen, node=0, epsilon=1):
        if (policy not in POLICIES or not integer(budget, 20000) or budget == 0
                or not integer(unseen, budget) or not integer(node, N - 1) or not integer(epsilon)):
            raise ValueError("configuration")
        self.policy, self.budget, self.unseen = policy, budget, unseen
        self.node, self.epsilon, self.clock = node, epsilon, 0
        self.grant_limit = budget if policy == "append" else ((budget - unseen) // 2 if policy == "reservation" else budget - unseen)
        self.path = None if path == ":memory:" else owned(Path(path))
        self.db = sqlite3.connect(":memory:" if self.path is None else str(self.path),
                                  isolation_level=None, timeout=10)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA wal_autocheckpoint=0")
        config = packed(dict(policy=policy, budget=budget, unseen=unseen, node=node,
                             epsilon=epsilon, grant_limit=self.grant_limit)).decode()
        try:
            self.db.execute("BEGIN IMMEDIATE")
            self.db.execute("CREATE TABLE IF NOT EXISTS metadata (singleton INTEGER PRIMARY KEY CHECK(singleton=1), config TEXT NOT NULL, floor INTEGER NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS records (key TEXT PRIMARY KEY, kind TEXT NOT NULL, target TEXT NOT NULL, horizon INTEGER NOT NULL, early INTEGER NOT NULL CHECK(early IN (0,1)), payload TEXT NOT NULL)")
            self.db.execute("CREATE INDEX IF NOT EXISTS target_kind ON records(target,kind)")
            self.db.execute("INSERT OR IGNORE INTO metadata VALUES (1,?,0)", (config,))
            if self.db.execute("SELECT config FROM metadata").fetchone()[0] != config:
                raise ValueError("configuration mismatch")
            self.db.commit()
        except BaseException:
            self.db.rollback()
            self.db.close()
            raise

    def set_clock(self, clock):
        if not integer(clock):
            raise ValueError("clock domain")
        self.clock = clock

    @staticmethod
    def _point(point, selected, hook):
        if hook is not None:
            hook(point)
        if selected == point:
            os._exit(70)  # only the owned, explicitly selected fault subprocess

    def _floor(self):
        return self.db.execute("SELECT floor FROM metadata WHERE singleton=1").fetchone()[0]

    def _counts(self):
        row = self.db.execute("SELECT COUNT(*), COALESCE(SUM(kind='grant'),0), COALESCE(SUM(kind='revoke'),0), COALESCE(SUM(early),0), COALESCE(SUM(early=0),0) FROM records").fetchone()
        return dict(records=row[0], grants=row[1], revokes=row[2], early=row[3], normal=row[4])

    def _write(self, event):
        g = target(event)
        ident = g["id"]
        counts = self._counts()
        if self.policy == "replacement":
            old = self.db.execute("SELECT kind,early FROM records WHERE key=?", (ident,)).fetchone()
            if old is not None:
                if old[0] == "grant" and event["kind"] == "revoke":
                    self.db.execute("UPDATE records SET kind='revoke',horizon=?,payload=? WHERE key=?", (horizon(event), packed(event).decode(), ident))
                    return "replaced"
                return "duplicate"  # a grant replay never overwrites a revoke
            early = int(event["kind"] == "revoke")
            if early and counts["early"] >= self.unseen:
                raise CapacityError("unseen quota")
            if not early and counts["normal"] >= self.grant_limit:
                raise CapacityError("grant quota")
            key = ident
        else:
            if self.db.execute("SELECT 1 FROM records WHERE key=?", (event["id"],)).fetchone():
                return "duplicate"
            known = self.db.execute("SELECT 1 FROM records WHERE kind='grant' AND target=?", (ident,)).fetchone() is not None
            early = int(event["kind"] == "revoke" and not known)
            if self.policy == "reservation":
                if event["kind"] == "grant" and counts["grants"] >= self.grant_limit:
                    raise CapacityError("grant quota")
                if early and counts["early"] >= self.unseen:
                    raise CapacityError("unseen quota")
            key = event["id"]
        if counts["records"] >= self.budget:
            raise CapacityError("record limit")
        self.db.execute("INSERT INTO records VALUES (?,?,?,?,?,?)",
                        (key, event["kind"], ident, horizon(event), early, packed(event).decode()))
        return "added"

    def ingest(self, batch, failpoint=None, hook=None):
        # Validation includes the complete batch before a transaction starts.
        if (not isinstance(batch, list) or len(batch) > 20000
                or not all(valid_event(e) for e in batch) or failpoint not in FAILPOINTS):
            raise ValueError("invalid batch or failpoint")
        self._point("before_transaction", failpoint, hook)
        outcomes, receipts = [], []
        try:
            self.db.execute("BEGIN IMMEDIATE")
            floor = self._floor()
            if self.clock + self.epsilon < floor:
                raise ValueError("clock contradicts floor")
            for event in batch:
                outcomes.append("floor" if horizon(event) <= floor else self._write(event))
                if event["kind"] == "revoke":
                    receipts.append(receipt(self.node, event))
            result = dict(outcomes=outcomes, receipts=receipts, floor=floor, **self._counts())
            self._point("before_commit", failpoint, hook)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self._point("after_commit_before_reply", failpoint, hook)
        return result

    def compact(self, failpoint=None, hook=None):
        if failpoint not in FAILPOINTS:
            raise ValueError("failpoint")
        self._point("before_transaction", failpoint, hook)
        try:
            self.db.execute("BEGIN IMMEDIATE")
            previous = self._floor()  # never read the floor before the write lock
            if self.clock + self.epsilon < previous:
                raise ValueError("clock contradicts floor")
            lower = max(previous, 0, self.clock - self.epsilon)
            before = self._counts()["records"]
            self.db.execute("DELETE FROM records WHERE horizon<=?", (lower,))
            self.db.execute("UPDATE metadata SET floor=? WHERE singleton=1", (lower,))
            result = dict(before=before, after=self._counts()["records"], floor=lower)
            self._point("before_commit", failpoint, hook)
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        self._point("after_commit_before_reply", failpoint, hook)
        return result

    def snapshot(self):
        self.db.execute("BEGIN")
        try:
            rows = self.db.execute("SELECT key,kind,target,horizon,early,payload FROM records ORDER BY key").fetchall()
            result = dict(floor=self._floor(), records=[dict(key=r[0], kind=r[1], target=r[2], horizon=r[3], early=r[4], event=json.loads(r[5])) for r in rows])
            self.db.commit()
            return result
        except BaseException:
            self.db.rollback()
            raise

    def authorize(self, leaf_id, actor, rights, service):
        if not hexid(leaf_id) or not integer(actor, N - 1) or not integer(rights, (1 << 32) - 1) or rights == 0 or service not in {f"svc{i}" for i in range(N)}:
            raise ValueError("request")
        self.db.execute("BEGIN")
        try:
            chain, seen, current, reason = [], set(), leaf_id, "allow"
            floor = self._floor()
            while current is not None:
                if current in seen or len(chain) >= MAX_CHAIN:
                    reason = "chain limit"
                    break
                seen.add(current)
                if self.policy == "replacement":
                    row = self.db.execute("SELECT payload FROM records WHERE key=?", (current,)).fetchone()
                else:
                    row = self.db.execute("SELECT payload FROM records WHERE target=? AND kind='grant'", (current,)).fetchone()
                if row is None:
                    reason = "missing"
                    break
                g = target(json.loads(row[0]))
                chain.append(g)
                current = g["parent"]
            if reason == "allow":
                leaf = chain[0]
                if leaf["subject"] != actor or leaf["service"] != service or chain[-1]["service"] != f"svc{chain[-1]['issuer']}" or rights & leaf["rights"] != rights:
                    reason = "request binding"
                for child, parent in zip(chain, chain[1:]):
                    if (child["issuer"] != parent["subject"] or child["service"] != parent["service"]
                            or child["rights"] & ~parent["rights"]
                            or any(a > b for a, b in zip(child["deadlines"], parent["deadlines"]))):
                        reason = "attenuation"
                        break
                if reason == "allow":
                    for g in chain:
                        if self.db.execute("SELECT 1 FROM records WHERE target=? AND kind='revoke'", (g["id"],)).fetchone():
                            reason = "revoked"
                            break
                if reason == "allow" and leaf["deadlines"][self.node] <= max(floor, self.clock + self.epsilon):
                    reason = "expired"
            self.db.commit()
            return dict(allow=reason == "allow", reason=reason, floor=floor)
        except BaseException:
            self.db.rollback()
            raise

    def physical(self):
        if self.path is None:
            return None
        sizes = {suffix or "db": (Path(str(self.path) + suffix).stat().st_size if Path(str(self.path) + suffix).exists() else 0) for suffix in ("", "-wal", "-shm")}
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        return dict(files_bytes=sizes, total_file_bytes=sum(sizes.values()), page_size=page_size,
                    page_count=self.db.execute("PRAGMA page_count").fetchone()[0],
                    freelist_count=self.db.execute("PRAGMA freelist_count").fetchone()[0],
                    wal_file_frame_slots=max(0, (sizes["-wal"] - 32) // (page_size + 24)),
                    interpretation="file extent, not physical-write count or a disk-space guarantee")

    def close(self):
        self.db.close()
