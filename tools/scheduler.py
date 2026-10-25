"""Local, trusted single-control-plane scheduling primitives (Python stdlib only).

This module does not call an LLM, GitHub, or a production service. Keep the database
outside untrusted agent mounts. GitHub receipt verification lives in verify_merge.py.
"""
from __future__ import annotations
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import secrets
import sqlite3
import time
from typing import Any

ACTIVE_CAPACITY = {"RUNNING", "ORPHANED"}
ACTIVE_LOCKS = {"RUNNING", "ORPHANED", "REVIEW"}


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def safe_relative(path: str) -> str:
    if not isinstance(path, str) or not path or "\\" in path or "\x00" in path:
        raise ValueError("Invalid relative path")
    p = PurePosixPath(path)
    if p.is_absolute() or any(x in {"..", ".git"} for x in p.parts) or ":" in path:
        raise ValueError("Path escapes the owned workspace or touches Git metadata")
    normalized = str(p)
    if normalized == ".":
        raise ValueError("Root ownership is not an admissible task scope")
    return normalized.rstrip("/")


def path_owned(path: str, scopes: list[str]) -> bool:
    target = safe_relative(path)
    for scope in scopes:
        clean = safe_relative(scope)
        if target == clean or (scope.endswith("/") and target.startswith(clean + "/")):
            return True
    return False


def scopes_conflict(left: list[str], right: list[str]) -> bool:
    for a in left:
        for b in right:
            ca, cb = safe_relative(a), safe_relative(b)
            if ca == cb or (a.endswith("/") and cb.startswith(ca + "/")) or (b.endswith("/") and ca.startswith(cb + "/")):
                return True
    return False


def validate_graph(tasks: list[dict]) -> list[str]:
    by = {t["key"]: t for t in tasks}
    if len(by) != len(tasks):
        raise ValueError("Duplicate task key")
    for t in tasks:
        for p in t.get("write_paths", []):
            safe_relative(p)
        if not set(t.get("depends_on", [])).issubset(by):
            raise ValueError(f"Unknown prerequisites for {t['key']}")
        if t["key"] in t.get("depends_on", []):
            raise ValueError("Self dependency")
        for value in t.get("resources", {}).values():
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError("Invalid resource reservation")
    pending = {k: set(v.get("depends_on", [])) for k, v in by.items()}
    order: list[str] = []
    while pending:
        ready = sorted(k for k, deps in pending.items() if not deps)
        if not ready:
            raise ValueError("Build prerequisites contain a cycle")
        order.extend(ready)
        for k in ready:
            del pending[k]
        for deps in pending.values():
            deps.difference_update(ready)
    return order


def validate_policy(policy: dict) -> None:
    for key in ["max_workers", "lease_seconds", "max_attempts"]:
        if not isinstance(policy.get(key), int) or policy[key] <= 0:
            raise ValueError(f"{key} must be a positive integer")
    for key in ["max_cost_per_task_usd", "total_cost_budget_usd"]:
        x = policy.get(key)
        if not isinstance(x, (int, float)) or not math.isfinite(x) or x < 0:
            raise ValueError(f"{key} must be a finite nonnegative number")
    for k, x in policy.get("capacities", {}).items():
        if not isinstance(x, (int, float)) or not math.isfinite(x) or x < 0:
            raise ValueError(f"Invalid capacity {k}")
    if not policy.get("capacities"):
        raise ValueError("No measured/example capacities configured")


class Scheduler:
    def __init__(self, database: str | Path, tasks: list[dict], policy: dict, clock=time.time):
        validate_graph(tasks)
        validate_policy(policy)
        self.path = Path(database)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.tasks = {t["key"]: t for t in tasks}
        self.policy = policy
        self.clock = clock
        self.graph_hash = canonical_hash(tasks)
        self.policy_hash = canonical_hash(policy)
        order = validate_graph(tasks)
        children: dict[str, list[str]] = {k: [] for k in self.tasks}
        for t in tasks:
            for parent in t.get("depends_on", []):
                children[parent].append(t["key"])
        self.depth: dict[str, int] = {}
        for key in reversed(order):
            self.depth[key] = 1 + max((self.depth[c] for c in children[key]), default=0)
        with self._connection() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tasks (
              key TEXT PRIMARY KEY, state TEXT NOT NULL, agent TEXT, token TEXT,
              fence INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
              lease_until REAL, base_revision TEXT, input_sha256 TEXT,
              created REAL NOT NULL, updated REAL NOT NULL, result TEXT, receipt TEXT,
              reserved_cost REAL NOT NULL DEFAULT 0, error TEXT);
            CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
              task_key TEXT, event TEXT NOT NULL, detail TEXT NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT value FROM metadata WHERE key='graph_hash'").fetchone()
            if prior and prior[0] != self.graph_hash:
                raise ValueError("Graph changed: reviewed migration of controller state required")
            prior_policy = db.execute("SELECT value FROM metadata WHERE key='policy_hash'").fetchone()
            if prior_policy and prior_policy[0] != self.policy_hash:
                raise ValueError("Policy changed: stop/reconcile and explicitly migrate state before changing authority")
            for k, v in {"graph_hash": self.graph_hash, "policy_hash": self.policy_hash, "spent": "0", "stopped": "false"}.items():
                db.execute("INSERT OR IGNORE INTO metadata VALUES (?,?)", (k, v))
            now = self.clock()
            for t in tasks:
                state = "MANUAL_HOLD" if t.get("manual") else ("BACKLOG" if t.get("enabled_by_default", True) else "DEFERRED")
                db.execute("INSERT OR IGNORE INTO tasks(key,state,created,updated) VALUES (?,?,?,?)", (t["key"], state, now, now))
            db.commit()
        os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def _connection(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=30000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            yield db
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def _event(self, db, key: str | None, kind: str, detail: dict):
        db.execute("INSERT INTO events(at,task_key,event,detail) VALUES (?,?,?,?)", (self.clock(), key, kind, json.dumps(detail, sort_keys=True)))

    def _expire(self, db):
        rows = db.execute("SELECT * FROM tasks WHERE state='RUNNING' AND lease_until<=?", (self.clock(),)).fetchall()
        for row in rows:
            db.execute("UPDATE tasks SET state='ORPHANED', updated=?, error=? WHERE key=?", (self.clock(), "Lease expired; termination/reconciliation required", row["key"]))
            self._event(db, row["key"], "ORPHANED", {"fence": row["fence"]})

    def _rows(self, db):
        return {r["key"]: dict(r) for r in db.execute("SELECT * FROM tasks")}

    def _runnable(self, rows, agent: str | None = None):
        ready = []
        for key, row in rows.items():
            task = self.tasks[key]
            if row["state"] != "BACKLOG" or task.get("manual") or not task.get("enabled_by_default", True):
                continue
            if any(rows[d]["state"] != "ACCEPTED" for d in task.get("depends_on", [])):
                continue
            if task.get("requires_independent_agent") and agent:
                deps = [rows[d] for d in task.get("depends_on", []) if self.tasks[d].get("workflow_id") == task.get("workflow_id")]
                if any(d["agent"] == agent for d in deps):
                    continue
            ready.append(key)
        return sorted(ready, key=lambda k: (self.tasks[k].get("priority", "P1"), -self.depth[k], rows[k]["created"], k))

    def status(self) -> dict:
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE"); self._expire(db)
            rows = self._rows(db)
            budget = float(db.execute("SELECT value FROM metadata WHERE key='spent'").fetchone()[0])
            stopped = db.execute("SELECT value FROM metadata WHERE key='stopped'").fetchone()[0] == "true"
            db.commit()
        used = {k: sum(self.tasks[t]["resources"].get(k, 0) for t, r in rows.items() if r["state"] in ACTIVE_CAPACITY) for k in self.policy["capacities"]}
        counts: dict[str, int] = {}
        for r in rows.values():
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        return {"graph_sha256": self.graph_hash, "policy_sha256": self.policy_hash, "stopped": stopped, "counts": counts,
                "ready": self._runnable(rows), "resources_reserved": used, "spent_usd": budget,
                "reserved_usd": sum(r["reserved_cost"] for r in rows.values()),
                "tasks": [{k: r[k] for k in ["key", "state", "agent", "fence", "lease_until", "attempts", "error"]} for r in rows.values()]}

    def claim(self, agent: str, base_revision: str, requested_key: str | None = None) -> dict | None:
        if not agent or not base_revision:
            raise ValueError("Agent identity and base revision required")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE"); self._expire(db)
            if db.execute("SELECT value FROM metadata WHERE key='stopped'").fetchone()[0] == "true":
                db.commit(); return None
            rows = self._rows(db)
            active = [k for k, r in rows.items() if r["state"] in ACTIVE_CAPACITY]
            locked = [k for k, r in rows.items() if r["state"] in ACTIVE_LOCKS]
            if len(active) >= self.policy["max_workers"]:
                db.commit(); return None
            used = {k: sum(self.tasks[t]["resources"].get(k, 0) for t in active) for k in self.policy["capacities"]}
            spent = float(db.execute("SELECT value FROM metadata WHERE key='spent'").fetchone()[0])
            held = sum(r["reserved_cost"] for r in rows.values())
            cost = self.policy["max_cost_per_task_usd"]
            if spent + held + cost > self.policy["total_cost_budget_usd"] + 1e-9:
                db.commit(); return None
            ready = self._runnable(rows, agent)
            if requested_key:
                ready = [k for k in ready if k == requested_key]
            for key in ready:
                t = self.tasks[key]
                if rows[key]["attempts"] >= self.policy["max_attempts"]:
                    continue
                if any(r > self.policy["capacities"].get(k, 0) - used.get(k, 0) for k, r in t["resources"].items()):
                    continue
                if any(scopes_conflict(t.get("write_paths", []), self.tasks[k].get("write_paths", [])) or set(t.get("locks", [])) & set(self.tasks[k].get("locks", [])) for k in locked):
                    continue
                token = secrets.token_urlsafe(32)
                fence = rows[key]["fence"] + 1
                packet = {"task": t, "task_key": key, "agent": agent, "base_revision": base_revision,
                          "graph_sha256": self.graph_hash, "policy_sha256": self.policy_hash,
                          "lease_token": token, "fence": fence, "lease_until": self.clock() + self.policy["lease_seconds"]}
                packet["input_sha256"] = canonical_hash({k: v for k, v in packet.items() if k != "lease_until"})
                db.execute("UPDATE tasks SET state='RUNNING',agent=?,token=?,fence=?,attempts=attempts+1,lease_until=?,base_revision=?,input_sha256=?,updated=?,reserved_cost=?,result=NULL,receipt=NULL,error=NULL WHERE key=?",
                           (agent, token, fence, packet["lease_until"], base_revision, packet["input_sha256"], self.clock(), cost, key))
                self._event(db, key, "CLAIM", {"agent": agent, "fence": fence, "base_revision": base_revision, "input_sha256": packet["input_sha256"]})
                db.commit(); return packet
            db.commit(); return None

    def _current(self, db, key: str, token: str, fence: int):
        self._expire(db)
        row = db.execute("SELECT * FROM tasks WHERE key=?", (key,)).fetchone()
        if not row or row["state"] != "RUNNING" or row["token"] != token or row["fence"] != fence:
            raise ValueError("Stale, expired, revoked or invalid task lease")
        return row

    def heartbeat(self, key: str, token: str, fence: int):
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE"); self._current(db, key, token, fence)
            db.execute("UPDATE tasks SET lease_until=?,updated=? WHERE key=?", (self.clock() + self.policy["lease_seconds"], self.clock(), key))
            db.commit()

    def _settle(self, db, row, trusted_cost: float | None):
        # Unknown usage is conservatively charged at the reservation, never assumed free.
        cost = row["reserved_cost"] if trusted_cost is None else trusted_cost
        if not isinstance(cost, (int, float)) or not math.isfinite(cost) or cost < 0:
            raise ValueError("Invalid trusted cost")
        spent = float(db.execute("SELECT value FROM metadata WHERE key='spent'").fetchone()[0])
        db.execute("UPDATE metadata SET value=? WHERE key='spent'", (str(spent + cost),))
        db.execute("UPDATE tasks SET reserved_cost=0 WHERE key=?", (row["key"],))
        if cost > row["reserved_cost"] + 1e-9:
            db.execute("UPDATE metadata SET value='true' WHERE key='stopped'")
            self._event(db, row["key"], "BUDGET_OVERRUN_STOP", {"cost": cost})

    def finish(self, result: dict, trusted_cost: float | None = None):
        required = {"task_key", "lease_token", "fence", "input_sha256", "base_revision", "status", "summary", "changed_paths", "tests", "artifacts", "blockers"}
        if not required.issubset(result) or result["status"] not in {"ready_for_review", "blocked", "failed"}:
            raise ValueError("Malformed result contract")
        key = result["task_key"]
        if key not in self.tasks or any(not path_owned(p, self.tasks[key].get("write_paths", [])) for p in result["changed_paths"]):
            raise ValueError("Result exceeds owned path scope")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._current(db, key, result["lease_token"], result["fence"])
            if result["input_sha256"] != row["input_sha256"] or result["base_revision"] != row["base_revision"]:
                raise ValueError("Result is not bound to the current immutable input")
            state = "REVIEW" if result["status"] == "ready_for_review" else "BLOCKED"
            self._settle(db, row, trusted_cost)
            sanitized = dict(result); sanitized.pop("lease_token", None)
            db.execute("UPDATE tasks SET state=?,result=?,lease_until=NULL,updated=? WHERE key=?", (state, json.dumps(sanitized, sort_keys=True), self.clock(), key))
            self._event(db, key, "RESULT", {"state": state, "fence": row["fence"]})
            db.commit()

    def accept(self, key: str, receipt: dict):
        """TRUSTED CONTROL PLANE ONLY; receipt must be externally verified first.

        This deliberately does not accept issue comments, status labels or agent output.
        verify_merge.py verifies a GitHub receipt; supervised/manual approvals need an
        authorized human outside this module. File/OS access is the trust boundary.
        """
        required = {"task_key", "verified_by", "independent_review", "checks_verified", "revision", "graph_sha256", "evidence_level", "source"}
        if not required.issubset(receipt) or receipt["task_key"] != key or receipt["graph_sha256"] != self.graph_hash:
            raise ValueError("Invalid acceptance receipt binding")
        if receipt["independent_review"] is not True or receipt["checks_verified"] is not True:
            raise ValueError("Review and checks must be positively verified")
        if receipt["evidence_level"] not in {"CODE_MERGED", "SANDBOX_QUALIFIED", "STAGING_QUALIFIED", "PRODUCTION_APPROVED"}:
            raise ValueError("Unknown evidence level")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM tasks WHERE key=?", (key,)).fetchone()
            task = self.tasks[key]
            if task.get("manual"):
                if row["state"] != "MANUAL_HOLD" or receipt["source"] != "verified-human-approval":
                    raise ValueError("Manual gate requires a verified human approval")
            elif row["state"] != "REVIEW":
                raise ValueError("Task must be in independent REVIEW before acceptance")
            if row["agent"] and receipt["verified_by"] == row["agent"]:
                raise ValueError("Author cannot accept their own work")
            if any(r[0] != "ACCEPTED" for d in task.get("depends_on", []) for r in db.execute("SELECT state FROM tasks WHERE key=?", (d,))):
                raise ValueError("Prerequisites not accepted")
            db.execute("UPDATE tasks SET state='ACCEPTED',receipt=?,updated=?,token=NULL,lease_until=NULL WHERE key=?", (json.dumps(receipt, sort_keys=True), self.clock(), key))
            self._event(db, key, "ACCEPTED", {"revision": receipt["revision"], "verified_by": receipt["verified_by"], "level": receipt["evidence_level"]})
            db.commit()

    def quarantine(self, key: str, reason: str):
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM tasks WHERE key=?", (key,)).fetchone()
            if not row or row["state"] not in {"RUNNING", "ORPHANED"}:
                raise ValueError("Only active work can be quarantined")
            db.execute("UPDATE tasks SET state='ORPHANED',error=?,updated=? WHERE key=?", (reason, self.clock(), key))
            self._event(db, key, "QUARANTINED", {"reason": reason}); db.commit()

    def reconcile_orphan(self, key: str, proof: dict, retry: bool = False, trusted_cost: float | None = None):
        # proof is supplied only by trusted kill/reap + remote-outcome reconciliation.
        if proof.get("terminated") is not True or proof.get("effects_reconciled") is not True or not proof.get("verified_by") or not proof.get("evidence_ref"):
            raise ValueError("Positive termination and reconciliation evidence required")
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE"); self._expire(db)
            row = db.execute("SELECT * FROM tasks WHERE key=?", (key,)).fetchone()
            if not row or row["state"] != "ORPHANED":
                raise ValueError("Task is not orphaned")
            self._settle(db, row, trusted_cost)
            state = "BACKLOG" if retry and row["attempts"] < self.policy["max_attempts"] else "BLOCKED"
            db.execute("UPDATE tasks SET state=?,token=NULL,lease_until=NULL,updated=?,error=? WHERE key=?", (state, self.clock(), "Reconciled orphan", key))
            self._event(db, key, "ORPHAN_RECONCILED", {"state": state, "proof": proof}); db.commit()

    def stop(self, reason: str):
        with self._connection() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE metadata SET value='true' WHERE key='stopped'")
            self._event(db, None, "STOP", {"reason": reason}); db.commit()

    def record(self, key: str) -> dict:
        with self._connection() as db:
            row = db.execute("SELECT * FROM tasks WHERE key=?", (key,)).fetchone()
            if not row:
                raise KeyError(key)
            out = dict(row); out.pop("token", None)
            return out
