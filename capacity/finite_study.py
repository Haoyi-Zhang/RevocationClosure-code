"""Depth-bounded exhaustive state exploration of valid benign fixture traces.

Every enabled action/clock transition is explored. Equal states at equal depth
are merged; no claim is made that their equivalent prefixes are independent runs.
SQLite is in-memory here; disk recovery and faults are separate campaigns.
"""
from __future__ import annotations

import gzip
import json
from collections import deque
from copy import deepcopy

from fixtures import grant, revoke, target, horizon, valid_receipt
from capacity_store import CapacityStore, POLICIES
from reference import State, transition, state_allow, ancestors
from study_io import fresh, save, compact_state


def fixtures():
    g = grant(0, 1, None, 3, [3] * 5, "finite-root")
    h = grant(1, 2, g, 1, [2] * 5, "finite-child")
    q = grant(2, 3, None, 3, [6] * 5, "finite-unrelated")
    z = grant(3, 4, None, 3, [4] * 5, "finite-unseen")
    return [g, h, q, z]


def load_state(store, state):
    """Test-only restoration of an already checked reachable memory state."""
    snapshot = state.snapshot(store.policy)
    store.db.execute("BEGIN IMMEDIATE")
    store.db.execute("DELETE FROM records")
    store.db.execute("UPDATE metadata SET floor=?", (state.floor,))
    store.db.executemany("INSERT INTO records VALUES (?,?,?,?,?,?)",
                        [(r["key"], r["kind"], r["target"], r["horizon"], r["early"], json.dumps(r["event"], sort_keys=True, separators=(",", ":"))) for r in snapshot["records"]])
    store.db.commit()
    assert store.snapshot() == snapshot


def run(out, depth=5):
    out = fresh(out)
    grants = fixtures()
    catalog = {g["id"]: g for g in grants}
    actions = [[g] for g in grants] + [[revoke(g)] for g in grants] + [None]
    configs = [dict(policy=p, budget=b, unseen=u, epsilon=e, node=0)
               for b, u in ((2, 0), (3, 1), (4, 1), (4, 2)) for p in POLICIES for e in (0, 1)]
    save(out / "inputs.json", dict(depth=depth, grants=grants, actions=actions, configs=configs,
                                  actual_time="transition depth", clocks="distinct max(0,t-epsilon) and t+epsilon",
                                  merge="same depth, floor, grant/revoke target sets and early-origin set"))
    totals = dict(transitions=0, states_expanded=0, state_matches=0, authorization_checks=0,
                  progress_obligations=0, future_admission_obligations=0,
                  receipt_checks=0, unrelated_checks=0, refused=0)
    rows = []
    with gzip.open(out / "transitions.jsonl.gz", "xt", encoding="utf-8", newline="\n") as trace:
        for ci, config in enumerate(configs):
            p, b, u, e = (config[k] for k in ("policy", "budget", "unseen", "epsilon"))
            store = CapacityStore(":memory:", **config)
            queue = deque([(0, State(), [])])
            seen = {(0, State().signature())}
            counts = {key: 0 for key in totals}
            while queue:
                level, state, prefix = queue.popleft()
                if level == depth:
                    continue
                counts["states_expanded"] += 1
                for clock in sorted({max(0, level - e), level + e}):
                    assert abs(clock - level) <= e
                    for ai, batch in enumerate(actions):
                        load_state(store, state)
                        store.set_clock(clock)
                        before = [state_allow(state, p, g, 0, clock, e) for g in grants]
                        expected_state, expected, refusal = transition(state, p, b, u, 0, e, clock, batch)
                        eligible_future = False
                        if batch is not None and batch[0]["kind"] == "grant":
                            g = batch[0]
                            room = (state.counts()["records"] < b if p == "append" else
                                    len(state.grants) < (b-u)//2 if p == "reservation" else
                                    state.counts()["normal"] < b-u)
                            if room and g["id"] not in state.grants and g["id"] not in state.revokes:
                                virtual = deepcopy(state)
                                virtual.grants[g["id"]] = g
                                eligible_future = state_allow(virtual, p, g, 0, clock, e)
                                if eligible_future:
                                    assert refusal is None and expected["outcomes"] == ["added"]
                                    counts["future_admission_obligations"] += 1
                        if batch is not None and batch[0]["kind"] == "revoke" and p != "append":
                            ident = target(batch[0])["id"]
                            known = ident in state.grants or ident in state.revokes
                            if known or len(state.early) < u or horizon(batch[0]) <= state.floor:
                                assert refusal is None
                                counts["progress_obligations"] += 1
                        reply, error = None, None
                        try:
                            reply = store.compact() if batch is None else store.ingest(batch)
                        except ValueError as ex:
                            error = str(ex)
                        assert error == refusal, (config, prefix, ai, clock, error, refusal)
                        assert reply == expected, (config, prefix, ai, reply, expected)
                        assert store.snapshot() == expected_state.snapshot(p)
                        assert expected_state.floor >= state.floor and expected_state.floor <= level
                        assert expected_state.counts()["records"] <= b
                        if p == "reservation":
                            assert len(expected_state.grants) <= (b - u) // 2 and len(expected_state.early) <= u
                        if p == "replacement":
                            assert expected_state.counts()["normal"] <= b - u and len(expected_state.early) <= u
                        after = []
                        for g in grants:
                            decision = store.authorize(g["id"], g["subject"], 1, g["service"])
                            wanted = state_allow(expected_state, p, g, 0, clock, e)
                            assert decision["allow"] == wanted
                            after.append(decision["allow"])
                            counts["authorization_checks"] += 1
                        if eligible_future:
                            assert after[ai]  # grant actions occupy indices 0..3
                        if reply is not None and batch is not None:
                            for event, rr in zip([v for v in batch if v["kind"] == "revoke"], reply["receipts"]):
                                assert valid_receipt(rr, 0, event)
                                for gi, g in enumerate(grants):
                                    if target(event)["id"] in ancestors(g, catalog):
                                        assert not after[gi]
                                        counts["receipt_checks"] += 1
                            if all(v["kind"] == "revoke" for v in batch):
                                targets = {target(v)["id"] for v in batch}
                                for gi, g in enumerate(grants):
                                    if not (ancestors(g, catalog) & targets):
                                        assert after[gi] == before[gi]
                                        counts["unrelated_checks"] += 1
                        counts["refused"] += int(refusal is not None)
                        counts["transitions"] += 1
                        counts["state_matches"] += 1
                        trace.write(json.dumps(dict(config=ci, depth=level, prefix=prefix,
                                                    pre=compact_state(state), action=ai, clock=clock,
                                                    actual_time=level, reply=reply, refusal=error,
                                                    post=compact_state(expected_state), authorization=after,
                                                    eligible_future=eligible_future), sort_keys=True) + "\n")
                        key = (level + 1, expected_state.signature())
                        if key not in seen:
                            seen.add(key)
                            queue.append((level + 1, deepcopy(expected_state), prefix + [[ai, clock]]))
            store.close()
            row = dict(config=config, reached_depth_states=len(seen), **counts)
            rows.append(row)
            for key in totals:
                totals[key] += counts[key]
            print(json.dumps(dict(stage="finite", config=ci, **counts)), flush=True)
    result = dict(depth=depth, configurations=len(configs), totals=totals, per_configuration=rows,
                  mismatches=0, scope="all declared traces to depth five modulo exact state/depth equivalence; in-memory SQLite, not physical recovery")
    save(out / "summary.json", result)
    return result
