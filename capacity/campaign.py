"""Sized controlled SQLite campaign, common-cohort and own-quota arms apart."""
from __future__ import annotations

import gzip
import json
import platform
import random
import sqlite3
import sys
import time

from fixtures import grant, revoke, target, valid_receipt
from capacity_store import CapacityStore, POLICIES
from reference import State, transition, state_allow, ancestors
from study_io import fresh, save


def pool(size, depth, seed, label):
    rng = random.Random(seed)
    values, parent = [], None
    for i in range(size):
        if i % depth == 0:
            parent = None
        issuer = rng.randrange(5) if parent is None else parent["subject"]
        subject = (issuer + 1) % 5
        deadlines = [1000 + 10 * j - i % depth for j in range(5)]
        event = grant(issuer, subject, parent, 3 if parent is None else 1,
                      deadlines, f"{label}-grant-{i}")
        values.append(event)
        parent = event
    return values


def batches(values, size=16):
    for offset in range(0, len(values), size):
        yield values[offset:offset + size]


def run(out):
    out = fresh(out)
    inputs = []
    for budget in (32, 128, 512):
        for unseen in (0, 4):
            for depth in (1, 4):
                for seed in (17, 29):
                    inputs.append(dict(budget=budget, unseen=unseen, depth=depth, seed=seed, sized=False))
    inputs.append(dict(budget=2048, unseen=16, depth=4, seed=17, sized=True))
    for group, item in enumerate(inputs):
        item["grants"] = pool(item["budget"], item["depth"], item["seed"], f"group-{group}")
        item["unseen_grants"] = [grant(0, 1, None, 1, [1300] * 5, f"group-{group}-unseen-{i}") for i in range(item["unseen"])]
        item["cohorts"] = ["common", "saturated"]
    with gzip.open(out / "inputs.json.gz", "xt", encoding="utf-8", newline="\n") as stream:
        json.dump(dict(groups=inputs, nodes=list(range(5)), policies=list(POLICIES), epsilon=2,
                       grant_batch_size=16, retry="a rejected batch is retried as singleton operations",
                       clocks="seeded sound readings; loading/revoking at actual 20, recovery at 30, expiry at 2000"), stream, sort_keys=True)
    rows = []
    overall = dict(operations=0, state_matches=0, authorization_checks=0, receipt_checks=0,
                   known_revoke_requests=0, known_revoke_refusals=0, unseen_revoke_refusals=0,
                   unrelated_checks=0, unrelated_losses=0, postreceipt_checks=0,
                   postreceipt_allows=0, progress_violations=0)
    with gzip.open(out / "operations.jsonl.gz", "xt", encoding="utf-8", newline="\n") as trace:
        for group, item in enumerate(inputs):
            budget, unseen = item["budget"], item["unseen"]
            catalog = {g["id"]: g for g in item["grants"] + item["unseen_grants"]}
            for cohort in item["cohorts"]:
                offered = item["grants"][:(budget - unseen) // 2] if cohort == "common" else item["grants"]
                for node in range(5):
                    for policy in POLICIES:
                        tag = f"g{group}-{cohort}-n{node}-{policy}"
                        config = dict(policy=policy, budget=budget, unseen=unseen, node=node, epsilon=2)
                        store = CapacityStore(out / (tag + ".sqlite"), **config)
                        state, accepted, acknowledged = State(), {}, set()
                        counts = {k: 0 for k in overall}
                        peak_records, admitted_count, sequence = 0, 0, 0
                        rng = random.Random(item["seed"] + node)
                        started = time.perf_counter()

                        def apply(batch, actual=20):
                            nonlocal state, peak_records, sequence
                            clock = rng.randrange(actual - 2, actual + 3)
                            assert abs(clock - actual) <= 2
                            store.set_clock(clock)
                            before = state
                            nxt, expected, refusal = transition(state, policy, budget, unseen, node, 2, clock, batch)
                            reply, error = None, None
                            try:
                                reply = store.compact() if batch is None else store.ingest(batch)
                            except ValueError as ex:
                                error = str(ex)
                            assert error == refusal and reply == expected, (tag, sequence, error, refusal)
                            assert store.snapshot() == nxt.snapshot(policy), (tag, sequence)
                            assert nxt.floor <= actual and nxt.floor >= before.floor
                            assert nxt.counts()["records"] <= budget
                            state = nxt
                            counts["operations"] += 1
                            counts["state_matches"] += 1
                            sequence += 1
                            peak_records = max(peak_records, nxt.counts()["records"])
                            if reply is not None and batch is not None:
                                revs = [e for e in batch if e["kind"] == "revoke"]
                                for event, rr in zip(revs, reply["receipts"]):
                                    assert valid_receipt(rr, node, event)
                                    acknowledged.add(target(event)["id"])
                                    counts["receipt_checks"] += 1
                                for event, outcome in zip(batch, reply["outcomes"]):
                                    if event["kind"] == "grant" and outcome in {"added", "duplicate"}:
                                        accepted[event["id"]] = event
                            trace.write(json.dumps(dict(case=tag, sequence=sequence, actual_time=actual, clock=clock,
                                                        inputs=None if batch is None else [e["id"] for e in batch],
                                                        reply=reply, refusal=error, post_floor=nxt.floor,
                                                        post_counts=nxt.counts()), sort_keys=True) + "\n")
                            return reply, error

                        for batch in batches(offered):
                            _, error = apply(batch)
                            if error is not None:
                                for g in batch:
                                    apply([g])
                        admitted_count = len(accepted)
                        expected_count = len(offered) if cohort == "common" else store.grant_limit
                        assert admitted_count == expected_count, (tag, admitted_count, expected_count)
                        physical_after_load = store.physical()
                        store.set_clock(20)
                        before_allows = {}
                        for g in accepted.values():
                            wanted = state_allow(state, policy, g, node, 20, 2)
                            decision = store.authorize(g["id"], g["subject"], 1, g["service"])
                            got = decision["allow"]
                            assert got == wanted and got
                            trace.write(json.dumps(dict(case=tag, authorization=dict(leaf=g["id"],actor=g["subject"],rights=1,service=g["service"],clock=20,actual_time=20),
                                                        decision=decision, obligation="pre-revocation"),sort_keys=True)+"\n")
                            before_allows[g["id"]] = got
                            counts["authorization_checks"] += 1
                        roots = [g for g in accepted.values() if g["parent"] is None]
                        chosen = roots[::2]
                        rng.shuffle(chosen)
                        # The known-target schedule is restricted to each arm's
                        # admitted cohort; only common-cohort arms share it exactly.
                        for g in chosen:
                            _, error = apply([revoke(g)])
                            counts["known_revoke_requests"] += 1
                            counts["known_revoke_refusals"] += int(error is not None)
                            if policy != "append":
                                counts["progress_violations"] += int(error is not None)
                                assert error is None
                        for g in item["unseen_grants"]:
                            _, error = apply([revoke(g)])
                            counts["unseen_revoke_refusals"] += int(error is not None)
                            if policy != "append":
                                counts["progress_violations"] += int(error is not None)
                                assert error is None
                        physical_after_revokes = store.physical()
                        durable = store.snapshot()
                        store.close()
                        store = CapacityStore(out / (tag + ".sqlite"), **config)
                        store.set_clock(30)
                        assert store.snapshot() == durable
                        for g in list(accepted.values()):
                            wanted = state_allow(state, policy, g, node, 30, 2)
                            decision = store.authorize(g["id"], g["subject"], 1, g["service"])
                            got = decision["allow"]
                            assert got == wanted
                            counts["authorization_checks"] += 1
                            related = bool(ancestors(g, catalog) & acknowledged)
                            trace.write(json.dumps(dict(case=tag, authorization=dict(leaf=g["id"],actor=g["subject"],rights=1,service=g["service"],clock=30,actual_time=30),
                                                        decision=decision, obligation="postreceipt" if related else "unrelated"),sort_keys=True)+"\n")
                            if related:
                                counts["postreceipt_checks"] += 1
                                counts["postreceipt_allows"] += int(got)
                                assert not got
                            else:
                                counts["unrelated_checks"] += 1
                                counts["unrelated_losses"] += int(before_allows[g["id"]] and not got)
                                assert got
                        # Late descendant after an early receipt: distinguish
                        # admitted-late cases from missing/refused-late cases.
                        late_admitted = late_refused = 0
                        if item["unseen_grants"] and item["unseen_grants"][0]["id"] in acknowledged:
                            z = item["unseen_grants"][0]
                            hidden = grant(z["subject"], 2, z, 1, [1200] * 5, tag + "-hidden")
                            catalog[hidden["id"]] = hidden
                            # Exact additional consumed payload is retained.
                            trace.write(json.dumps(dict(case=tag, additional_input=hidden), sort_keys=True) + "\n")
                            _, error = apply([z, hidden], actual=30)
                            late_admitted = int(error is None)
                            late_refused = int(error is not None)
                            store.set_clock(30)
                            decision = store.authorize(hidden["id"], 2, 1, hidden["service"])
                            got = decision["allow"]
                            assert got == state_allow(state, policy, hidden, node, 30, 2) and not got
                            trace.write(json.dumps(dict(case=tag, authorization=dict(leaf=hidden["id"],actor=2,rights=1,service=hidden["service"],clock=30,actual_time=30),
                                                        decision=decision, obligation="late-postreceipt"),sort_keys=True)+"\n")
                            counts["postreceipt_checks"] += 1
                            counts["authorization_checks"] += 1
                        physical_before_compaction = store.physical()
                        apply(None, actual=2000)
                        assert state.counts()["records"] == 0
                        apply([revoke(item["grants"][0])], actual=2000)
                        assert state.counts()["records"] == 0
                        physical_after_compaction = store.physical()
                        store.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                        physical_after_checkpoint = store.physical()
                        final_state = store.snapshot()
                        assert store.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                        store.close()
                        row = dict(case=tag, group=group, cohort=cohort, config=config,
                                   admitted_grants=admitted_count, offered_grants=len(offered),
                                   known_targets_requested=len(chosen), peak_records=peak_records,
                                   late_batch_admitted=late_admitted, late_batch_refused=late_refused,
                                   final_state=final_state, counts=counts,
                                   physical=dict(after_load=physical_after_load, after_revokes=physical_after_revokes,
                                                 before_compaction=physical_before_compaction,
                                                 after_compaction=physical_after_compaction,
                                                 after_explicit_checkpoint=physical_after_checkpoint),
                                   descriptive_wall_s=time.perf_counter() - started)
                        rows.append(row)
                        for k in overall:
                            overall[k] += counts[k]
            print(json.dumps(dict(stage="campaign", group=group, completed_cases=len(rows), budget=budget)), flush=True)
    result = dict(case_count=len(rows), groups=len(inputs), environment=dict(platform=platform.platform(),
                  python=sys.version.split()[0], sqlite=sqlite3.sqlite_version, wal="FULL, automatic checkpoint disabled; one explicit truncate checkpoint after measurement"),
                  totals=overall, cases=rows, mismatches=0,
                  scope="same logical budget, owned one-host SQLite; distinct common/own-quota cohorts; file extents separate, no physical capacity or deployment claim")
    save(out / "summary.json", result)
    return result
