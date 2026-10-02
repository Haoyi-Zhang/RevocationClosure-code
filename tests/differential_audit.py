"""Deterministic differential audit for authorization and durable receipt disposition.

This is owned synthetic validation.  It compares every Store decision with the
separately written dictionary/set verifier, exercises stateful mutation,
compaction and process recovery against the independent Replay state machine,
then checks the branch where an already sufficient durable floor lets a gateway
acknowledge a revoke without retaining the revoke row.  The branch establishes
terminal durable dominance; it does not claim that a receipt always names a row
still present in SQLite.
"""
from __future__ import annotations

import argparse
import gzip
import json
import random
import resource
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capability import Store, barrier, grant, receipt_authenticated, revocation, sign
from verifier import Replay, verify_barrier, verify_decision

SEED = 20260910
SCENARIOS = 640
STATEFUL_SEEDS = (1103, 2207)
STATEFUL_STEPS = 250
CATEGORIES = (
    "live",
    "ancestor-revoked",
    "missing-parent",
    "rights-amplified",
    "deadline-amplified",
    "expired",
    "root-service-mismatch",
    "issuer-mismatch",
)


def signed_child(parent: dict, subject: int, rights: int, deadlines: list[int], nonce: str,
                 *, issuer: int | None = None, service: str | None = None) -> dict:
    """Construct a well-shaped signed child, including deliberately invalid edges."""
    return sign({
        "kind": "grant",
        "issuer": parent["subject"] if issuer is None else issuer,
        "subject": subject,
        "parent": parent["id"],
        "rights": rights,
        "deadlines": deadlines,
        "nonce": nonce,
        "service": parent["service"] if service is None else service,
    })


def build_case(rng: random.Random, index: int) -> dict:
    category = CATEGORIES[index % len(CATEGORIES)]
    node = rng.randrange(5)
    epsilon = rng.randrange(0, 5)
    depth = 3 + rng.randrange(0, 10)
    root_rights = rng.randrange(1, 256)
    base = 3000 + rng.randrange(0, 1000)
    root_deadlines = [base + 100 * i for i in range(5)]
    root = grant(0, rng.randrange(5), None, root_rights, root_deadlines,
                 f"audit-{index}-0")
    chain = [root]
    parent = root
    for level in range(1, depth):
        rights = parent["rights"] & rng.randrange(1, 256)
        if rights == 0:
            rights = parent["rights"] & -parent["rights"]
        deadlines = [max(1, d - rng.randrange(0, 31)) for d in parent["deadlines"]]
        child = grant(parent["subject"], rng.randrange(5), parent, rights, deadlines,
                      f"audit-{index}-{level}")
        chain.append(child)
        parent = child

    if category == "rights-amplified":
        p = chain[-2]
        chain[-1] = signed_child(p, chain[-1]["subject"], p["rights"] | (1 << 8),
                                 list(chain[-1]["deadlines"]), chain[-1]["nonce"])
    elif category == "deadline-amplified":
        p = chain[-2]
        deadlines = list(chain[-1]["deadlines"])
        coordinate = rng.randrange(5)
        deadlines[coordinate] = p["deadlines"][coordinate] + 1
        chain[-1] = signed_child(p, chain[-1]["subject"], chain[-1]["rights"],
                                 deadlines, chain[-1]["nonce"])
    elif category == "root-service-mismatch":
        body = {k: v for k, v in chain[0].items() if k not in ("id", "mac")}
        body["service"] = "svc1"
        chain[0] = sign(body)
        # Rebind the descendants so ancestry remains complete and only the root
        # service invariant is violated.
        rebuilt = [chain[0]]
        for level, old in enumerate(chain[1:], 1):
            p = rebuilt[-1]
            rebuilt.append(signed_child(p, old["subject"], old["rights"],
                                        list(old["deadlines"]), f"audit-{index}-{level}"))
        chain = rebuilt
    elif category == "issuer-mismatch":
        p = chain[-2]
        wrong = (p["subject"] + 1) % 5
        chain[-1] = signed_child(p, chain[-1]["subject"], chain[-1]["rights"],
                                 list(chain[-1]["deadlines"]), chain[-1]["nonce"],
                                 issuer=wrong)

    leaf = chain[-1]
    events = list(chain)
    if category == "ancestor-revoked":
        events.append(revocation(chain[rng.randrange(0, len(chain) - 1)]))
    elif category == "missing-parent":
        missing_index = rng.randrange(1, len(chain) - 1)
        events = [event for j, event in enumerate(events) if j != missing_index]

    if category == "expired":
        clock = leaf["deadlines"][node] - epsilon
    else:
        clock = 100 + rng.randrange(0, 100)

    held = leaf["rights"]
    one_held = held & -held
    requests = [
        {"cap": leaf["id"], "actor": leaf["subject"], "right": one_held,
         "service": leaf["service"]},
        {"cap": leaf["id"], "actor": (leaf["subject"] + 1) % 5, "right": one_held,
         "service": leaf["service"]},
        {"cap": leaf["id"], "actor": leaf["subject"], "right": one_held,
         "service": "svc1" if leaf["service"] != "svc1" else "svc2"},
        {"cap": leaf["id"], "actor": leaf["subject"], "right": 1 << 31,
         "service": leaf["service"]},
        {"cap": leaf["id"], "actor": leaf["subject"], "right": held,
         "service": leaf["service"]},
        {"cap": leaf["id"], "actor": leaf["subject"], "right": one_held,
         "service": leaf["service"]},
    ]
    return {
        "case": index,
        "category": category,
        "node": node,
        "epsilon": epsilon,
        "clock": clock,
        "events": events,
        "requests": requests,
    }


def durable_floor_receipt_case() -> tuple[dict, dict]:
    """Return the retained input and observed disposition for the floor branch."""
    target = grant(0, 1, None, 7, [50] * 5, "audit-floor-target")
    revoke = revocation(target)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "node0.sqlite"
        store = Store(path, 0)
        store.set_clock(100)
        compacted = store.compact()
        first = store.ingest([revoke])
        assert compacted["floor"] == 100
        assert first["added"] == 0 and first["dropped"] == 1
        assert len(first["receipts"]) == 1 and receipt_authenticated(first["receipts"][0])
        assert store.events() == []
        receipt_value = first["receipts"][0]
        store.close()

        recovered = Store(path, 0)
        recovered.set_clock(100)
        assert recovered.floor == 100 and recovered.events() == []
        replay = recovered.ingest([target, revoke])
        decision = recovered.authorize(target["id"], 1, 1, "svc0", with_snapshot=True)
        assert verify_decision(decision)
        assert not decision["allow"]
        assert replay["added"] == 0 and replay["dropped"] == 2
        assert len(replay["receipts"]) == 1
        recovered.close()

    certificate = barrier(revoke, [receipt_value], 100, 0)
    assert certificate["closed"] and verify_barrier(revoke, [receipt_value], 100, 0)
    source = {
        "target": target,
        "revocation": revoke,
        "initial_clock": 100,
        "epsilon": 0,
    }
    observed = {
        "installed_floor": compacted["floor"],
        "revocation_rows_retained_before_recovery": 0,
        "initial_revoke_added": first["added"],
        "initial_revoke_dropped": first["dropped"],
        "receipt_returned_after_commit": True,
        "recovered_floor": 100,
        "replay_added": replay["added"],
        "replay_dropped": replay["dropped"],
        "post_recovery_allow": decision["allow"],
        "post_recovery_reason": decision["reason"],
        "certificate_closed_at_sound_expiry": certificate["closed"],
        "receipt_meaning": "committed revoke row or already sufficient durable floor",
    }
    return source, observed


def stateful_replay_audit() -> tuple[list[dict], dict]:
    """Exercise evolving stores against an independently maintained replay.

    Each of ten traces performs exactly ``STATEFUL_STEPS`` mutations or clock
    transitions and one authorization comparison per step.  Operations include
    duplicate and reordered delivery, valid and invalid delegation edges,
    ancestor revocation, compaction and process recovery.  The replay receives
    only successful state transitions; after every step both the retained event
    identifiers and the authorization decision must agree.
    """
    traces: list[dict] = []
    reasons: Counter[str] = Counter()
    operations: Counter[str] = Counter()
    decisions = restarts = compactions = issued = refused = 0

    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        for node in range(5):
            for seed in STATEFUL_SEEDS:
                trace_seed = seed + 10000 * node
                rng = random.Random(trace_seed)
                epsilon = rng.randrange(0, 4)
                path = base / f"stateful-{node}-{seed}.sqlite"
                store = Store(path, node, epsilon)
                replay = Replay(node, epsilon)
                clock = 20
                store.set_clock(clock)
                known_grants: list[dict] = []
                known_events: list[dict] = []
                trace_ops: list[dict] = []

                for root_index in range(3):
                    issuer = (node + root_index) % 5
                    root = grant(
                        issuer,
                        rng.randrange(5),
                        None,
                        0xFF,
                        [180 + 20 * coordinate + root_index for coordinate in range(5)],
                        f"stateful-{trace_seed}-root-{root_index}",
                    )
                    store.ingest([root])
                    replay.ingest([root])
                    known_grants.append(root)
                    known_events.append(root)

                for step in range(STATEFUL_STEPS):
                    clock += rng.randrange(0, 4)
                    store.set_clock(clock)
                    choice = rng.randrange(8)
                    record: dict = {"step": step, "clock": clock}

                    if choice == 0:
                        event = rng.choice(known_events)
                        batch = [event, event]
                        store.ingest(batch)
                        replay.ingest(batch)
                        record.update(kind="duplicate-delivery", events=batch)
                    elif choice == 1:
                        parent = rng.choice(known_grants)
                        rights = parent["rights"] & rng.randrange(1, 256)
                        if rights == 0:
                            rights = parent["rights"] & -parent["rights"]
                        deadlines = [max(0, value - rng.randrange(0, 8))
                                     for value in parent["deadlines"]]
                        result = store.delegate(
                            parent["id"], parent["subject"], rng.randrange(5),
                            rights, deadlines, f"stateful-{trace_seed}-delegate-{step}",
                        )
                        record.update(kind="delegate", parent=parent["id"],
                                      issued=result["issued"], reason=result["reason"])
                        if result["issued"]:
                            child = result["event"]
                            replay.ingest([child])
                            known_grants.append(child)
                            known_events.append(child)
                            record["event"] = child
                            issued += 1
                        else:
                            refused += 1
                    elif choice == 2:
                        parent = rng.choice(known_grants)
                        if step % 2:
                            child = signed_child(
                                parent, rng.randrange(5), parent["rights"] | (1 << 8),
                                list(parent["deadlines"]),
                                f"stateful-{trace_seed}-invalid-{step}",
                            )
                            invalid_kind = "rights-amplified"
                        else:
                            child = signed_child(
                                parent, rng.randrange(5), parent["rights"],
                                list(parent["deadlines"]),
                                f"stateful-{trace_seed}-invalid-{step}",
                                issuer=(parent["subject"] + 1) % 5,
                            )
                            invalid_kind = "issuer-mismatch"
                        store.ingest([child])
                        replay.ingest([child])
                        known_grants.append(child)
                        known_events.append(child)
                        record.update(kind="invalid-edge-delivery", subtype=invalid_kind,
                                      event=child)
                    elif choice == 3:
                        target = rng.choice(known_grants)
                        revoke = revocation(target)
                        store.ingest([revoke])
                        replay.ingest([revoke])
                        known_events.append(revoke)
                        record.update(kind="revoke", event=revoke)
                    elif choice == 4:
                        result = store.compact()
                        replay.compact(clock)
                        compactions += 1
                        record.update(kind="compact", result=result)
                    elif choice == 5:
                        store.close()
                        store = Store(path, node, epsilon)
                        store.set_clock(clock)
                        restarts += 1
                        record.update(kind="restart")
                    elif choice == 6:
                        batch = [rng.choice(known_events) for _ in range(1 + rng.randrange(4))]
                        rng.shuffle(batch)
                        store.ingest(batch)
                        replay.ingest(batch)
                        record.update(kind="reordered-batch", events=batch)
                    else:
                        issuer = rng.randrange(5)
                        root = grant(
                            issuer,
                            rng.randrange(5),
                            None,
                            1 + rng.randrange(255),
                            [clock + 80 + 20 * coordinate for coordinate in range(5)],
                            f"stateful-{trace_seed}-fresh-root-{step}",
                        )
                        store.ingest([root])
                        replay.ingest([root])
                        known_grants.append(root)
                        known_events.append(root)
                        record.update(kind="fresh-root", event=root)

                    operations[record["kind"]] += 1
                    candidate = rng.choice(known_grants)
                    request = {
                        "cap": candidate["id"],
                        "actor": candidate["subject"],
                        "right": candidate["rights"] & -candidate["rights"],
                        "service": candidate["service"],
                    }
                    request_variant = step % 5
                    if request_variant == 1:
                        request["actor"] = (candidate["subject"] + 1) % 5
                    elif request_variant == 2:
                        request["service"] = "svc1" if candidate["service"] != "svc1" else "svc2"
                    elif request_variant == 3:
                        request["right"] = 1 << 31

                    decision = store.authorize(**request, with_snapshot=True)
                    if not verify_decision(decision):
                        raise AssertionError({"trace": trace_seed, "step": step,
                                              "decision": decision})
                    replay_reason, replay_atom = replay.decide(request, clock)
                    if (decision["reason"], decision["atom"]) != (replay_reason, replay_atom):
                        raise AssertionError({
                            "trace": trace_seed, "step": step,
                            "store": (decision["reason"], decision["atom"]),
                            "replay": (replay_reason, replay_atom),
                        })
                    store_ids = {event["id"] for event in store.events()}
                    replay_ids = set(replay.records)
                    if store_ids != replay_ids:
                        raise AssertionError({
                            "trace": trace_seed, "step": step,
                            "store_only": sorted(store_ids - replay_ids),
                            "replay_only": sorted(replay_ids - store_ids),
                        })
                    record["request"] = request
                    record["decision"] = {"reason": decision["reason"],
                                            "atom": decision["atom"]}
                    reasons[decision["reason"]] += 1
                    decisions += 1
                    trace_ops.append(record)

                store.close()
                traces.append({
                    "node": node,
                    "seed": trace_seed,
                    "epsilon": epsilon,
                    "steps": trace_ops,
                })

    return traces, {
        "traces": len(traces),
        "steps_per_trace": STATEFUL_STEPS,
        "decisions": decisions,
        "verifier_mismatches": 0,
        "retained_state_mismatches": 0,
        "restarts": restarts,
        "compactions": compactions,
        "delegations_issued": issued,
        "delegations_refused": refused,
        "operation_counts": dict(sorted(operations.items())),
        "reason_counts": dict(sorted(reasons.items())),
    }


def run(out: Path) -> dict:
    if not __debug__:
        raise RuntimeError("Assertions are part of this audit; do not use -O.")
    started = time.perf_counter()
    parent_cpu = time.process_time()
    before_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    rng = random.Random(SEED)
    fixtures = []
    reasons: Counter[str] = Counter()
    category_counts: Counter[str] = Counter()
    decisions = 0
    for index in range(SCENARIOS):
        case = build_case(rng, index)
        category_counts[case["category"]] += 1
        store = Store(Path(":memory:"), case["node"], case["epsilon"])
        store.set_clock(case["clock"])
        store.ingest(case["events"])
        for request in case["requests"]:
            decision = store.authorize(**request, with_snapshot=True)
            if not verify_decision(decision):
                raise AssertionError({"case": index, "request": request, "decision": decision})
            reasons[decision["reason"]] += 1
            decisions += 1
        store.close()
        fixtures.append(case)

    stateful_inputs, stateful_observed = stateful_replay_audit()
    floor_input, floor_observed = durable_floor_receipt_case()
    fixture = {
        "seed": SEED,
        "scenario_count": SCENARIOS,
        "categories": list(CATEGORIES),
        "scenarios": fixtures,
        "stateful_traces": stateful_inputs,
        "durable_floor_receipt_case": floor_input,
    }
    with gzip.open(out / "differential-audit-input.json.gz", "wt") as stream:
        json.dump(fixture, stream, sort_keys=True, separators=(",", ":"))

    after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {
        "seed": SEED,
        "scenarios": SCENARIOS,
        "decisions": decisions,
        "verifier_mismatches": 0,
        "category_counts": dict(sorted(category_counts.items())),
        "reason_counts": dict(sorted(reasons.items())),
        "stateful_replay_audit": stateful_observed,
        "durable_floor_receipt_case": floor_observed,
        "wall_s": time.perf_counter() - started,
        "parent_cpu_s": time.process_time() - parent_cpu,
        "children_cpu_s": ((after_children.ru_utime + after_children.ru_stime) -
                           (before_children.ru_utime + before_children.ru_stime)),
        "parent_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "scope": (
            "Deterministic owned-input differential testing and one on-disk recovery branch; "
            "not a mechanized proof, deployment trace, or independent review."
        ),
    }
    (out / "differential-audit.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results"))
    args = parser.parse_args()
    print(json.dumps(run(args.out), indent=2))
