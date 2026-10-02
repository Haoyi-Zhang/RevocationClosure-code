"""Executable recovery-window case for the age-conditioned metadata bound.

This test is intentionally separate from the authorization-safety campaigns.  It
shows that a long downtime can make the Delta-specialized retained-count bound
inapplicable until a successful compaction occurs, while the current upper-time
guard still rejects every expired grant.  It uses owned temporary SQLite state
and deterministic fixture records only.
"""
from __future__ import annotations

import argparse
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from capability import N, Store, grant
from verifier import verify_decision


def run(out: Path) -> dict:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    cpu_started = time.process_time()

    epsilon = 0
    lifetime = 1
    rho = 1
    burst = 1
    delta = 1
    initial_compaction_time = 0
    recovery_time = 100
    first_post_recovery_compaction_time = 101

    # One creation at each integer time 1..10, each with horizon creation+1.
    # For any real interval of width w, this schedule has at most w+1 events,
    # so rho=1 and B=1 satisfy the declared arrival envelope.
    events = []
    event_facts = []
    for creation_time in range(1, 11):
        horizon = creation_time + lifetime
        issuer = (creation_time - 1) % N
        event = grant(
            issuer,
            issuer,
            None,
            1,
            [horizon] * N,
            f"recovery-window-{creation_time}",
        )
        events.append(event)
        event_facts.append(
            {
                "creation_time": creation_time,
                "horizon": horizon,
                "event_id": event["id"],
            }
        )

    with tempfile.TemporaryDirectory() as directory:
        db_path = Path(directory) / "gateway.sqlite"

        store = Store(db_path, node=0, epsilon=epsilon)
        store.set_clock(initial_compaction_time)
        initial_compaction = store.compact()
        assert initial_compaction == {"before": 0, "after": 0, "floor": 0}
        store.close()

        # Reopening the database models recovery of the persistent store.  The
        # existing implementation admits against the last durable floor until
        # an explicit compaction advances it.
        store = Store(db_path, node=0, epsilon=epsilon)
        store.set_clock(recovery_time)
        replay = store.ingest(events)
        before_compaction = store.stats()
        decisions = [
            store.authorize(
                event["id"],
                event["subject"],
                1,
                event["service"],
                with_snapshot=True,
            )
            for event in events
        ]
        for decision in decisions:
            assert verify_decision(decision)
            assert not decision["allow"]
            assert decision["reason"] == "expired"

        store.set_clock(first_post_recovery_compaction_time)
        post_recovery_compaction = store.compact()
        after_compaction = store.stats()
        store.close()

    specialized_bound = rho * (lifetime + delta + 2 * epsilon) + burst
    compaction_age_at_replay = recovery_time - initial_compaction_time
    age_conditioned_bound = (
        rho * (lifetime + compaction_age_at_replay + 2 * epsilon) + burst
    )

    assert replay["added"] == 10 and replay["dropped"] == 0
    assert before_compaction["floor"] == 0
    assert before_compaction["records"] == 10
    assert before_compaction["records"] > specialized_bound
    assert compaction_age_at_replay > delta
    assert before_compaction["records"] <= age_conditioned_bound
    assert post_recovery_compaction["floor"] == 101
    assert post_recovery_compaction["before"] == 10
    assert post_recovery_compaction["after"] == 0
    assert after_compaction["records"] == 0

    result = {
        "case": "recovery-compaction-age-window",
        "parameters": {
            "epsilon": epsilon,
            "L": lifetime,
            "rho": rho,
            "B": burst,
            "Delta": delta,
            "initial_compaction_time": initial_compaction_time,
            "recovery_time": recovery_time,
            "first_post_recovery_compaction_time": first_post_recovery_compaction_time,
        },
        "events": event_facts,
        "initial_floor": initial_compaction["floor"],
        "replay": {
            "added": replay["added"],
            "dropped": replay["dropped"],
            "records_before_first_post_recovery_compaction": before_compaction["records"],
            "floor_before_first_post_recovery_compaction": before_compaction["floor"],
        },
        "authorization": {
            "checks": len(decisions),
            "rejected": sum(not decision["allow"] for decision in decisions),
            "reasons": sorted({decision["reason"] for decision in decisions}),
            "sql_interpreter_agreement": all(verify_decision(decision) for decision in decisions),
        },
        "bounds": {
            "Delta_specialization": specialized_bound,
            "Delta_specialization_premise_holds_at_replay": compaction_age_at_replay <= delta,
            "compaction_age_at_replay": compaction_age_at_replay,
            "age_conditioned_bound_at_replay": age_conditioned_bound,
            "pre_compaction_count_exceeds_Delta_specialization": (
                before_compaction["records"] > specialized_bound
            ),
            "pre_compaction_count_within_age_conditioned_bound": (
                before_compaction["records"] <= age_conditioned_bound
            ),
        },
        "post_compaction": {
            "floor": post_recovery_compaction["floor"],
            "records_before": post_recovery_compaction["before"],
            "records_after": post_recovery_compaction["after"],
        },
        "interpretation": (
            "Observed executable case: the Delta-specialized metadata bound does not apply "
            "before the first successful post-recovery compaction because the last-compaction "
            "age is 100>Delta. Authorization safety is preserved by the upper-time check; all "
            "ten expired grants reject. The general age-conditioned bound applies, and the "
            "next compaction advances the durable floor and removes the retained metadata."
        ),
        "wall_s": time.perf_counter() - started,
        "parent_cpu_s": time.process_time() - cpu_started,
        "parent_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    }
    (out / "recovery-compaction-window.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results"))
    args = parser.parse_args()
    print(json.dumps(run(args.out), indent=2))
