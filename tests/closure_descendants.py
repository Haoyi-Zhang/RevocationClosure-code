"""Directed mixed-cover closure test with a previously unseen valid lineage.

The revoke reaches only three gateways.  A hybrid certificate closes the other
two by target expiry.  After two owned-process restarts, the target and two valid
descendants are delivered for the first time; all uses and new delegations must
still be rejected.  This is finite correspondence evidence, not a general proof.
"""
from __future__ import annotations

import argparse
import gzip
import json
import resource
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from capability import grant, revocation
from transport import Cluster
from verifier import verify_barrier, verify_decision


def run(out: Path) -> dict:
    if not __debug__:
        raise RuntimeError("Assertions are part of this test; do not use -O.")
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    parent_cpu = time.process_time()
    before_children = resource.getrusage(resource.RUSAGE_CHILDREN)

    epsilon = 2
    target = grant(0, 1, None, 7, [100, 100, 100, 40, 40], "closure-target")
    child = grant(1, 2, target, 3, [90, 90, 90, 35, 35], "closure-child")
    grandchild = grant(2, 3, child, 1, [80, 80, 80, 30, 30], "closure-grandchild")
    revoke = revocation(target)
    lineage = [target, child, grandchild]
    receipt_nodes = [0, 1, 2]
    closure_actual_time = 40
    collector_clock = 42
    post_restart_actual_time = 42
    post_restart_clock = 40

    fixture = {
        "epsilon": epsilon,
        "target": target,
        "hidden_lineage": lineage,
        "revocation": revoke,
        "receipt_nodes": receipt_nodes,
        "closure_actual_time": closure_actual_time,
        "collector_clock": collector_clock,
        "post_restart_actual_time": post_restart_actual_time,
        "post_restart_clock": post_restart_clock,
    }
    with gzip.open(out / "closure-descendants-input.json.gz", "wt") as stream:
        json.dump(fixture, stream, sort_keys=True, separators=(",", ":"))

    decisions = []
    delegations = []
    with tempfile.TemporaryDirectory() as directory, gzip.open(
            out / "closure-descendants-trace.jsonl.gz", "wt") as trace:
        with Cluster(Path(directory) / "state", epsilon=epsilon) as cluster:
            def rpc(node: int, actual_time: int, request: dict) -> dict:
                assert abs(request.get("clock", actual_time) - actual_time) <= epsilon
                response = cluster.rpc(node, request)
                trace.write(json.dumps({
                    "actual_time": actual_time,
                    "node": node,
                    "request": request,
                    "response": response,
                }, sort_keys=True) + "\n")
                return response

            receipts = []
            for node in receipt_nodes:
                reply = rpc(node, 20, {"op": "ingest", "clock": 20, "events": [revoke]})
                receipts.extend(reply["receipts"])

            certificate = rpc(0, closure_actual_time, {
                "op": "barrier",
                "clock": collector_clock,
                "revocation": revoke,
                "receipts": receipts,
            })
            assert certificate["closed"]
            assert certificate["cover"] == ["receipt", "receipt", "receipt", "expiry", "expiry"]
            assert verify_barrier(revoke, receipts, collector_clock, epsilon)

            # The receipt state survives recovery before the hidden lineage arrives.
            cluster.restart()
            trace.write(json.dumps({
                "actual_time": 41,
                "op": "process_restart_before_hidden_lineage",
            }, sort_keys=True) + "\n")
            for node in range(5):
                rpc(node, 41, {"op": "ingest", "clock": 39, "events": lineage})

            # Recover once more so both the prior revoke and newly delivered grants
            # are read from disk at the decisions below.
            cluster.restart()
            trace.write(json.dumps({
                "actual_time": post_restart_actual_time,
                "op": "process_restart_before_decisions",
            }, sort_keys=True) + "\n")

            for node in range(5):
                for token in lineage:
                    request = {
                        "op": "use",
                        "clock": post_restart_clock,
                        "cap": token["id"],
                        "actor": token["subject"],
                        "right": token["rights"] & -token["rights"],
                        "service": token["service"],
                        "snapshot": True,
                    }
                    answer = rpc(node, post_restart_actual_time, request)
                    assert not answer["allow"] and verify_decision(answer)
                    expected = "revoked" if node in receipt_nodes else "expired"
                    assert answer["reason"] == expected
                    decisions.append({
                        "node": node,
                        "capability": token["id"],
                        "depth": lineage.index(token) + 1,
                        "reason": answer["reason"],
                    })

                issue = rpc(node, post_restart_actual_time, {
                    "op": "delegate",
                    "clock": post_restart_clock,
                    "parent": target["id"],
                    "actor": target["subject"],
                    "subject": 4,
                    "rights": 1,
                    "deadlines": [70, 70, 70, 25, 25],
                    "nonce": f"post-closure-{node}",
                })
                expected = "revoked" if node in receipt_nodes else "expired"
                assert not issue["issued"] and issue["reason"] == expected
                delegations.append({"node": node, "issued": issue["issued"], "reason": issue["reason"]})

            messages = cluster.messages
            wire_bytes = cluster.sent_bytes + cluster.received_bytes
            server_peak = cluster.max_server_rss_kib

    after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
    result = {
        "certificate_closed": certificate["closed"],
        "cover": certificate["cover"],
        "hidden_lineage_depth": len(lineage),
        "process_restarts": 2,
        "post_closure_authorization_comparisons": len(decisions),
        "post_closure_delegation_attempts": len(delegations),
        "all_authorizations_rejected": all(x["reason"] in {"revoked", "expired"} for x in decisions),
        "all_delegations_rejected": all(not x["issued"] for x in delegations),
        "reasons_by_node": {
            str(node): sorted({x["reason"] for x in decisions if x["node"] == node})
            for node in range(5)
        },
        "decisions": decisions,
        "delegations": delegations,
        "messages": messages,
        "wire_bytes": wire_bytes,
        "server_peak_rss_kib": server_peak,
        "wall_s": time.perf_counter() - started,
        "parent_cpu_s": time.process_time() - parent_cpu,
        "children_cpu_s": (
            after_children.ru_utime + after_children.ru_stime
            - before_children.ru_utime - before_children.ru_stime
        ),
        "parent_peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "scope": (
            "One deterministic owned-loopback mixed-cover case with a valid depth-three lineage; "
            "finite correspondence evidence, not exhaustive descendant or deployment evidence."
        ),
    }
    (out / "closure-descendants.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=Path("results"))
    args = parser.parse_args()
    print(json.dumps(run(args.out), indent=2))
