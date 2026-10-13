"""Owned disk tests: capacity, lineage, quota lifetime, two connections, exits."""
from __future__ import annotations

import json
import gzip
import subprocess
import sys

from fixtures import HERE, grant, revoke, valid_receipt
from capacity_store import CapacityStore, POLICIES
from study_io import fresh, save


def make_root(label, deadline=100):
    return grant(0, 1, None, 3, [deadline] * 5, label)


def refused(store, batch):
    before = store.snapshot()
    try:
        store.ingest(batch)
    except ValueError as error:
        assert store.snapshot() == before
        return str(error)
    raise AssertionError("expected a refusal")


def run(out):
    out = fresh(out)
    cases, inputs = [], []
    audit = gzip.open(out / "operations.jsonl.gz", "xt", encoding="utf-8", newline="\n")

    class DiskStore(CapacityStore):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.actual_time = 0

        def set_clock(self, clock, actual=None):
            actual = clock if actual is None else actual
            assert actual >= self.actual_time and abs(clock - actual) <= self.epsilon
            super().set_clock(clock)
            self.actual_time = actual

        def _audit(self, operation, arguments, action):
            audit.write(json.dumps(dict(phase="call", db=str(self.path.relative_to(HERE)), operation=operation,
                                        clock=self.clock, actual_time=self.actual_time,
                                        config=dict(policy=self.policy,budget=self.budget,unseen=self.unseen,node=self.node,epsilon=self.epsilon),
                                        arguments=arguments), sort_keys=True) + "\n")
            try:
                reply = action()
            except ValueError as error:
                audit.write(json.dumps(dict(phase="return", db=str(self.path.relative_to(HERE)), operation=operation,
                                            refusal=str(error), post=self.snapshot()), sort_keys=True) + "\n")
                raise
            audit.write(json.dumps(dict(phase="return", db=str(self.path.relative_to(HERE)), operation=operation,
                                        reply=reply, post=None if operation == "authorize" else self.snapshot()), sort_keys=True) + "\n")
            return reply

        def ingest(self, batch, failpoint=None, hook=None):
            return self._audit("ingest", dict(batch=batch, failpoint=failpoint, interleave=hook is not None),
                               lambda: super(DiskStore, self).ingest(batch, failpoint, hook))

        def compact(self, failpoint=None, hook=None):
            return self._audit("compact", dict(failpoint=failpoint, interleave=hook is not None),
                               lambda: super(DiskStore, self).compact(failpoint, hook))

        def authorize(self, leaf_id, actor, rights, service):
            return self._audit("authorize", dict(leaf_id=leaf_id, actor=actor, rights=rights, service=service),
                               lambda: super(DiskStore, self).authorize(leaf_id, actor, rights, service))

    for policy in POLICIES:
        config = dict(policy=policy, budget=8, unseen=2, node=0, epsilon=2)
        s = DiskStore(out / f"saturated-{policy}.sqlite", **config)
        s.set_clock(20)
        grants = [make_root(f"saturation-{i}") for i in range(9)]
        admitted = grants[:s.grant_limit]
        s.ingest(admitted)
        before = s.snapshot()
        assert all(s.authorize(g["id"], 1, 1, "svc0")["allow"] for g in admitted)
        new_grant_error = refused(s, [grants[s.grant_limit]])
        rr = revoke(admitted[0]) if admitted else None
        receipts = []
        if policy == "append":
            revoke_error = refused(s, [rr])
            assert s.authorize(admitted[0]["id"], 1, 1, "svc0")["allow"]
        else:
            revoke_error = None
            for g in admitted:
                event = revoke(g)
                response = s.ingest([event])
                assert valid_receipt(response["receipts"][0], 0, event)
                receipts += response["receipts"]
            zs = [make_root(f"early-{i}") for i in range(3)]
            for g in zs[:2]:
                response = s.ingest([revoke(g)])
                assert valid_receipt(response["receipts"][0], 0, revoke(g))
            assert refused(s, [revoke(zs[2])]) == "unseen quota"
            assert all(not s.authorize(g["id"], 1, 1, "svc0")["allow"] for g in admitted)
            # Credits are not released by grant replay or collector receipt delivery.
            assert refused(s, [make_root("still-no-credit")]) == "grant quota"
        peak = s.physical()
        s.set_clock(122, actual=120)  # lower bound 120
        compact = s.compact()
        assert compact["after"] == 0
        response = s.ingest([revoke(grants[0])])
        assert response["outcomes"] == ["floor"] and response["records"] == 0
        assert valid_receipt(response["receipts"][0], 0, revoke(grants[0]))
        s.ingest([make_root("credit-after-expiry", 300)])
        cases.append(dict(case="saturation-and-credit-lifetime", config=config,
                          admitted=len(admitted), new_grant_refusal=new_grant_error,
                          known_revoke_refusal=revoke_error, receipts=len(receipts),
                          before=before, physical_at_peak=peak, compact=compact))
        inputs.append(dict(case="saturation-and-credit-lifetime", config=config, grants=grants,
                           actual_times=[20, 120], clocks=[20, 122], unseen_targets=[make_root(f"early-{i}") for i in range(3)]))
        s.close()

        config = dict(policy=policy, budget=12, unseen=2, node=0, epsilon=2)
        s = DiskStore(out / f"lineage-{policy}.sqlite", **config)
        s.set_clock(20)
        g = make_root("lineage-target")
        h = grant(1, 2, g, 1, [90] * 5, "lineage-child")
        q = grant(2, 3, None, 3, [100] * 5, "unrelated-root")
        v = grant(3, 4, q, 1, [90] * 5, "unrelated-child")
        late = grant(1, 3, g, 1, [80] * 5, "hidden-descendant")
        s.ingest([g, h, q, v])
        assert all(s.authorize(x["id"], x["subject"], 1, x["service"])["allow"] for x in (g, h, q, v))
        response = s.ingest([revoke(g)])
        assert valid_receipt(response["receipts"][0], 0, revoke(g))
        assert s.ingest([late])["outcomes"] == ["added"]
        replay = s.ingest([g])
        for x in (g, h, late):
            assert not s.authorize(x["id"], x["subject"], 1, x["service"])["allow"]
        for x in (q, v):
            assert s.authorize(x["id"], x["subject"], 1, x["service"])["allow"]
        committed = s.snapshot()
        s.close()
        s = DiskStore(out / f"lineage-{policy}.sqlite", **config)
        s.set_clock(20)
        assert s.snapshot() == committed
        assert not s.authorize(late["id"], late["subject"], 1, late["service"])["allow"]
        assert s.authorize(v["id"], v["subject"], 1, v["service"])["allow"]
        # A late batch failure must not release a partial receipt or exclusion.
        before = s.snapshot()
        bad = dict(revoke(q), mac="0" * 64)
        assert refused(s, [revoke(q), bad]) == "invalid batch or failpoint"
        assert s.snapshot() == before and s.authorize(v["id"], v["subject"], 1, v["service"])["allow"]
        cases.append(dict(case="hidden-lineage-and-unrelated-availability", config=config,
                          replay=replay["outcomes"], received_receipt=response["receipts"][0],
                          late_grant_admitted=True, unrelated_after_reopen=True))
        inputs.append(dict(case="lineage", config=config, events=[g, h, q, v, late], clock=20, actual_time=20))
        s.close()

        s = DiskStore(out / f"early-arrival-{policy}.sqlite", **config)
        s.set_clock(20)
        z = make_root("revoke-before-grant")
        child = grant(1, 2, z, 1, [80] * 5, "child-after-early-revoke")
        response = s.ingest([revoke(z)])
        s.ingest([z, child])
        assert not s.authorize(child["id"], 2, 1, "svc0")["allow"]
        if policy != "append":
            w = make_root("second-early")
            s.ingest([revoke(w)])
            # Arrival of z does not free its early-origin credit.
            assert refused(s, [revoke(make_root("third-early"))]) == "unseen quota"
        cases.append(dict(case="early-origin-persists-until-horizon", policy=policy,
                          receipt=response["receipts"][0], snapshot=s.snapshot()))
        inputs.append(dict(case="early-arrival", config=config, events=[revoke(z), z, child], clock=20, actual_time=20))
        s.close()

        # Positive future admission is fixed by authority and free quota, not
        # redefined as false merely because an unrelated early revoke exists.
        s = DiskStore(out / f"eligible-future-{policy}.sqlite", **config)
        s.set_clock(20)
        old = make_root("already-admitted-unrelated")
        early = make_root("revoked-unknown-target")
        future = grant(2, 3, None, 1, [100]*5, "eligible-future-unrevoked")
        s.ingest([old, revoke(early)])
        assert s.authorize(old["id"], 1, 1, "svc0")["allow"]
        result = s.ingest([future])
        assert result["outcomes"] == ["added"]
        assert s.authorize(future["id"], 3, 1, "svc2")["allow"]
        assert s.authorize(old["id"], 1, 1, "svc0")["allow"]
        cases.append(dict(case="eligible-unrevoked-future-admission", policy=policy,
                          future=future, early_revoked_target=early, added=True, authorized=True))
        s.close()

        for index, (ca, cb) in enumerate(((18, 22), (19, 22), (20, 22), (22, 18), (21, 19), (20, 20))):
            path = out / f"floor-{policy}-{index}.sqlite"
            a, b = DiskStore(path, **config), DiskStore(path, **config)
            a.ingest([make_root("short", 19), make_root("long", 100)])
            a.set_clock(ca, actual=20)
            b.set_clock(cb, actual=20)
            observed = []
            def interleave(point):
                if point == "before_transaction":
                    observed.append(b.compact())
            result = a.compact(hook=interleave)
            expected_floor = max(0, ca - 2, cb - 2)
            assert result["floor"] == a.snapshot()["floor"] == expected_floor
            assert result["before"] == observed[0]["after"]
            assert abs(ca - 20) <= 2 and abs(cb - 20) <= 2
            cases.append(dict(case="two-connection-floor-and-count", policy=policy,
                              actual_time=20, clocks=[ca, cb], first_commit=observed[0], reply=result))
            a.close()
            b.close()

        # Re-read admission counts after obtaining the write lock.
        config = dict(policy=policy, budget=4, unseen=1, node=0, epsilon=2)
        path = out / f"admission-{policy}.sqlite"
        a, b = DiskStore(path, **config), DiskStore(path, **config)
        a.set_clock(20)
        b.set_clock(20)
        prefill = [make_root(f"prefill-{i}") for i in range(a.grant_limit - 1)]
        a.ingest(prefill)
        other, waiting = make_root("other-connection-grant"), make_root("waiting-grant")
        def interleave_admission(point):
            if point == "before_transaction":
                b.ingest([other])
        try:
            a.ingest([waiting], hook=interleave_admission)
        except ValueError as error:
            assert str(error) in {"grant quota", "record limit"}
        else:
            raise AssertionError("stale admission count")
        assert a.snapshot() == b.snapshot()
        assert len(a.snapshot()["records"]) <= config["budget"]
        cases.append(dict(case="two-connection-grant-admission", policy=policy, snapshot=a.snapshot()))
        a.close()
        b.close()

        # Valid late capacity/quota failure rolls back earlier batch revokes.
        s = DiskStore(out / f"valid-batch-rollback-{policy}.sqlite", **config)
        s.set_clock(20)
        g = make_root("batch-live-control")
        extras = [make_root(f"batch-prefill-{i}") for i in range(2)] if policy == "append" else []
        s.ingest([g, *extras])
        z, w = make_root("batch-unseen-a"), make_root("batch-unseen-b")
        error = refused(s, [revoke(g), revoke(z), revoke(w)])
        assert error == ("record limit" if policy == "append" else "unseen quota")
        assert s.authorize(g["id"], 1, 1, "svc0")["allow"]
        cases.append(dict(case="valid-late-batch-failure", policy=policy, error=error, old_authority_available=True))
        s.close()

        path = out / f"early-admission-{policy}.sqlite"
        a, b = DiskStore(path, **config), DiskStore(path, **config)
        a.set_clock(20)
        b.set_clock(20)
        def interleave_early(point):
            if point == "before_transaction":
                b.ingest([revoke(z)])
        if policy == "append":
            reply = a.ingest([revoke(w)], hook=interleave_early)
            assert reply["revokes"] == 2  # this control has no protected U quota
        else:
            try:
                a.ingest([revoke(w)], hook=interleave_early)
            except ValueError as error:
                assert str(error) == "unseen quota"
            else:
                raise AssertionError("stale early-origin count")
            assert len(a.snapshot()["records"]) == 1
        before = a.snapshot()
        for changed_config in (dict(config, budget=5), dict(config, unseen=0), dict(config, epsilon=1), dict(config, node=1)):
            try:
                CapacityStore(path, **changed_config)
            except ValueError as error:
                assert str(error) == "configuration mismatch"
            else:
                raise AssertionError("configuration rebound")
            assert a.snapshot() == before
        cases.append(dict(case="two-connection-early-quota-and-configuration", policy=policy, snapshot=before))
        a.close()
        b.close()

        for changed in (True, False):
            for point in ("before_transaction", "before_commit", "after_commit_before_reply"):
                config = dict(policy=policy, budget=8, unseen=2, node=0, epsilon=2)
                path = out / f"fault-{policy}-{changed}-{point}.sqlite"
                s = DiskStore(path, **config)
                s.set_clock(20)
                g = make_root("fault-target")
                s.ingest([g])
                event = revoke(g)
                if not changed:
                    s.ingest([event])
                before = s.snapshot()
                s.close()
                input_path = out / f"fault-{policy}-{changed}-{point}.json"
                save(input_path, dict(path=str(path.relative_to(HERE)), config=config, clock=20, actual_time=20, event=event, point=point))
                cp = subprocess.run([sys.executable, "-B", str(HERE / "run.py"), "fault", "--input", str(input_path)],
                                    cwd=HERE, capture_output=True, text=True, timeout=20)
                assert cp.returncode == 70 and cp.stdout == "" and cp.stderr == "", cp.stderr
                audit.write(json.dumps(dict(phase="fault_process", input=json.loads(input_path.read_text(encoding="utf-8")),
                                            exit=cp.returncode, stdout=cp.stdout, stderr=cp.stderr), sort_keys=True) + "\n")
                s = DiskStore(path, **config)
                s.set_clock(20)
                expected_revoke = not changed or point == "after_commit_before_reply"
                assert s.authorize(g["id"], 1, 1, "svc0")["allow"] == (not expected_revoke)
                if point != "after_commit_before_reply":
                    assert s.snapshot() == before
                assert s.db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
                retry = s.ingest([event])
                assert valid_receipt(retry["receipts"][0], 0, event)
                assert not s.authorize(g["id"], 1, 1, "svc0")["allow"]
                cases.append(dict(case="process-exit-boundary", config=config, changed=changed,
                                  point=point, exit=70, stdout_empty=True, revoked_after_reopen=expected_revoke,
                                  retry_receipt=retry["receipts"][0], integrity="ok"))
                s.close()
    # Representation-specific necessity witness for 2G+U, not a universal bound.
    s = DiskStore(out / "separate-row-bound.sqlite", "append", 4, 1)
    gs = [make_root("tight-a"), make_root("tight-b")]
    z = make_root("tight-unseen")
    s.ingest(gs + [revoke(z), revoke(gs[0])])
    assert refused(s, [revoke(gs[1])]) == "record limit"
    cases.append(dict(case="separate-row-bound-witness", B=4, G=2, U=1, required_records=5,
                      stored=s.snapshot(), refused_target=gs[1]["id"]))
    inputs.append(dict(case="separate-row-bound-witness", grants=gs, unseen=z))
    s.close()
    save(out / "inputs.json", inputs)
    result = dict(cases=cases, case_count=len(cases), failures=0,
                  scope="owned local SQLite, honest actors, bounded supplied clocks; process exits, not power loss or storage rollback")
    save(out / "summary.json", result)
    audit.close()
    return result
