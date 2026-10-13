"""Replay retained raw evidence through the SQL-free specification, read-only.

The replay checks raw replies/decisions and summary counts. It is not independent
of reference.py or a proof of the common specification. No original DB is opened.
"""
from __future__ import annotations

import gzip
import json
import lzma
from collections import defaultdict
from copy import deepcopy

from fixtures import HERE, owned, revoke, valid_event, target, horizon
from reference import State, transition, state_allow, allow, ancestors
from study_io import fresh, save, compact_state


def open_retained(path):
    path = owned(path)
    if not path.exists() and path.suffix == '.gz':
        path = owned(path.with_suffix('.xz'))
    opener = gzip.open if path.suffix == '.gz' else lzma.open if path.suffix == '.xz' else open
    return opener(path, 'rt', encoding='utf-8')


def read(path):
    with open_retained(path) as stream:
        return json.load(stream)


def decision(state, policy, query, config):
    gs = dict(state.grants)
    if policy == "replacement":
        gs.update({i: e["target"] for i, e in state.revokes.items()})
    return allow(gs, state.revokes, query["leaf_id"], query["actor"], query["rights"], query["service"],
                 config["node"], query["clock"], config["epsilon"], state.floor)


def finite(path):
    inputs, summary = read(path / "inputs.json"), read(path / "summary.json")
    counts = defaultdict(int)
    cache = {}
    expanded = set()
    catalog = {g["id"]:g for g in inputs["grants"]}
    with open_retained(path / "transitions.jsonl.gz") as stream:
        for line in stream:
            row = json.loads(line)
            c = inputs["configs"][row["config"]]
            key = (row["config"], tuple(tuple(p) for p in row["prefix"]))
            if key not in cache:
                state = State()
                for level, (action, clock) in enumerate(row["prefix"]):
                    assert abs(clock-level) <= c["epsilon"]
                    state, _, _ = transition(state, c["policy"], c["budget"], c["unseen"], c["node"], c["epsilon"], clock, inputs["actions"][action])
                cache[key] = state
            state = cache[key]
            assert compact_state(state) == row["pre"]
            expanded.add((row["config"],row["depth"],json.dumps(row["pre"],sort_keys=True)))
            assert row["actual_time"] == row["depth"] == len(row["prefix"])
            assert abs(row["clock"]-row["actual_time"]) <= c["epsilon"]
            nxt, expected, error = transition(state, c["policy"], c["budget"], c["unseen"], c["node"], c["epsilon"], row["clock"], inputs["actions"][row["action"]])
            assert expected == row["reply"] and error == row["refusal"]
            assert compact_state(nxt) == row["post"]
            wanted = [state_allow(nxt,c["policy"],g,c["node"],row["clock"],c["epsilon"]) for g in inputs["grants"]]
            assert wanted == row["authorization"]
            batch = inputs["actions"][row["action"]]
            eligible = False
            if batch is not None and batch[0]["kind"] == "grant":
                g, p, b, u = batch[0], c["policy"], c["budget"], c["unseen"]
                room = (state.counts()["records"] < b if p == "append" else
                        len(state.grants) < (b-u)//2 if p == "reservation" else state.counts()["normal"] < b-u)
                if room and g["id"] not in state.grants and g["id"] not in state.revokes:
                    virtual = deepcopy(state)
                    virtual.grants[g["id"]] = g
                    eligible = state_allow(virtual,p,g,c["node"],row["clock"],c["epsilon"])
            assert eligible == row["eligible_future"]
            if eligible:
                assert row["action"] < 4 and error is None and wanted[row["action"]]
                counts["future_admission_obligations"] += 1
            if batch is not None and batch[0]["kind"] == "revoke" and c["policy"] != "append":
                ident = target(batch[0])["id"]
                if ident in state.grants or ident in state.revokes or len(state.early)<c["unseen"] or horizon(batch[0])<=state.floor:
                    assert error is None
                    counts["progress_obligations"] += 1
            if expected is not None and batch is not None and batch[0]["kind"] == "revoke":
                ident = target(batch[0])["id"]
                before = [state_allow(state,c["policy"],g,c["node"],row["clock"],c["epsilon"]) for g in inputs["grants"]]
                for index,g in enumerate(inputs["grants"]):
                    if ident in ancestors(g,catalog):
                        assert not wanted[index]
                        counts["receipt_checks"] += 1
                    else:
                        assert wanted[index] == before[index]
                        counts["unrelated_checks"] += 1
            counts["transitions"] += 1
            counts["authorization_checks"] += len(wanted)
            counts["refused"] += int(error is not None)
    counts["states_expanded"] = len(expanded)
    counts["state_matches"] = counts["transitions"]
    for metric in summary["totals"]:
        assert counts[metric] == summary["totals"][metric],metric
    return dict(raw_counts=dict(counts))


def campaign(path):
    inputs, summary = read(path / "inputs.json.gz"), read(path / "summary.json")
    cases = {r["case"]: r for r in summary["cases"]}
    states = {key: State() for key in cases}
    acknowledged = {key:set() for key in cases}
    before_allow = {key:{} for key in cases}
    catalogs = {}
    for key, row in cases.items():
        group = inputs["groups"][row["group"]]
        gs = group["grants"] + group["unseen_grants"]
        catalogs[key] = {e["id"]: e for g in gs for e in (g, revoke(g))}
    counts = defaultdict(lambda: defaultdict(int))
    with open_retained(path / "operations.jsonl.gz") as stream:
        for line in stream:
            row = json.loads(line)
            key, c, state = row["case"], cases[row["case"]]["config"], states[row["case"]]
            if "additional_input" in row:
                g = row["additional_input"]
                assert valid_event(g)
                catalogs[key][g["id"]] = g
                continue
            if "authorization" in row:
                q = row["authorization"]
                assert abs(q["clock"]-q["actual_time"]) <= c["epsilon"]
                query = dict(leaf_id=q["leaf"],actor=q["actor"],rights=q["rights"],service=q["service"],clock=q["clock"])
                assert row["decision"]["allow"] == decision(state,c["policy"],query,c)
                assert row["decision"]["floor"] == state.floor
                counts[key]["authorization_checks"] += 1
                if row["obligation"] == "pre-revocation":
                    assert row["decision"]["allow"]
                    before_allow[key][q["leaf"]] = row["decision"]["allow"]
                else:
                    gs = {i:g for i,g in catalogs[key].items() if g["kind"]=="grant"}
                    related = bool(ancestors(gs[q["leaf"]],gs) & acknowledged[key])
                    assert related == (row["obligation"] in {"postreceipt","late-postreceipt"})
                if row["obligation"] == "unrelated":
                    assert row["decision"]["allow"]
                    counts[key]["unrelated_checks"] += 1
                    counts[key]["unrelated_losses"] += int(before_allow[key][q["leaf"]] and not row["decision"]["allow"])
                if row["obligation"] in {"postreceipt", "late-postreceipt"}:
                    assert not row["decision"]["allow"]
                    counts[key]["postreceipt_checks"] += 1
                    counts[key]["postreceipt_allows"] += int(row["decision"]["allow"])
                continue
            assert abs(row["clock"]-row["actual_time"]) <= c["epsilon"]
            batch = None if row["inputs"] is None else [catalogs[key][i] for i in row["inputs"]]
            nxt, expected, error = transition(state,c["policy"],c["budget"],c["unseen"],c["node"],c["epsilon"],row["clock"],batch)
            assert expected == row["reply"] and error == row["refusal"]
            assert nxt.floor == row["post_floor"] and nxt.counts() == row["post_counts"]
            if batch is not None:
                if expected is not None:
                    acknowledged[key].update(target(e)["id"] for e in batch if e["kind"]=="revoke")
                if len(batch)==1 and batch[0]["kind"]=="revoke" and row["actual_time"]==20:
                    ident = target(batch[0])["id"]
                    if ident in state.grants:
                        counts[key]["known_revoke_requests"] += 1
                        counts[key]["known_revoke_refusals"] += int(error is not None)
                    else:
                        assert ident not in state.revokes
                        counts[key]["unseen_revoke_refusals"] += int(error is not None)
                    if c["policy"]!="append":
                        counts[key]["progress_violations"] += int(error is not None)
                        assert error is None
            states[key] = nxt
            counts[key]["operations"] += 1
            counts[key]["receipt_checks"] += len(expected["receipts"]) if expected is not None and batch is not None else 0
    for key, row in cases.items():
        assert states[key].snapshot(row["config"]["policy"]) == row["final_state"]
        for metric in ("operations","receipt_checks","authorization_checks","unrelated_checks","postreceipt_checks",
                       "unrelated_losses","postreceipt_allows","known_revoke_requests","known_revoke_refusals","unseen_revoke_refusals","progress_violations"):
            assert counts[key][metric] == row["counts"][metric], (key,metric)
    for value in counts.values():
        value["state_matches"] = value["operations"]
    totals = {k:sum(v[k] for v in counts.values()) for k in summary["totals"]}
    for metric,value in totals.items():
        assert value == summary["totals"][metric],metric
    return dict(cases=len(cases),raw_counts=totals)


def directed(path):
    summary = read(path / "summary.json")
    stacks, states, configs = defaultdict(list), {}, {}
    returns = auth = faults = 0
    with open_retained(path / "operations.jsonl.gz") as stream:
        for line in stream:
            row = json.loads(line)
            if row["phase"] == "call":
                key = str(owned(row["db"]))
                c = row["config"]
                states.setdefault(key,State())
                configs.setdefault(key,c)
                assert configs[key] == c
                assert abs(row["clock"]-row["actual_time"]) <= c["epsilon"]
                stacks[key].append(row)
            elif row["phase"] == "fault_process":
                value = row["input"]
                key = str(owned(value["path"]))
                assert row["exit"] == 70 and row["stdout"] == row["stderr"] == ""
                assert not stacks[key]
                if value["point"] == "after_commit_before_reply":
                    c = value["config"]
                    states[key], _, err = transition(states[key],c["policy"],c["budget"],c["unseen"],c["node"],c["epsilon"],value["clock"],[value["event"]])
                    assert err is None
                faults += 1
            else:
                key = str(owned(row["db"]))
                call = stacks[key].pop()
                c, args = call["config"], call["arguments"]
                assert call["operation"] == row["operation"]
                if row["operation"] == "authorize":
                    query = dict(args,clock=call["clock"])
                    assert row["reply"]["allow"] == decision(states[key],c["policy"],query,c)
                    assert row["reply"]["floor"] == states[key].floor
                    auth += 1
                else:
                    batch = args["batch"] if row["operation"] == "ingest" else None
                    if batch is not None and not all(valid_event(e) for e in batch):
                        nxt, expected, err = states[key], None, "invalid batch or failpoint"
                    else:
                        nxt, expected, err = transition(states[key],c["policy"],c["budget"],c["unseen"],c["node"],c["epsilon"],call["clock"],batch)
                    assert row.get("refusal") == err
                    if err is None:
                        assert row["reply"] == expected
                    states[key] = nxt
                    assert row["post"] == nxt.snapshot(c["policy"])
                returns += 1
    assert not any(stacks.values()) and faults == 18
    return dict(cases=summary["case_count"], raw_returns=returns, raw_authorizations=auth, owned_process_exits=faults)


def run(out, paths):
    out = fresh(out)
    assert set(paths) == {'finite', 'directed', 'campaign'}
    paths = {key: owned(path) for key, path in paths.items()}
    result = {"finite":finite(paths["finite"]),"directed":directed(paths["directed"]),"campaign":campaign(paths["campaign"]),
              "mismatches":0,"scope":"read-only raw replay through the shared SQL-free specification; no database or old P001 pipeline execution"}
    save(out/"summary.json",result)
    return result
