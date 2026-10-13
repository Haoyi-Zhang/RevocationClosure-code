"""Set/dictionary specification, no SQL/store import; fixture MACs are shared.

This is a separately structured executable oracle, not independent authorship
or independent validation of the common written model or fixture encoding.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field

from fixtures import MAX_CHAIN, target, horizon, receipt


@dataclass
class State:
    grants: dict = field(default_factory=dict)
    revokes: dict = field(default_factory=dict)
    early: set = field(default_factory=set)
    floor: int = 0

    def counts(self):
        total = len(self.grants) + len(self.revokes)
        return dict(records=total, grants=len(self.grants), revokes=len(self.revokes),
                    early=len(self.early), normal=total - len(self.early))

    def snapshot(self, policy):
        rows = []
        for event in [*self.grants.values(), *self.revokes.values()]:
            g = target(event)
            key = g["id"] if policy == "replacement" else event["id"]
            rows.append(dict(key=key, kind=event["kind"], target=g["id"], horizon=horizon(event),
                             early=int(event["kind"] == "revoke" and g["id"] in self.early), event=event))
        return dict(floor=self.floor, records=sorted(rows, key=lambda r: r["key"]))

    def signature(self):
        return (self.floor, tuple(sorted(self.grants)), tuple(sorted(self.revokes)), tuple(sorted(self.early)))


def transition(state, policy, budget, unseen, node, epsilon, clock, batch=None):
    """Return (new state, expected reply, expected refusal), atomically."""
    if clock + epsilon < state.floor:
        return state, None, "clock contradicts floor"
    result = deepcopy(state)
    if batch is None:
        before = result.counts()["records"]
        result.floor = max(state.floor, 0, clock - epsilon)
        result.grants = {k: e for k, e in result.grants.items() if horizon(e) > result.floor}
        result.revokes = {k: e for k, e in result.revokes.items() if horizon(e) > result.floor}
        result.early.intersection_update(result.revokes)
        return result, dict(before=before, after=result.counts()["records"], floor=result.floor), None
    limit = budget if policy == "append" else ((budget - unseen) // 2 if policy == "reservation" else budget - unseen)
    outcomes, receipts = [], []
    for event in batch:
        g = target(event)
        ident = g["id"]
        if horizon(event) <= state.floor:
            outcome = "floor"
        elif policy == "replacement":
            if ident in result.revokes or (event["kind"] == "grant" and ident in result.grants):
                outcome = "duplicate"
            elif event["kind"] == "revoke" and ident in result.grants:
                del result.grants[ident]
                result.revokes[ident] = event
                outcome = "replaced"
            else:
                early = event["kind"] == "revoke"
                if early and len(result.early) >= unseen:
                    return state, None, "unseen quota"
                if not early and result.counts()["normal"] >= limit:
                    return state, None, "grant quota"
                if result.counts()["records"] >= budget:
                    return state, None, "record limit"
                (result.revokes if early else result.grants)[ident] = event
                if early:
                    result.early.add(ident)
                outcome = "added"
        else:
            destination = result.grants if event["kind"] == "grant" else result.revokes
            if ident in destination:
                outcome = "duplicate"
            else:
                early = event["kind"] == "revoke" and ident not in result.grants
                if policy == "reservation":
                    if event["kind"] == "grant" and len(result.grants) >= limit:
                        return state, None, "grant quota"
                    if early and len(result.early) >= unseen:
                        return state, None, "unseen quota"
                if result.counts()["records"] >= budget:
                    return state, None, "record limit"
                destination[ident] = event
                if early:
                    result.early.add(ident)
                outcome = "added"
        outcomes.append(outcome)
        if event["kind"] == "revoke":
            receipts.append(receipt(node, event))
    return result, dict(outcomes=outcomes, receipts=receipts, floor=result.floor, **result.counts()), None


def allow(grants, revokes, leaf_id, actor, requested, service, node, clock, epsilon, floor):
    """Root-to-leaf, set-valued rights, only an allow Boolean is compared."""
    path, seen, current = [], set(), leaf_id
    while current is not None:
        if current not in grants or current in seen or len(path) >= MAX_CHAIN:
            return False
        seen.add(current)
        path.insert(0, grants[current])
        current = grants[current]["parent"]
    if not path:
        return False
    rights = lambda mask: {i for i in range(32) if mask & (1 << i)}
    if path[0]["service"] != f"svc{path[0]['issuer']}":
        return False
    for parent, child in zip(path, path[1:]):
        if (parent["subject"] != child["issuer"] or parent["service"] != child["service"]
                or not rights(child["rights"]).issubset(rights(parent["rights"]))
                or any(b > a for a, b in zip(parent["deadlines"], child["deadlines"]))):
            return False
    leaf = path[-1]
    return (actor == leaf["subject"] and service == leaf["service"] and requested > 0
            and rights(requested).issubset(rights(leaf["rights"]))
            and not any(g["id"] in revokes for g in path)
            and leaf["deadlines"][node] > clock + epsilon
            and leaf["deadlines"][node] > floor)


def state_allow(state, policy, g, node, clock, epsilon):
    grants = dict(state.grants)
    if policy == "replacement":
        grants.update({ident: e["target"] for ident, e in state.revokes.items()})
    return allow(grants, state.revokes, g["id"], g["subject"], 1, g["service"], node, clock, epsilon, state.floor)


def ancestors(g, catalog):
    result, current = set(), g
    while current is not None:
        if current["id"] in result:
            raise ValueError("cycle in fixture")
        result.add(current["id"])
        current = None if current["parent"] is None else catalog[current["parent"]]
    return result
