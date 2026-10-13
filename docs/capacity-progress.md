# Record budgets and revocation progress

## Model

Let R be the authorization-record budget, U the quota for a revocation received
before its target grant, and G the normal-grant quota. Target identifiers are
immutable and there is one canonical revoke event per target. The target's
horizon is the maximum deadline over the fixed audience. A sound persistent
floor permits reclamation when that horizon is at or below the floor.

The model uses honest local gateways, authenticated immutable events, single
parents, attenuating rights/service/deadlines, complete ancestry, bounded clocks
after recovery, and successful durable commits. Event validation precedes any
transaction. Floor and quota counts are read after the write lock is acquired;
a reply containing receipts is released after commit. Authorization reads one
database snapshot and rejects if any ancestor has a retained exact revoke or
if the leaf deadline is at or below the conservative current-time/floor bound.

Early-origin credit persists through later grant arrival. A normal target remains
normal-origin after revocation. Neither kind of credit is released by receipt
delivery; a sound horizon compaction releases it. Fixed quota configuration is
checked when a database is reopened.

## Separate-row reservation

A normal grant has a retained grant row and at most one canonical revoke row.
Choose G = floor((R-U)/2). With n_g normal grant rows and n_k revokes of known
targets, n_k <= n_g <= G. At most U early-origin revoke rows remain. Therefore
the record count is at most 2G+U <= R. An early-target grant arriving later uses
a normal grant credit while its early-origin revoke keeps the early credit.

For any reachable valid state, a revoke-only batch whose targets are already
known, duplicated, floor-covered, or new early targets within the available U
credit can commit without exceeding this bound. Known-target revocation can
add at most one row for its retained grant; repeated revocations add none.
The statement concerns this target/credit domain, not arbitrary mixed batches.

For a representation that retains a separate individually addressable grant and
revoke row for each of G simultaneously live normal targets and U early targets,
2G+U rows are necessary: the state containing all G grants, their G distinct
revokes, and the U distinct early revokes contains that many required rows.
This is a representation-specific row bound, not a byte lower bound.

## One-target-row replacement

Choose G = R-U. Each normal target occupies one row. A committed revoke atomically
replaces the grant disposition and retains the grant payload needed for ancestry;
grant replay cannot overwrite the revoke. Each early-origin target occupies one
separately credited row. Thus at most G+U <= R rows are retained, and the same
known/duplicate/floor/early-credit revoke-only batches fit. Keeping one individually
addressable disposition for each of G normal and U early targets requires G+U rows
in this representation. Compression or packed membership structures use a
different accounting model.

## Exclusion and non-interference

After a receipt returns, the transaction has retained an exact revoke or the
target horizon is covered by a sound floor. While the exact revoke remains,
complete ancestry checks reject the target and every valid descendant, including
a descendant delivered later. Replay cannot remove the disposition. If compaction
removes it, the horizon and every attenuated deadline are at or below the floor,
so later authorization still rejects. A failed batch rolls back and releases no
receipt. Precommit termination retains the old state; postcommit reply loss
retains the new state and permits a consistent retry.

A revoke-only transition changes only its target dispositions. At a fixed clock
and floor, the authorization decision of an already-admitted chain disjoint from
those targets is unchanged. Complete parent availability is part of this claim.
For an eligible fresh unrevoked grant with a free declared normal credit, admission
adds its row without changing unrelated dispositions. Eligibility is determined
by the authority/time model, not by a blanket ban on unknown future grants.

These contracts distinguish the admission price of reservation from the capacity
benefit of replacement. They use ordinary durable storage policies; the original
gateway event-export/convergence representation and its diagnostics remain a
separate implementation. The capacity experiment compares authorization Booleans
and receipts within its stated model, rather than transferring historical gateway
campaign counts to a different representation.

## Executable evidence

`../capacity/capacity_store.py` implements the write-locked policies and snapshot
authorizer. `reference.py` uses sets/dictionaries and root-to-leaf rights sets,
without importing the SQL store. Both share fixture encoding and the specification.
`finite_study.py` checks every enabled transition in the declared depth-bounded
state space, including eligible future admission and unrelated-chain decisions.
`directed_tests.py` isolates lineage, quotas, atomic failure and recovery boundaries.
`campaign.py` keeps common-cohort and own-quota comparisons separate and records
physical extents before/after compaction and explicit checkpointing.

The fixed metadata row, indexes, temporary batches, WAL/SHM and free database
pages are outside R. Logical row savings therefore require a separate physical
storage measurement. The recorded SQLite comparisons include cases where fewer
logical rows do not give fewer allocated bytes.
