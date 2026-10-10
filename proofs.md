# Scope note for the journal revision

This document retains the underlying gateway model and the **legacy current-poll** barrier arguments. Statements about stateless status regression describe that baseline, not the new durable collector. The revised article additionally uses `collector-proofs.md` and `collector.py`: a retained time watermark, fixed-configuration evidence journal, inert-deadline boundary, and observation-relative characterization. Implementation clocks and storage remain assumptions; no prior-effect cancellation is implied.

---

# Model, invariants, and complete arguments

These are mathematical arguments about the declared model, not mechanized proofs.
The finite checker tests explicitly enumerated instances of the implementation.
The replay verifier is a separate implementation, not an independent human audit.

## Objects and trust boundary

Let G be a fixed finite set of gateways. Real time t is nonnegative and
nondecreasing. Each active or recovered gateway i, and the certificate collector
c, has a nonnegative clock C_i(t) satisfying |C_i(t)-t| <= epsilon. The bound
includes recovery; a machine whose clock cannot meet it must remain unavailable.
The implementation uses five gateways and one common epsilon. It admits logical
clock and deadline values only in the integer interval [0, 2^53]. Logical clock
inputs supplied by the owned emulator stand for the bounded-error assumption, not
a measured synchronization system. The finite numeric envelope closes parsing and
serialization behavior; it is not an additional theorem premise beyond using
well-defined nonnegative times inside the executable model.

A grant g has immutable content identity, service s, issuer u, subject v, a set
R(g) of rights, a parent identity p(g) or no parent, and deadline vector d(g).
A root is valid only for the service owned by its issuer. Each root owner may
create independent fresh roots. An edge p -> g is valid precisely when services
match, u(g)=v(p), R(g) is a subset of R(p), and d_i(g)<=d_i(p) for every i.
The executable delegation transition takes an explicit actor a, applies the normal
parent authorization check, and issues g only when a=v(p); it then sets u(g)=a.
The implementation limits a usable chain to 256 records and rights to 32 bits.
A depth-255 parent may issue a child at depth 256; delegation from a depth-256 parent
is refused with `chain_limit`, rather than creating a child that authorization must
later reject at depth 257. Single-parent chains are the only authority algebra.
There is no alternative-path
union, group membership, use-count budget, resource implication, or revocation
of independently issued roots.

An authenticated revoke r(g) contains the target grant itself and is authorized
only by u(g). Embedding the target permits admission before the target's ordinary
grant record arrives. Authentication and immutable identity are assumed in the
arguments. The executable uses public, deterministic HMAC fixture keys and hashes:
these exercise bytes and integrity checks, not production credential security.
Principal events and gateway receipts use disjoint fixture-key domains and
different signer fields, so a principal-event MAC cannot satisfy a gateway receipt.
The public RPC is an administrative harness, not an authenticated client API.
Supplying an actor is therefore a model input, while equality with the parent
subject is an enforced state-machine condition.

Gateway i stores immutable event set E_i and durable scalar floor F_i, initially
zero. A grant or revoke has horizon H(e)=max_j d_j(g), using the embedded target
for a revoke. Admission inserts an authenticated, well-shaped event only when
H(e)>F_i; duplicates and events already dominated by F_i are idempotently dropped.
A valid revoke dropped for this second reason may receive a receipt only after the
transaction confirms the durable floor. Exhaustion of the 20,000-record admission
cap rejects the entire batch without a receipt; it does not disable existing uses.
Durable and intentionally volatile revocation effects are staged until the same
transaction commits, so a later event's capacity failure cannot leak a partial revoke.
The executable accepts canonical grants of at most 512 bytes, revoke events of at
most 768 bytes, and replies of at most 16 MiB. The conservative event-array bound
for 20,000 maximum-size events plus separators is 15,380,002 bytes, leaving a
1 MiB framing reserve under the reply cap. These limits bind admitted logical
records to the transport, but do not claim byte optimality or production protocol
compactness. Locally unusable, incomplete, or invalidly attenuated signed grants
may be buffered, but they never authorize a request. A request is allowed only
if its entire chain is present and valid, its actor and service match, its rights
are included at the leaf, no chain member is revoked locally, and

    d_i(leaf) > max(F_i, C_i(t)+epsilon).

All revocation checks include every ancestor. The implementation checks structural
and request errors before revocation, so a rejection's diagnostic label need not
be `revoked` when another blocker also exists.

A revoke receipt for i and r(g) is released only after a FULL SQLite transaction
has committed either the revoke or an already sufficient floor. Its gateway,
revoke and target fields are authenticated in the gateway-receipt domain; exact
target matching and signer-domain separation are part of certificate validation. Crash recovery
preserves committed database state and loses incomplete transactions. This is a
storage contract. Actual tests cover process termination at named points. After each of nine crash
fixtures, all five recovered SQLite databases also return `ok` from
`PRAGMA integrity_check` (45 checks total). This remains process-level evidence, not
power failure, torn-sector behavior, external rollback, or storage-corruption testing.

## Lemma 1: attenuation and inherited expiry

For a valid chain g_0,...,g_k, induction on k gives R(g_k) subset R(g_j) and
coordinatewise d(g_k)<=d(g_j) for every ancestor j. The base case is equality.
For the induction step compose the subset and coordinatewise inequalities on
edge g_(k-1)->g_k with the induction hypothesis. Services are preserved by the
same induction. Because each non-root issuance checks its explicit actor against
the previous subject and records that actor as issuer, a path cannot transfer
authority from an unrelated principal or service within the model.

A permitted request at real time t satisfies C_i(t)+epsilon<d_i(g_k).
Since t<=C_i(t)+epsilon, t<d_i(g_k), and therefore t<d_i(g_j) for every ancestor.
Thus no accepted request contains rights outside any ancestor and no accepted
request occurs at or after any ancestor's audience deadline. The argument does
not establish that every legitimate request is available: missing history,
conservative clocks, admission limits, and chain limits may all deny it.

## Lemma 2: durable local revocation dominance

Suppose i releases a receipt for r(g). The committed transaction establishes one
of two states. If H(r(g))>F_i, r(g) is retained. Before later compaction, admission
is set union, so no grant, duplicate, timestamp, or message order deletes it.
Every local request descending from g either fails earlier chain checks or
encounters g in the all-ancestor revocation test. Recreating a descendant with a
new nonce does not bypass the check because its ancestry still includes g.

If H(r(g))<=F_i, the revoke need not be retained. The durable floor is a sound
lower bound on real time, and every target deadline is at most H(r(g))<=F_i.
Lemma 1 therefore makes g and every valid descendant already expired at every
audience; at i the explicit floor/time guard also denies them. A receipt thus
acknowledges a committed exclusion state, not necessarily a surviving revoke row.

A process crash after the receipt preserves whichever committed state justified
it: retained r(g), or the already-sufficient floor. Later compaction preserves the
same exclusion by Lemma 4. A crash before commitment may lose the transition, but
no receipt is released. A committed state whose reply is lost remains effective;
the collector may be less available because it lacks the receipt, not less safe.

## Theorem 1: receipt-or-expiry closure

For target g, define coverage at collector time C_c as, for every i in G:

    receipt_i(r(g)) is present, OR C_c-epsilon >= d_i(g).

A certificate is closed if all coordinates are covered. From the instant the
collector accepts a closed certificate, every future authorization check at any
gateway rejects a request whose chain descends from g, including checks after
process recovery and requests containing descendants not yet known to the
collector.

Proof. Fix a gateway i. A receipt-covered i denies by Lemma 2 and Lemma 4.
Otherwise let t_c be actual certificate time. Clock soundness gives
C_c-epsilon<=t_c; coverage implies d_i(g)<=t_c. At any future real time t>=t_c,
Lemma 1 prohibits use of any descendant of g at i. The two cases cover every
gateway, independently of message order or future disconnected delegation.
The certificate concerns future authorization decisions, not completion or undo
of effects admitted before t_c. A newly admitted gateway outside fixed G is not
covered. Revoking an ancestor says nothing about a separately issued fresh root.

## Theorem 2: observation-relative completeness in the nondegenerate case

The collector knows only the valid target token (whose ancestry can exist),
the fixed gateway set, its current clock and epsilon, and correctly typed receipts
for this exact revoke. It has no fresh proof of absence of the target at a
gateway, no stronger fencing knowledge, and no knowledge that an unrelated
ancestor has already been revoked. Assume every uncovered audience deadline
exceeds epsilon. Then if the coverage predicate is false, the observation admits
an execution in which an uncovered gateway accepts the target itself now.

Proof. Choose uncovered i with d_i(g)>C_c-epsilon and d_i(g)>epsilon.
Choose actual current time t=max(0,C_c-epsilon), and i's clock
C_i=max(0,t-epsilon). These nonnegative clocks satisfy both error bounds.
Moreover C_i+epsilon=max(epsilon,t)<d_i(g). Supply a valid ancestry for g to i,
with no local revoke and floor zero. The target's subject requests a nonempty
right of g for its service. The valid target grants it, and the expiry test passes.
Delay the target revocation and any receipt from i. Receipt histories of the other
gateways remain unchanged. This extension is indistinguishable to the collector,
so the available evidence cannot guarantee global rejection.

The nondegeneracy condition is material. If d_i(g)<=epsilon, nonnegative clocks
plus the conservative expiry test can make that audience permanently unusable,
even before the collector's lower time reaches the deadline. The simple predicate
remains sufficient but is not complete for those degenerate timestamps. The
finite certificate enumeration uses deadlines 3 or 6 and epsilon 0,1,2, so it
satisfies the stated condition. Also, extra knowledge or a different protocol can
close sooner. This theorem is not a global lower bound on all revocation systems,
not minimum byte-size certification, and not a claim of a novel lease theorem.

With exact clocks and no such degeneracy, let A_i denote receipt arrival time
(infinity when absent), and D_i the inherited target deadline. The earliest time
this ideal predicate becomes true is T = max_i min(A_i,D_i). Each coordinate becomes true
at min(A_i,D_i); their conjunction becomes true at the maximum. This elementary
identity does not give a reply time: an operation begun at S cannot reply before
max(S,T), and must observe sufficient evidence and commit it before replying. It
describes a fixed certificate and fixed issuance policy, not an optimized
lease policy. Per-gateway shorter leases reduce disconnected useful lifetime.

## Lemma 3: monotone-set convergence and its boundary

Without compaction, each successful admission adds elements to E_i by union.
Union is associative, commutative and idempotent. For a finite retained event set
E*, if every event in E* is eventually delivered to every gateway and admission
limits do not reject it, every E_i eventually equals E*. Reordering and duplication
do not affect the result. Common clock, floor and request then produce common
semantic authorization decisions. Durations and service timings need not match.

Delivery fairness, finite retention and sufficient capacity are indispensable.
No equality is promised while messages are withheld. With time-based compaction,
independent floors can produce different stored sets even after all messages have
been exchanged; that is not a safety counterexample and must not be described as
ordinary byte-level strong eventual consistency. Instead, for a common floor F
at least as high as each prior local floor, normalize each state by removing all
events with H(e)<=F. If all still-relevant events have been delivered and admitted,
all normalized event sets agree. The durable floor values themselves agree only
when the nodes adopt that common floor.

## Lemma 4: compaction, receipt persistence, and stale admission

A gateway computes F'=max(F_i,C_i(t)-epsilon), removes every event with H(e)<=F',
and stores F' in the SAME transaction. Since F_i was a lower time bound at an
earlier real instant and time does not go backwards, both arguments to max are
lower bounds on current time. Thus F'<=t. The transaction leaves either the old
state and old floor, or the new state and new floor after a crash.

Any removed target g has d_j(g)<=H(g)<=F'<=t for every gateway j. By Lemma 1 it
and all descendants are expired everywhere now and forever. Removing its grant
record can create a missing-ancestor rejection, but cannot hide a live usable
ancestor. Removing its revocation cannot enable a valid descendant: that
descendant's deadline at every audience is no later than the expired target's.
Future replay of the removed event has the same H(e)<=F' and is refused by the
persistent admission floor. A receipt issued for a discarded, already expired
revoke is sound for the same reason. Hence Theorem 1 survives compaction.

The MAXIMUM audience deadline is necessary for this particular global-discard
rule: a token locally expired at a short-lease gateway may still be needed at a
long-lease gateway. Deleting it only locally is safe for the local gateway but
cannot justify global event reclamation. Our implementation conservatively keeps
it until all audiences have expired, rather than claim a more efficient
per-audience dissemination protocol.

Disabling only persistent admission-floor updates does NOT by itself defeat the
conservative expiry check under the clock contract. It allows old, unusable
records to consume storage again. The negative control is therefore a metadata
regression, not an expired-authorization counterexample.

## Proposition 3: conditional space, not an unconditional bounded-history result

The implementation never successfully admits more than 20,000 records at a
single gateway; the admission check, durable insertion and publication of any
volatile negative-control revoke share one atomic batch boundary.
This bounds admission, with an availability cost, not graceful service under
unbounded issuance. In particular, a new revocation can be refused at capacity:
no receipt is then returned, but an already admitted, unexpired grant may still
be used. Capacity refusal must not be described as a global fail-closed use mode. It also does not bound database-file allocation
by the current JSON payload size; free pages and journal files can remain.

For a separate conditional rate bound, suppose every event's horizon is at most
its creation time plus L and no more than rho*w+B distinct events are created in
any interval of width w. Let t0 be the latest successful compaction and let
A=t-t0 be its age at the current time. That compaction installs a floor of at
least t0-2*epsilon. Every retained event therefore has creation time greater than
t0-2*epsilon-L, while no creation time exceeds t=t0+A. The retained set contains
at most rho*(L+A+2*epsilon)+B events. The familiar
rho*(L+Delta+2*epsilon)+B specialization is valid only when A<=Delta.

A long downtime followed by admission before the first recovery compaction does
not satisfy that specialization. `tests/recovery_compaction_window.py` executes
the concrete epsilon=0, L=rho=B=Delta=1 case: a time-0 compaction leaves floor
0; after reopen at time 100, ten grants with horizons 2 through 11 are admitted
before compaction. The observed count is 10, exceeding the inapplicable value 3,
while all ten SQL decisions and independent verifier checks reject as expired.
Compaction at time 101 advances the floor to 101 and removes all ten records.
This is a retained-metadata window, not an authorization-safety counterexample.
The artifact does not enforce the rate or lifetime premises, so neither form is a
measured service SLA.

Without a retention restriction, expiry, a fence, or an admission refusal, an
unbounded sequence of independent, non-expiring roots already needs unbounded
state. Even with one root, distinct historical decisions may require retaining
revocation information. Calling a data structure finite or a merge idempotent
does not eliminate this information or availability tradeoff.

## Proposition 4: immediate global revocation under a partition

Consider a gateway that has a valid, unexpired capability and receives no messages
during a partition. Compare executions identical at that gateway: in one the
issuer revokes remotely, in the other it does not. The local state, clock and
request are identical. Any deterministic decision rule returns the same result;
a randomized rule has the same decision distribution. Guaranteeing acceptance
for the non-revoked offline request and rejection immediately after the remote
revoke is therefore impossible without changing an assumption. The selected
protocol explicitly permits pre-closure stale use and exposes when it stops.
This is an instance of an established distributed indistinguishability argument,
not a claimed new impossibility theorem.

## Diagnostics and executable correspondence

`capability.py` validates leaf-to-root edges and performs indexed SQL lookups.
`verifier.py` validates authenticated records independently, represents rights as
sets, traverses root-to-leaf edges, and uses dictionaries and sets rather than SQL.
`finite.py` checks both implementations on the stated finite products.
`tests/differential_audit.py` adds 640 deterministic scenarios and 3,840 request
decisions across eight validity categories, with zero verifier mismatches. Ten
additional evolving traces contribute 2,500 step-by-step comparisons while mixing
duplicate and reordered delivery, valid and invalid edges, revocation, compaction
and recovery; both decisions and retained event-id sets match the separate replay.
The same test also exercises the on-disk branch where an already-sufficient floor
justifies a receipt without retaining the revoke. `tests/closure_descendants.py` constructs a valid
three-grant lineage that remains hidden until after a mixed three-receipt/two-expiry
closure, restarts the process twice, and compares 15 use decisions plus five local
delegation attempts; every operation rejects. This is one directed correspondence
case, not an exhaustive descendant enumeration. A separate 16-round owned-loopback
race checks the local gateway's delegate/revoke serialization: only the two serial
orders occur, and no child remains usable after both replies. This is not a
distributed linearizability proof. `histories.py` compares every generated use
against an incrementally reconstructed complete local view. The
verifier also checks barrier receipts independently. `tests/reproduction_guard.py` separately checks
that segmented execution can resume only when the retained Python source file set
and every byte are unchanged. That guard protects provenance of finite evidence; it
is not evidence for the authorization theorem itself.

A decision includes a reason and one atom: missing grant, invalid child edge,
wrong service/subject/right, nearest revoked ancestor, or expired leaf. With a
complete local snapshot the replay verifies the selected reason. A missing grant
is not accompanied by a cryptographic global nonexistence proof. A revoked atom
still needs its valid ancestry and complete view to explain the decision; it is
not a universally subset-minimal event history. No universal minimal-witness
conjecture is retained.

## Clock-window corollaries and non-monotone observations

These corollaries concern only time permission after all structural, ancestry,
request and revocation checks have passed. Let d be one audience deadline and
assume F<=t and |C-t|<=epsilon. If t<d-2*epsilon, then
C+epsilon<=t+2*epsilon<d and F<d, so the time guard permits use.
Conversely, a permitted use implies t<=C+epsilon<d. Thus the conservative
uncertainty window is at most 2*epsilon; no availability claim is made about
missing grants, revoked ancestors, capacity refusal or other policy checks.

If the collector's expiry coordinate is covered, then d<=C_c-epsilon<=t.
If t>=d+2*epsilon, then C_c-epsilon>=t-2*epsilon>=d, so expiry coverage is
certain under every admissible clock reading. These are bounds, not clock
synchronization measurements or optimized lease choices.

A time bound does not require each observed clock value to increase. For
 epsilon=2 and d=10, a collector may read 12 at actual time 10 and 9 at actual
time 11. Its stateless expiry predicate changes from covered to uncovered.
This is not a failure of Theorem 1: after the first observation, all actual
times are at least 10 and all sound authorizer upper bounds are at least their
actual times. The expired lineage is still unusable. Retaining a previously
validated closure certificate is a caller-side option; the implemented
collector is a pure check and does not persist a monotone completion status.
A caller requiring that API must retain a validated receipt/certificate or
sound monotone lower-time state across its own recovery.

A separate example concerns local rejection: at actual time 8, clock 10 and
 epsilon=2, the time guard rejects d=10; at actual time 9, clock 7, it permits
use. Both readings satisfy the contract. An `expired` diagnostic at the early
conservative boundary therefore does not assert that actual time has reached
the deadline. At actual time 10 or later, use is impossible for every admissible
clock. The executable clock checks retain both examples, actual times and all
RPC replies; they do not introduce a stronger monotone-clock premise.

## Bounds on auxiliary state

The 20,000-event cap concerns each gateway's event table. It is not a bound on
caller-retained receipts, requested historical decisions, experiment logs, open
connections, transient batch copies or the collector's callers. The collector
accepts one supplied receipt collection rather than maintaining a globally
bounded history. For n gateways, the current grant representation uses n deadline
coordinates and a revocation embeds the target. The experiments fix n=5 and do
not measure scaling in audience count. A compressed representation or dynamic
membership would need a different encoding and a rechecked contract.
