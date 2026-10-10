# Durable collector characterization

## Model and observations

The gateway model and proofs are in `proofs.md`. Let epsilon be fixed and nonnegative, actual time be nondecreasing and nonnegative, and every active clock C satisfy C >= 0 and |C - t| <= epsilon. A valid child has no more rights and no later deadline at any audience. A use requires complete valid ancestry, a matching subject/service/right, no ancestor revoke, and d_i > max(F_i, C_i + epsilon).

For one immutable revoke r(g), the collector observes a feasible ordered history C_1,...,C_m and received exact durable receipts. Let K = max(0, max_j(C_j - epsilon)) and A be the receipt-covered coordinates. It knows no additional absence, ancestor-revoke, fencing, or effect-completion fact. The target admits a valid nonempty lineage. The collector's knowledge of receipt ordering imposes no additional numerical time bounds in this model.

## Coverage

Every coordinate i is covered when i is in A, or d_i(g) <= max(K, epsilon). A nonreceipt coordinate is reported as inert if d_i <= epsilon; otherwise it is expired when d_i <= K. Inertness is a permanent authorizer restriction, not an observation that actual expiry has passed.

## Sufficiency for all future authorization

K is at most actual time at observation and every later time. A received receipt supplies persistent local dominance: either the exact revoke survives, or safe floor-based reclamation has made every audience deadline expire. For other coordinates, d_i <= K gives actual expiry; d_i <= epsilon gives C_i + epsilon >= d_i at every nonnegative reading. Deadline attenuation extends both arguments to every valid hidden or future descendant. Complete ancestry rejects malformed or missing lineages. These cases cover the fixed finite audience without later message delivery.

## Necessity relative to this observation

For an uncovered coordinate i, d_i(g) > max(K, epsilon). Construct historical actual times t_j = max(0, max_{k<=j}(C_k-epsilon)). They are nondecreasing, satisfy every lower clock bound, and satisfy every upper clock bound by feasibility of the observed history. Set current time to K and the gateway reading to max(0,K-epsilon). This reading is nonnegative, within epsilon of current time, and has upper bound max(K,epsilon) strictly below d_i(g).

Supply the complete valid ancestry at i, floor zero, no target or ancestor revoke, and a request by the target subject for a nonempty permitted right on its service. The gateway authorizes. Preserve receipts at the other coordinates and delay the revoke at i. This is observationally indistinguishable to the stipulated collector. It proves failure of inference from the restricted observation, not that the actual open gateway must accept.

The construction includes the target itself as a lineage request. The full valid ancestry can coexist by premise and inherited restrictions. Extra information about a revoked ancestor, absent authority, dynamic membership, trusted hardware, or an external fence changes the observation model and can permit other closure rules.

## Monotone evidence and transaction boundary

Join evidence by (K,A) join (K',A') = (max(K,K'), A union A'). For fixed configuration, this is associative, commutative, and idempotent and cannot invalidate coverage. The implementation validates all incoming receipts before a BEGIN IMMEDIATE transaction, joins evidence, commits, then exposes status. A precommit process failure leaves the previous state and cannot have returned the new closure. A postcommit/pre-reply failure loses the reply but preserves evidence. A retry or database reopen reconstructs the same or a stronger status. Committed-state rollback is excluded.

A reading with C + epsilon < K contradicts the retained history and is rejected. This necessary consistency test does not certify clock soundness. A new target, audience, or epsilon cannot reinterpret an existing database. The state is a locally trusted validated receipt mask, not a transferable certificate verified by an untrusted observer.

## Liveness and limits

If each coordinate eventually has a received receipt or sufficient retained time evidence and the collector continues taking steps, finite membership yields eventual closure. With finite deadlines and sound progressing time, expiry eventually suffices; unscheduled processes still have no guaranteed response time. Under exact clocks and fixed receipt arrivals/deadlines, the ideal receipt-or-expiry predicate crossing is T = max_i min(A_i,d_i). An operation started at S cannot reply before max(S,T); its reply follows a sufficient collector observation and durable commit. This identity is not an optimal lease assignment or an impossibility result for stronger fences.

All guarantees concern future checks. They do not undo prior effects or released information. They do not supply production cryptography, clock synchronization, Byzantine behavior, power-loss semantics, dynamic membership, or physical disk-rollback protection.

## Executable correspondence

`tests/collector_audit.py` enumerates feasible actual-time histories independently of the watermark formula: 26,852 finite cases agree, 9,931 uncovered witnesses satisfy the construction, and 93 selected witnesses actually authorize in SQL. Three owned process exits check the collector transaction boundary. `tests/collector_stateful.py` covers all four profiles and sixteen seeds: 51,200 decisions agree with the independently structured authorization interpreter, 37,890 post-closure checks reject, and returned status never regresses. These are finite checks, not a mechanized proof of an unbounded implementation.
