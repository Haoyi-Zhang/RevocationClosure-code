# Recovery-Stable Revocation Closure

This repository implements a bounded authorization model and a durable completion-evidence journal for a fixed five-gateway audience. It accompanies **Recovery-Stable Revocation Closure for Offline Capability Delegation**, prepared in IEEE Computer Society journal format for TDSC. It is not a production identity system or a multi-machine deployment.

## Run and reproduce

Requirements: Python 3.10 or newer with the standard library, SQLite, a POSIX-like system for process fault tests, writable local storage, and permission to bind owned loopback sockets. No Java compiler, external dataset, network download, account, or credential is needed. Do not use Python `-O`, because assertions are validation checks.

From this directory:

```sh
python3 reproduce.py --out reproduced --max-commands 3
python3 reproduce.py --out reproduced --resume --max-commands 3
```

Repeat the second command until `reproduced/reproduction.json` says `complete`. Omit the chunk flag for an uninterrupted environment. The 71-command schedule snapshots the full executable root/test Python source set, executes every command from that snapshot, and refuses resume after any source-byte or source-membership change. It compares 69 semantic JSON results, 59 exact structured inputs, and the decompressed 10,240-row collector trace. Timing and process telemetry are not equality targets. The source-count metadata is checked against the actual snapshot, rather than required to equal an earlier implementation's source count.

`results/` holds primary service measurements and the journal's primary experiments. `results/reproduction/` holds their source-closed rerun, with command logs, inputs, and results. Primary latency numbers are not replaced by a faster rerun. A runtime interruption can be resumed at the last recorded command boundary; source changes require a fresh output.

For focused checks:

```sh
python3 tests/collector_audit.py --out journal-check
python3 tests/collector_stateful.py --out journal-check
python3 verify_history.py --directory results
python3 summarize.py --directory results
```

The recovery-window regression is independently runnable:

```sh
python3 tests/recovery_compaction_window.py --out recovery-window-check
```

It records the durable floor, retained counts before and after the first post-recovery compaction, the age-conditioned and $\Delta$-specialized bounds, and ten SQL/interpreter authorization rejections. The case narrows the metadata proposition; it is not reported as a core authorization failure.

## Implementation map

`capability.py` implements immutable fixture records, attenuation, full-ancestry authorization, receipts, atomic admission, and floor-based reclamation. `server.py` exposes five loopback endpoints in **one server process** with five separate SQLite stores. `transport.py` owns that process and its TCP requests. This is one host and one gateway-service fault domain, not five independent gateway processes.

`verifier.py` independently evaluates authorization using sets and dictionaries; it imports neither the SQL implementation nor server dispatch. `collector.py` binds one revoke, membership, and clock-error configuration to a SQLite evidence journal. It joins received receipt coordinates with a retained lower-time watermark, commits before exposing completion, and reconstructs status from evidence on reopen.

`proofs.md` gives the underlying gateway arguments; `collector-proofs.md` gives the journal characterization and its exact observation boundary. `experiment_plan.json` specifies the service grid; `collector-plan.json` specifies the full four-profile, sixteen-seed collector campaign. `claim_evidence_ledger.csv` maps claims to executable or analytical evidence.

## Retained journal evidence

The independent observation oracle matches 26,852 cases: 16,921 covered and 9,931 open, with zero mismatch. It rejects 34 inconsistent clock histories and executes 93 accepting uncovered-coordinate witnesses through the SQL authorizer. The durable journal retains closure through a directed bounded-clock regression that reopens the legacy stateless poll. Three owned child-process exits distinguish precommit loss from postcommit reply loss; all reopened stores pass integrity checks.

The stateful campaign contains 64 traces, 10,240 steps, and 51,200 matching SQL/interpreter comparisons. All 37,890 checks after first closure reject. It includes 1,196 gateway database reopens, 1,135 collector database reopens, 1,554 compactions, 1,809 replays, and 80 late hidden-lineage deliveries. Database reopens in this campaign are not counted as process crashes.

The gateway-service evidence remains separate: 27,648 barrier cases; 29,875 finite/static/evolving/hidden-lineage comparisons; nine transaction crash cases and 45 integrity checks; eight network histories; and 48 lookup runs. Negative controls distinguish volatile receipts, leaf-only lookup, arrival-order replacement, and unsafe clocks from the metadata-only effect of omitting a replay floor.

## Assumptions and limits

The model assumes fixed complete honest membership, authentic immutable records, nonnegative clocks within a fixed error bound after recovery, and durable non-rollback storage. Fixture keys are public; administrative RPC actors and clocks are model inputs, not production authentication. The journal stores a validated receipt mask, not a portable certificate for an untrusted verifier. It does not solve Byzantine receipts, changing audiences, power failure, clock restoration, physical storage rollback, saturation throughput, or cancellation of effects admitted before closure.

No public contact-trace experiment or separate Java model checker is claimed. Finite tests are not an unbounded mechanized proof or independent human review. A familiar lease/receipt/evidence-join pattern is not itself a broad novelty claim. See the paper's closest-work comparison and `source_notes.md` for provenance and interpretation.

## Paper build

The complete project archive additionally contains `paper/`. From that directory, run `sh build.sh` to build `main.pdf` and `supplement.pdf` using the unmodified IEEEtran class and bibliography style. The standalone artifact intentionally does not duplicate the paper tree. The supplement is a separate PDF, not an appendix embedded in the main submission.
