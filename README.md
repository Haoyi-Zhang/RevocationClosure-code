# Recovery-Stable Revocation Closure

A finite authorization model and durable completion-evidence journal for a fixed
five-gateway audience. The SQL implementation, set/dictionary interpreter and
owned loopback harness exercise authorization, recovery and revocation closure.
The accompanying paper is *Recovery-Stable Revocation Closure for Offline
Capability Delegation* (TDSC).

## Requirements

Python 3.10+ and its standard library, including SQLite. The complete reproduction
uses Linux/POSIX process and resource interfaces, writable local storage and
owned loopback sockets. It needs no external service, dataset download or
credentials. Keep Python assertions enabled; do not use `-O`.
`ENVIRONMENT.md` describes the process model and paper-build dependencies.

## Reproduce

Run from this directory in a POSIX shell. Choose a fresh output outside the
checkout, leaving `results/` unchanged:

```sh
OUT="${TMPDIR:-/tmp}/revocation-run"
python3 -B reproduce.py --out "$OUT" --compare results --max-commands 3
python3 -B reproduce.py --out "$OUT" --compare results --resume --max-commands 3
```

Repeat the resume command until `$OUT/reproduction.json` reports `complete`,
or omit `--max-commands` for one uninterrupted run. A run executes 71 commands
from its retained source snapshot and compares 69 semantic JSON results,
59 structured inputs and the decompressed 10,240-row collector trace. Resume
requires unchanged executable source bytes and membership; use a fresh output
after changing source. Timing and process telemetry are not equality targets.

## Focused checks

```sh
python3 -B tests/compaction_transactions.py
python3 -B tests/replay_input_contract.py
python3 -B verify_history.py --directory results
python3 -B lookup_batch.py
python3 -B collector_comparison.py --out "${OUT}-collector"
```

The first two commands use disposable local data. History verification reads the
eight retained histories without writing them. The lookup and collector controls
compare the optimized and straightforward implementations under the same
authorization contract. Their optional `--measure` modes require a separate
fresh output; normal correctness checks do not replace retained timings.

The record-budget module has its own confined output layout and commands in
`capacity/README.md`. Its finite, directed, campaign and replay stages distinguish
common admitted workloads from saturated offered pools.
`docs/capacity-progress.md` defines its quotas, progress conditions and row costs.

## Code and evidence

| Location | Role |
|---|---|
| `capability.py` | SQL records, attenuation, ancestry decisions, admission and reclamation |
| `verifier.py` | Separate set/dictionary authorization interpreter |
| `server.py`, `transport.py` | Five sockets and five stores in one owned server process |
| `collector.py`, `collector_reference.py` | Durable evidence join and same-contract latest-state reference |
| `lookup_batch.py` | Local batched/sequential ancestry comparison |
| `results/` | Retained primary inputs, decisions, traces and measurements |
| `results/reproduction/` | Retained source-closed run, command logs and comparisons |
| `proofs.md`, `collector-proofs.md` | Gateway arguments and journal characterization |
| `claim_evidence_ledger.csv` | Claim-to-proof, implementation and result mapping |
| `source_notes.md`, `external_resources.csv` | Sources, provenance and licenses |

The five endpoints share one host and one gateway-service process. The model
uses fixed honest membership, authentic immutable records, bounded nonnegative
clocks and non-rollback durable storage. Public fixture keys are model inputs,
not production credentials. Local recovery tests distinguish transaction
rollback, reply loss and database reopen from physical power loss.

`STATISTICAL-NOTES.md` explains the actual denominators and error bars.
`resource_accounting.md` describes the retained campaign, not an assumed source
count for a future run. Collector and ancestry measurements retain all paired
outcomes, including slower cases; they measure local SQLite work rather than
WAN closure or deployment gains.

## Paper

The complete project also contains `paper/`; from that directory run
`sh build.sh` for the main manuscript and separate supplement. The script uses
the supplied unmodified IEEEtran class/style and an isolated temporary build.
The standalone code repository intentionally contains only this artifact.
