# Record-budget revocation experiments

This module compares append-only event retention, separate-row reservation, and
one-target-row replacement at the same logical record budget. It specializes
immutable single-parent capability chains with attenuating deadlines and rights,
complete ancestry checks, bounded nonnegative clocks, and durable local commits.
The normal and early-revocation quotas are fixed at initialization.

Run from this directory with Python 3.12 and assertions enabled:

```sh
python -B -m unittest test_environment test_retained_input -v
python -B run.py finite --out reproduced/finite
python -B run.py directed --out reproduced/directed
python -B run.py campaign --out reproduced/campaign
python -B run.py verify --out reproduced/verification --finite-input reproduced/finite --directed-input reproduced/directed --campaign-input reproduced/campaign
```

Each output must be fresh. All writable paths are confined to this module.
`results/finite`, `results/directed`, and `results/campaign` retain complete inputs,
operation/authorization records, summaries, and actual runtime environment records.
Retained streams use lossless XZ containers; fresh runs emit gzip. The replay accepts
both and preserves the same decompressed records. Directed database names and process
inputs are relative to this directory.
The read-only replay uses these records and the separate set/dictionary specification;
it does not reopen retained SQLite databases. Public fixture keys are not credentials.

The finite stage covers 24 configurations to depth five modulo exact state/depth
merging. Disk tests exercise lineage, quota lifetime, transaction serialization,
batch rollback, and 18 selected owned process exits. The campaign has 25 groups,
two cohorts, five separately exercised node coordinates, and three policies:
750 local cases. Common-cohort arms admit identical workloads; saturated arms
receive the same offered pool but admit different cohorts and expose the admission
price of protected revocation space.

The promised progress concerns revoke-only batches for known targets or early
targets within the remaining early-origin quota. An already-admitted unrelated
chain retains its decision, and eligible unrevoked grants are admitted when a
declared normal credit is free. Reservation and replacement are ordinary controls.
Their exact contracts and row accounting are in `../docs/capacity-progress.md`.

Record count excludes fixed metadata, indexes, transient buffers, DB/WAL/SHM
allocation and SQLite free pages. Physical file extents and checkpoint effects are
recorded separately. Reopen and owned process termination are local storage tests,
distinct from physical power loss or multi-host deployment. CPU/OS records are
sampled on each assigned runner; missing hardware-query values remain unknown.
