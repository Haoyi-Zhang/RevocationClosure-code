# Final Artifact Verification

**Status:** PASS for the bounded TDSC artifact and the requested recovery-window repair.

This status is a mechanical and scientific-consistency check inside the declared model. It is not peer review, an acceptance prediction, or evidence for Byzantine gateways, dynamic membership, production credentials, multi-host deployment, physical power loss, or representative workload behavior.

## Recovery-compaction window

`tests/recovery_compaction_window.py` was executed as an independent directed regression. With `epsilon=0` and `L=rho=B=Delta=1`:

- a successful compaction at logical time 0 installed floor 0;
- after reopening at logical time 100, ten deterministic grants with horizons 2 through 11 were admitted before the first post-recovery compaction;
- the observed retained count was 10, while the value 3 from the `A<=Delta` specialization was explicitly inapplicable because the latest-compaction age was 100;
- all ten SQL authorization decisions and independent interpreter checks rejected with reason `expired`;
- compaction at logical time 101 installed floor 101 and reduced the retained count from 10 to 0.

The result is retained in `recovery-compaction-window.json`. It narrows the metadata proposition to the age `A` of the latest successful compaction; it is not reported as a failure of the core authorization-safety theorem.

## Preserved primary evidence

The repair did not change the retained primary counts:

- collector oracle: 26,852 comparisons, 16,921 closed cases, 9,931 open witness cases, and 93 SQL witness executions;
- stateful collector campaign: 64 traces, 10,240 steps, 51,200 SQL/interpreter comparisons, 37,890 post-closure rejections, zero status regressions, and zero post-closure allows;
- gateway finite product: 27,648 barrier instances and 23,520 local decisions;
- combined finite/static/evolving/hidden-lineage authorization correspondence: 29,875 decisions;
- lookup measurements: 48 runs and 9,600 timed queries.

Compressed traces, structured-input fixtures, and command logs are intentionally retained even where a short checklist does not enumerate them individually. Their absence from a prose list is not treated as file loss.

## Source-closed reproduction

`results/reproduction/reproduction.json` records:

- state `complete`;
- 71 successful commands and zero failed attempts;
- 24 executable Python source files bound byte-for-byte to the retained source snapshot;
- 69 semantic JSON comparisons;
- 59 exact structured-input comparisons;
- exact decompressed comparison of the 10,240-row collector trace;
- completed-segment command total equal to 71.

The campaign used a fresh output directory after the scientific-source change. Timing and process telemetry were not required to equal the retained primary measurements.

## Code and data checks

- All executable Python files parse and compile with assertions enabled.
- The project artifact and standalone repository have identical file sets and bytes.
- JSON, gzip JSON, gzip JSONL, and CSV result assets required by the reproduction are retained and parseable.
- The public fixture keys and harness-supplied actor/clock remain explicitly non-production inputs.
- Gateway database reopen, owned process exit, and physical machine/power failure remain distinct claims.
