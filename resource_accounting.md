# Resource scope and current reproduction

The retained source-closed campaign completed all 71 scientific commands. Each command used one owned local runner and bounded child processes; no GPU, external compute, external model API, private dataset, or production service was used. Individual commands have a 180-second coordinator timeout.

## Measured coordinator record

The authoritative record is `results/reproduction/reproduction.json`.

- Retained executable source files: 24.
- Successful commands: 71.
- Semantic JSON comparisons: 69.
- Exact structured-input comparisons: 59.
- The complete 10,240-row collector trace was compared after gzip decompression.
- Sum of recorded completed-segment wall intervals: 208.424110796 seconds.
- Sum of command-child CPU observations: 292.362023 seconds.
- Sum of recorded coordinator CPU intervals: 0.223788572 seconds.
- Maximum coordinator RSS in the completion report: 141,432 KiB.
- Every successful command is covered by a completed segment record; the segment command total is 71.

These are scoped process observations, not simultaneous whole-environment RSS or an exact cumulative interactive-session total. The campaign was intentionally executed in bounded resumable segments. No scientific command is marked failed, and each segment exited at a persisted command boundary.

## Primary results and comparisons

The article's lookup figure retains the primary measured per-query data. Reproduction re-executes the grid but checks semantic results and consumed inputs rather than timing equality. The two evidence-journal campaigns retain their own primary timing fields in `collector-audit.json` and `collector-stateful.json`; they are not deployment-latency benchmarks, and database reopen counts are not process-crash counts.

The recovery-compaction-window case is retained in `results/recovery-compaction-window.json`. It records the observed floor and record counts before and after the first post-recovery compaction, plus ten SQL/interpreter authorization rejections. It does not change the article's 26,852 collector cases, 51,200 stateful decisions, 37,890 post-closure rejections, or 9,600 measured lookup queries.

The reproduction guard checks exact executable source bytes and source-set membership. All 24 executable Python files are compared with the snapshot from which the commands run. The standalone repository does not require a toolchain fingerprint or checksum manifest.
