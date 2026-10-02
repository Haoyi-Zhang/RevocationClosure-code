# Statistical interpretation

The primary lookup grid has four record counts, four chain depths, and three runs per point: 48 runs, 9,600 timed queries, and 960 warmups. The client opens a fresh loopback TCP connection per query. The server timer covers a different interval. The plot uses medians of three run medians and observed minimum/maximum run medians. These bars are **not bootstrap or confidence intervals**. The original per-query CSV files and summary generator are retained.

Timing is environment-dependent. Source-closed reproduction compares scientific state and consumed fixtures, not latency equality. It does not select a faster reproduction to replace the primary plot. The journal extension has no performance-improvement threshold and no measured claim to reduce lookup latency or WAN completion.

The collector oracle is an exact finite product, not a random sample. The 64 stateful traces are the full Cartesian product of four declared profiles and sixteen fixed seeds, with 160 steps each. Repeated steps within a trace are correlated. The 37,890 post-closure checks must not be treated as that many independent population trials or as a substitute for the proof.

There is no learned model or training/test split. The relevant robustness controls are a predeclared finite grid, all profile/seed results retained, separate oracle and authorization implementations, accepting witnesses for uncovered cases, invalid inputs, actual transaction fault injection, and explicit unsafe variants. These reduce scenario and implementation-path dependence; they do not establish representative edge demand or deployment external validity.
