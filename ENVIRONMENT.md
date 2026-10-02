# Execution environment and scope

Scientific commands use Python 3.10+ and its standard library, including SQLite, asyncio, gzip, socket, subprocess, and resource. Linux/POSIX is the tested execution family. Local socket and owned-process permissions are needed. Python assertions must be enabled. No third-party Python dependency, Java, external trace, private data, GPU, remote service, or online retrieval is required.

The gateway harness runs one sequential emulator process and one owned asyncio server process. Five gateway sockets and five databases share the server process. Journal crash tests run one owned child at a time. Stateful journal tests reopen databases in their test process. Parallel worker count is one. Each scientific command has a 180-second timeout in the coordinator; resumable chunks accommodate a shorter calling environment.

Reproduction retains the exact executable root and test Python source set and command logs. It compares scientific decisions, structured inputs, and ordered collector traces, not timing equality. Results report scoped process CPU/RSS where collected. No whole-session global memory peak or cumulative human-session CPU figure is asserted.

Paper builds additionally require pdfLaTeX, BibTeX (or the equivalent installed `bibtex.original` entry), standard AMS/graphics packages, TikZ, and PGFPlots. IEEEtran class and bibliography-style files are supplied unmodified with their license notices. Font files are not redistributed.
