# Documentation

| doc | contents |
|---|---|
| [architecture.md](architecture.md) | the fuzzing loop, why parser-aware, data flow, component map, boundaries |
| [scheduler.md](scheduler.md)       | the science — Bernoulli bandit, Beta-Bernoulli conjugacy, two-level Thompson Sampling, Beta-via-Gamma sampling, concurrency |
| [prng.md](prng.md)                 | xoroshiro128++ / splitmix64, statistical requirements, reproducibility |
| [oracles.md](oracles.md)           | crash / hang / behavioral-sink oracles, IAT hooking, validation, harness count |
| [lnk-format.md](lnk-format.md)     | MS-SHLLINK section layout as the parser sees it (reference) |
| [extra-data.md](extra-data.md)     | field-level deep dives on security-relevant ExtraData blocks (reference) |
| [attack-surface.md](attack-surface.md) | the CVEs the operators and oracle target |
| [running.md](running.md)           | build, both campaigns, PageHeap, distributed, triage |

Start at [architecture.md](architecture.md). The two docs that carry the design's depth are
[scheduler.md](scheduler.md) (probability/statistics) and [oracles.md](oracles.md) (detection model).
