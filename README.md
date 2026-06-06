# Lnk

A parser-aware, coverage-guided fuzzer for the Windows Shell Link (`.lnk`) format, built on
[Jackalope](https://github.com/googleprojectzero/Jackalope) + TinyInst and targeting the real
`shell32.dll` / `msi.dll` parsers. It parses each seed into a typed model, applies one
structure-aware mutation chosen by a **two-level Thompson Sampling bandit** over live coverage
feedback, reserializes, and runs it through the Shell Link COM surface under dynamic instrumentation.

Productive mutation strategies are learned, not hand-weighted: the scheduler shifts budget toward the
format regions and corruption styles that keep unlocking new code in the parser.

```
seed .lnk ─▶ deserialize ─▶ typed model ─▶ scheduler picks+applies ─▶ serialize ─▶ shell32 / msi
                                              one of ~85 operators        (rebuild         │  under
                                              (Thompson Sampling)          magic/sigs/len) │  TinyInst
            update Beta posteriors ◀── new coverage? ◀── coverage + oracles ◀──────────────┘
```

## Why parser-aware

A `.lnk` is dense with structure a byte-level mutator wastes its budget fighting — the `0x4C` header
magic, the 16-byte CLSID, ExtraData signatures (`0xA00000xx`), the `0x53505331` property-store
version, interdependent length/offset fields. Random bit-flips die at the header. This fuzzer mutates
*fields and structure* and recomputes the invariants on the way out, so mutations re-enter the parser
deep instead of bouncing off the magic. **What** to corrupt is a learning problem, handled by the
scheduler.

## The science

Mutation scheduling is framed as a **Bernoulli multi-armed bandit**: each operator pays off (new
coverage) with an unknown, non-stationary, highly uneven probability. The scheduler must balance
exploiting known-productive operators against exploring uncertain ones — under a finite budget.

- **Beta-Bernoulli conjugacy.** Each arm's coverage rate `θ ~ Beta(α, β)`; the Bernoulli outcome
  updates it exactly in `O(1)` — success `α += 1`, failure `β += 1`, from a `Beta(1,1)` uniform prior.
- **Thompson Sampling.** Draw `θ̂ ~ Beta(α, β)` per arm, act on the argmax. Exploration is emergent
  from posterior width — no ε, temperature, or decay schedule — and because beliefs (not point
  estimates) drive selection, it re-explores automatically when coverage saturates an arm. Preferred
  here over greedy/AFL and MOPT for exactly that non-stationarity.
- **Two-level (hierarchical) bandit.** Sample over 15 operator *groups*, then over the
  precondition-valid operators inside the winner. Every outcome credits both levels, so a group's
  belief pools its operators' evidence — convergence with ~85 arms.
- **Sampling.** No closed-form Beta inverse-CDF, so `X~Γ(α), Y~Γ(β) ⟹ X/(X+Y)~Beta(α,β)`, with Gamma
  by Marsaglia–Tsang over Box–Muller normals. ~1000 uniform draws per decision — which is why the
  PRNG is **xoroshiro128++** (period `2¹²⁸−1`, full-width, BigCrush-clean) seeded by splitmix64, not
  `rand()` (15-bit, ~2³¹ period, thread-unsafe — bias would propagate straight into the posteriors).

Full treatment: [docs/scheduler.md](docs/scheduler.md) and [docs/prng.md](docs/prng.md).

## Oracles

A fuzzer is an input generator plus an oracle — the judge that decides *was that a bug?* Three run here:

| oracle | judge | catches |
|---|---|---|
| crash      | hardware fault, via TinyInst | memory corruption (AV, heap guard, `/GS`, stack exhaustion) |
| hang       | `-t` timeout                 | non-termination / DoS |
| **sink**   | API hooks in [`oracle.h`](oracle.h) | attacker-controlled code execution — the logic-RCE class |

The crash oracle is free but blind to *successful* misbehavior: the Stuxnet-family bugs
(CVE-2010-2568 / 2015-0096 / 2017-8464) make shell32 *load attacker code*, which doesn't fault. The
**behavioral sink oracle** closes that gap — it IAT-hooks the code-exec sinks
(`LoadLibrary{,Ex}W`, `CreateProcessW`, `WinExec`, `ShellExecuteExW`), judges each call's module path
against a System32 allowlist, and converts a violation into a self-identifying access violation
(`0xDEAD0xxx`) so the existing crash pipeline captures the input. `harness.cpp` additionally drives
`IExtractIconW::Extract` so the historic CPL-load sink is actually reached. Details, the IAT
mechanism, and the mandatory positive/negative-control validation: [docs/oracles.md](docs/oracles.md).

## Layout

```
mutate.{c,h}        ~85 structure-aware operators (15 groups) + Thompson Sampling scheduler
model.h             typed LNK model — section structs, ItemID types, layouts
deserialize.c       raw bytes  → LNKGeneratorState
serialize.c         LNKGeneratorState → raw bytes (recomputes magic / signatures / lengths)
gen.c               from-scratch valid-state generators (seed synthesis)
lnk_prng.{c,h}      xoroshiro128++ / splitmix64, per-thread
clsids.h            143 IShellFolder CLSIDs (registry-enumerated) for PIDL injection
oracle.h            behavioral sink oracle, shared by both harnesses
harness.cpp         shell32 target  — IPersistStream::Load → Resolve → full IShellLinkW surface
harness_darwin.cpp  msi.dll target  — MsiGetShortcutTargetW / CommandLineFromMsiDescriptor
lnk_mutator.cc      Jackalope Mutator adapter (deserialize → mutate_apply → serialize)
lnk_prng_jackalope.cc  Jackalope PRNG adapter over xoroshiro
lnk_fuzzer_main.cc  Fuzzer subclass — wires PRNG + mutator; produces lnk_fuzzer.exe
tools/              seed generators
docs/               architecture, scheduler, prng, oracles, format reference, attack surface
```

Two campaigns, run separately (TinyInst instruments one module per run): `harness.exe` over
`shell32.dll`, `harness_darwin.exe` over `msi.dll`.

## Quick start

```
git submodule update --init --recursive
cmake -S . -B build -G "Visual Studio 17 2022" -A x64 && cmake --build build --config Release
python tools\generate_seeds.py
build\Release\lnk_fuzzer.exe -in seeds -out findings -nthreads 24 -t 5000 -t1 10000 ^
  -delivery shmem -max_sample_size 1048576 -instrument_module shell32.dll ^
  -target_module harness.exe -target_method fuzz -nargs 1 ^
  -iterations 10000 -persist -loop -cmp_coverage -generate_unwind ^
  -- build\Release\harness.exe -m @@
```

Full flag reference, the msi campaign, PageHeap, and distributed mode: [docs/running.md](docs/running.md).

## Documentation

[docs/](docs/) — start at [architecture.md](docs/architecture.md). The design depth lives in
[scheduler.md](docs/scheduler.md) (probability/statistics) and [oracles.md](docs/oracles.md)
(detection model).

## References

- [MS-SHLLINK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink) — Shell Link Binary File Format
- [MS-PROPSTORE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-propstore) — Property Store Binary File Format
- [Geoff Chappell — RegFolder](https://www.geoffchappell.com/studies/windows/shell/shell32/classes/regfolder.htm) — DELEGATEITEMID
- [libfwsi](https://github.com/libyal/libfwsi) — Windows Shell Item documentation
- Thompson (1933); Marsaglia & Tsang (2000), *A Simple Method for Generating Gamma Variables*; Blackman & Vigna (2018), xoshiro/xoroshiro
