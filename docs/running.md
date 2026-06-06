# Building & running

## Build

```
git submodule update --init --recursive       # populate Jackalope/ + TinyInst/
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
python tools\generate_seeds.py                 # seed corpus (tools\generate_seeds_darwin.py for msi)
```

Three executables: `lnk_fuzzer.exe` (the frontend you run), `harness.exe` (shell32 target),
`harness_darwin.exe` (msi target). Release builds carry PDBs (`/Zi /DEBUG`) so crash dumps symbolize.

## shell32 campaign

```
build\Release\lnk_fuzzer.exe `
  -in seeds -out findings `
  -nthreads 24 `
  -t 5000 -t1 10000 `
  -delivery shmem -max_sample_size 1048576 `
  -instrument_module shell32.dll `
  -target_module harness.exe -target_method fuzz -nargs 1 `
  -iterations 10000 -persist -loop `
  -cmp_coverage -generate_unwind `
  --% -- build\Release\harness.exe -m @@
```

| flag | meaning |
|---|---|
| `-nthreads 24`            | parallel workers; each gets its own xoroshiro stream |
| `-t 5000 / -t1 10000`     | per-sample / first-startup timeout (ms) — also the hang oracle |
| `-delivery shmem`         | samples over shared memory, no disk I/O |
| `-max_sample_size 1048576`| **must** equal `LNK_MAX_BYTES` / `MAX_SAMPLE_SIZE` in the harness or samples truncate silently |
| `-instrument_module`      | the module coverage is collected from — the parser, not the harness |
| `-persist -loop`          | persistent target; `fuzz()` loops in-process instead of relaunching |
| `-cmp_coverage`           | track comparison operands — blasts through the magic numbers LNK is full of |
| `-generate_unwind`        | handle SEH unwinding so shell32's own `__try/__except` isn't mistaken for crashes |

## msi (Darwin) campaign — separate run

```
build\Release\lnk_fuzzer.exe -in seeds_darwin -out findings_darwin `
  -instrument_module msi.dll `
  -target_module harness_darwin.exe -target_method fuzz -nargs 1 `
  -t 5000 -t1 10000 -delivery shmem -max_sample_size 1048576 `
  -iterations 10000 -persist -loop -cmp_coverage -generate_unwind `
  --% -- build\Release\harness_darwin.exe -m @@
```

Run it as its own campaign: a shell32 run never calls the msi descriptor decoder, so `GROUP_DARWIN`
mutations get no reward signal there and the scheduler starves them.

## Detection fidelity — enable PageHeap

The crash oracle only catches corruption that *faults*. shell32 is closed-source (no ASan), so
without page-granular heap checking, sub-page overflows and use-after-free on still-mapped memory
pass silently. For a serious memory-safety pass, enable Application Verifier / PageHeap on the
instrumented module:

```
gflags /p /enable harness.exe /full           # full page heap (slower, higher recall)
```

Run this as a second, slower campaign rather than always-on. See [oracles.md](oracles.md) for the
oracle taxonomy and the validation procedure you must run before trusting the sink oracle.

## Distributed

`lnk_fuzzer` inherits Jackalope's server/client model unchanged: one node with `-start_server`
coordinates; workers connect with `-server <ip>:8000` and stream new-coverage samples to the shared
corpus. Each node needs its own build and seed copy.

## Triaging findings

A crash dump faulting at `0xDEAD0xxx` is a **behavioral oracle hit** (logic-RCE candidate) — the low
byte is the sink id, the `0x100` bit marks an input-tainted path. Any other faulting address is a
conventional memory/DoS finding. See [oracles.md](oracles.md).
