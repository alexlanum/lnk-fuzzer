# Oracles

An **oracle** is the judge: after each input runs, it answers one question — *was that a bug?* A
fuzzer is an input generator plus an oracle; without the oracle it just opens a million files and
shrugs. This campaign runs three.

| oracle | judge | question | source |
|---|---|---|---|
| crash      | CPU + OS, caught by TinyInst | did the process fault? | free (hardware) |
| hang       | timer (`-t`)                 | did it run too long?   | Jackalope flag |
| **sink**   | hooks in [`oracle.h`](../oracle.h) | did the target execute attacker-controlled code? | this project |

## Crash & hang — the free oracles

Memory-corruption fuzzing gets its oracle from the hardware: the MMU faults on an out-of-bounds
access, TinyInst catches the exception, Jackalope dedups and saves the input. No code written. It
fires on access violations (`0xC0000005`), the heap-corruption guard (`0xC0000374`), `/GS` fastfail
(`0xC0000409`), stack exhaustion (`MUTATE_PIDL_DEPTH`), and similar fatal faults. The hang oracle is
a stopwatch: the `-t` timeout flags samples that don't terminate — the DoS class several operators
target on purpose (e.g. `MUTATE_PROPSTORE_VALUE_SIZE_ZERO`, an infinite-loop walker).

These cover *self-harm* and *non-termination*. They are structurally blind to a third class.

## Sink (behavioral) oracle — the one we add

The CVEs the operators are built around — CVE-2010-2568 (Stuxnet), CVE-2015-0096, CVE-2017-8464
([attack-surface.md](attack-surface.md)) — are **logic** bugs: shell32 is steered into loading
attacker-controlled code and the load **succeeds**. A successful `LoadLibrary` does not fault, so
the crash oracle never sees it. The input side is built to produce these (`GROUP_PIDL`,
`GROUP_SPECIALFOLDER`, `GROUP_KNOWNFOLDER`, the CPL dispatch); the missing piece was a judge that
can recognize a hit. `oracle.h` is that judge.

All three CVEs collapse onto **one sink**: a module load triggered by parsing an untrusted `.lnk`.
A sink oracle watches the sink, not the bypassed check — so it catches a whitelist bypass without
needing to understand how the bypass works.

### Detection model

```
reach     drive IExtractIconW::Extract on the resolved PIDL — the call that historically ends in
          CPL_LoadCPLModule -> LoadLibraryW. Resolve() alone (SLR_NO_UI) never gets there.
recognize IAT-hook the code-exec sinks; judge each call's module path.
report    convert a hit into a deliberate, self-identifying access violation so TinyInst's existing
          crash path captures the input. The logic bug rides the free crash channel.
```

**Policy.** A load is benign iff the module is a bare name (loader resolves via the system search
path) or rooted under `%SystemRoot%` / `System32`. Any other path — temp, UNC, a `\\.\STORAGE`
device path (the literal Stuxnet payload) — is a finding. Resource-only `LoadLibraryEx` loads
(`AS_DATAFILE` / `AS_IMAGE_RESOURCE`) never run `DllMain`, so they are skipped to keep the signal
clean.

**Taint tag.** If the offending path's UTF-16 image also occurs in the current sample bytes, the
load was provably steered by the mutator (not by machine state). It is *tagged* in the report, never
used to suppress one — a miss is inconclusive (the path may be env-expanded), so taint informs
triage rather than gating detection.

**Report.** A write to `0xDEAD0NNN` — `NN` = sink id, `0x100` bit = tainted. The faulting address
self-documents the finding class in the dump: `0xDEAD0xxx` = logic-RCE candidate, any other = memory
bug. Sinks hooked: `LoadLibrary{,Ex}W`, `CreateProcessW`, `WinExec`, `ShellExecuteExW`.

### Mechanism — IAT patching, no dependency

For each target module, walk its import descriptors, match the sink by **symbolic name** via the
Import Name Table (robust against the apiset forwarding that makes address comparison unreliable on
modern Windows), and swap the IAT slot to a trampoline. The trampoline judges, then tail-calls the
real export resolved via `GetProcAddress`.

**Scope / limits.** IAT hooking catches cross-module imports only. The historic sink —
`LoadLibrary{,Ex}W`, imported from kernel32 — is covered. A sink a module calls *intra-module* or
resolves via `GetProcAddress` is not seen; that needs an inline hook (Detours/MinHook), noted as the
upgrade path. Only modules loaded at install time are patched, so the target set is force-loaded
first. Single-threaded persistent-target assumption: one harness process, one `fuzz()` loop, so the
sample pointer is a plain global.

## Validation — mandatory before any campaign

*An oracle you have not watched fire is worthless.*

- **Positive control** — a seed whose PIDL points a control-panel item at a non-System32 module
  **must** produce a `0xDEAD0xxx` finding. If it doesn't: the sink isn't being reached (revisit the
  `IExtractIconW` path) or the call is intra-module (needs an inline hook).
- **Negative control** — a clean `.lnk` **must** stay silent through shell32's legitimate system-DLL
  loads. A hit here means the allowlist is too tight (third-party shell extensions on the box) —
  widen `oracle_is_trusted_path` or gate on taint.

## Do I need more than one harness?

No new harness for the oracle — it is a shared header compiled into both existing targets. You still
run the two campaigns separately because TinyInst instruments one module per run:

- `harness.exe` → `-instrument_module shell32.dll` (+ `windows.storage.dll`, `propsys.dll`)
- `harness_darwin.exe` → `-instrument_module msi.dll`

A single shell32 campaign starves `GROUP_DARWIN` (those bugs live in msi.dll, which `harness.cpp`
never calls). A *third* harness is warranted only for a sink no current target invokes — e.g.
`trkwks.dll` link-tracking resolution, presently suppressed by `SLR_NOTRACK`.

## Precedent

Behavioral/sink oracles are standard; memory-safety just happens to have a free one. ASan/MSan/UBSan
are themselves injected oracles (shadow memory / poisoning — make the invisible faultable);
command-injection and path-traversal fuzzers hook `exec`/`open` and judge arguments; differential
fuzzers use a second implementation as the oracle; syzkaller treats kernel `WARN`/`BUG`/`KASAN` as
signal. The pattern is always the same: RE characterizes the dangerous event, you encode it as a
runtime predicate, the fuzzer scales the search.
