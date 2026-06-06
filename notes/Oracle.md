# Oracles

An **oracle** is the judge: after each input runs, it answers one question — *"was that a bug?"*
A fuzzer without an oracle just opens a million weird files and shrugs. This campaign now has three.

| Oracle | Judge | Question | Source |
|---|---|---|---|
| Crash | CPU + OS, caught by TinyInst | did the process fault? | free (hardware) |
| Hang | timer (`-t`) | did it run too long? | Jackalope flag |
| **Sink (behavioral)** | hooks in `oracle.h` | did shell32/msi execute attacker-controlled code? | **ours** |

## Why the sink oracle was needed

Memory corruption is *self-harm* — the CPU faults, so the crash oracle catches it for free. The bug
class this fuzzer's operators target — CVE-2010-2568 (Stuxnet), CVE-2015-0096, CVE-2017-8464 — is
*successful misbehavior*: shell32 is steered into loading attacker code and the load **succeeds**. A
successful `LoadLibrary` does not fault, so the crash oracle is structurally blind to it. We had the
whole input side built to produce these (GROUP_PIDL, GROUP_SPECIALFOLDER, GROUP_KNOWNFOLDER, the CPL
dispatch in `vulnscool.md`) and no judge that could recognize a hit.

## How it works (`oracle.h`)

1. **Reach** — `harness.cpp` drives `IExtractIconW::Extract` on the resolved PIDL. That is the call
   that historically ended in `CPL_LoadCPLModule -> LoadLibraryW`; `Resolve()` alone (with
   `SLR_NO_UI`) never gets there.
2. **Recognize** — IAT hooks on the code-exec sinks (`LoadLibrary{,Ex}W`, `CreateProcessW`,
   `WinExec`, `ShellExecuteExW`) judge each call: a module under System32 / a bare name is benign; a
   path anywhere else (temp, UNC, `\\.\STORAGE` — the Stuxnet payload) is a finding. If the path is
   also present in the sample bytes, it is tagged *tainted* (provably mutator-driven).
3. **Report** — the judge converts the logic hit into a deliberate access violation at `0xDEAD0NNN`
   (`NN` = sink id, `0x100` bit = tainted), so TinyInst's existing crash path saves the input. No new
   reporting infrastructure — the logic bug rides the free crash channel. Findings faulting at
   `0xDEAD0xxx` are logic-RCE candidates; ordinary shell32-address AVs are memory bugs.

## Precedent — yes, real fuzzers do exactly this

Sink/behavioral oracles are mainstream; memory-safety just happens to be the one with a free oracle.
- **ASan/MSan/UBSan** are themselves injected oracles (shadow memory / poisoning) — the canonical
  "make the invisible faultable" pattern; we apply the same idea to a closed binary via hooks.
- **Command-injection / path-traversal fuzzers** hook `system`/`exec`/`open` and flag attacker-
  controlled arguments — structurally identical to this.
- **Differential fuzzers** (TLS stacks, JS engines, `jsfunfuzz`, compiler fuzzers) use a second
  implementation as the oracle for logic divergence.
- **syzkaller** treats kernel `WARN`/`BUG`/`KASAN` reports as oracle signals beyond plain crashes.
The pattern: RE characterizes the dangerous event, you encode it as a runtime predicate, the fuzzer
scales the search. "Found via RE" and "fuzzing target" are the two halves of the same pipeline.

## Do I need more than one harness?

No new harness for the oracle — it is a shared header (`oracle.h`) compiled into both existing
targets. You still run the **two campaigns you already have**, separately, because TinyInst
instruments one module per run:
- `harness.exe`      — `-instrument_module shell32.dll` (+ `windows.storage.dll`, `propsys.dll`)
- `harness_darwin.exe` — `-instrument_module msi.dll`

A single shell32 campaign starves GROUP_DARWIN (those bugs live in msi.dll, which `harness.cpp`
never calls). A third harness is only warranted for a sink no current target invokes — e.g.
`trkwks.dll` link-tracking resolution, currently suppressed by `SLR_NOTRACK`.

## VALIDATE BEFORE TRUSTING

An oracle you have not watched fire is worthless. Before any campaign:
- **Positive control** — a seed whose PIDL points a control-panel item at a non-System32 module.
  It MUST produce a `0xDEAD0xxx` finding. If it does not, the sink is not being reached (revisit the
  `IExtractIconW` path) or the import is intra-module (needs an inline hook, not IAT — see `oracle.h`
  scope notes).
- **Negative control** — a clean `.lnk`. It MUST stay silent through shell32's legitimate
  system-DLL loads. A hit here means the allowlist is too tight (third-party shell extensions on the
  box) — extend `oracle_is_trusted_path` or gate on taint.
