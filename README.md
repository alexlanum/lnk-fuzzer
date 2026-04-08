Structure-aware mutation-based fuzzer for Windows Shell Link (.lnk) files, built as an AFL++ custom mutator.

This is a mutation engine that understands the internal structure of .lnk files and applies targeted corruptions to specific fields based on reverse engineering of the shell32 parsing code. It mutates fields at every layer of the format.

The mutation operator scheduler uses two-level Thompson Sampling to learn which format regions and corruption strategies produce new code coverage, and favors productive operators over time.

- `mutator.c` – AFL++ custom mutator interface + Thompson Sampling custom scheduler
- `deserialize.c` – converts raw .lnk bytes into a `LNKGeneratorState` structure
- `mutate.c` – structure-aware mutation operators
- `serialize.c` – converts mutated `LNKGeneratorState` structure into raw bytes
- `model.h` – LNK format model (section structs, enums, layouts)
- `mutate.h` – mutation operator/group enums, scheduler API
- `clsids.h` – 143 IShellFolder CLSIDs enumerated from Windows registry
- `harness.cpp` – Windows target: `CShellLink::Load` -> `CShellLink::Resolve`

## ref
- [MS-SHLLINK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink) — Shell Link Binary File Format
- [MS-PROPSTORE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-propstore) — Property Store Binary File Format
- [Geoff Chappell — RegFolder](https://www.geoffchappell.com/studies/windows/shell/shell32/classes/regfolder.htm) — DELEGATEITEMID structure
- [libfwsi](https://github.com/libyal/libfwsi) — Windows Shell Item format documentation