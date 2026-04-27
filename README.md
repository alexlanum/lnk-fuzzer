Parser-aware mutation-based fuzzer for Windows Shell Link files.
The SOTA mutation operator scheduler uses two-level Thompson Sampling to learn which format regions and corruption strategies produce new code coverage. In such a way, productive operators are favored over time.

* `deserialize.c` – converts raw .lnk bytes into a `LNKGeneratorState` structure
* `mutate.c` – structure-aware mutation operators and Thompson Sampling scheduler
* `serialize.c` – converts mutated `LNKGeneratorState` structure into raw bytes
* `model.h` – LNK format model (section structs, enums, layouts)
* `mutate.h` – mutation operator/group enums, scheduler API
* `lnk_prng.c` / `lnk_prng.h` – xoroshiro128++ PRNG, per-thread state
* `clsids.h` – 143 IShellFolder CLSIDs enumerated from Windows registry
* `lnk_prng_jackalope.cc` – adapter: subclasses Jackalope's `PRNG`, backed by our xoroshiro
* `lnk_mutator.cc` – adapter: subclasses Jackalope's `Mutator`, drives `mutate_apply`/`mutate_report`
* `lnk_fuzzer_main.cc` – entry point: subclasses Jackalope's `Fuzzer`, produces `lnk_fuzzer.exe`
* `harness.cpp` – Windows target: `CShellLink::Load` -> `CShellLink::Resolve`

## ref
- [MS-SHLLINK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink) — Shell Link Binary File Format
- [MS-PROPSTORE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-propstore) — Property Store Binary File Format
- [Geoff Chappell — RegFolder](https://www.geoffchappell.com/studies/windows/shell/shell32/classes/regfolder.htm) — DELEGATEITEMID structure
- [libfwsi](https://github.com/libyal/libfwsi) — Windows Shell Item format documentation