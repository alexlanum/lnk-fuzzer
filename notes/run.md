## Build
```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
python tools\generate_seeds.py
```

## Run
```
build\Release\lnk_fuzzer.exe `
  -in corpus\seeds -out findings `
  -nthreads 24 `
  -t 5000 -t1 10000 `
  -delivery shmem -max_sample_size 1048576 `
  -instrument_module shell32.dll `
  -target_module harness.exe -target_method fuzz -nargs 1 `
  -iterations 10000 -persist -loop `
  -cmp_coverage -generate_unwind `
  --% -- build\Release\harness.exe -m @@
```

- `-in corpus\seeds` — folder of starting .lnk files to mutate from
- `-out findings` — where crashes, new samples, and state get written
- `-nthreads 24` — run 24 fuzzing workers in parallel
- `-t 5000` — kill a sample if it runs longer than 5 seconds
- `-t1 10000` — give the harness 10 seconds to start up the first time
- `-delivery shmem` — pass samples via shared memory (fast, no disk I/O)
- `-max_sample_size 1048576` — cap samples at 1 MiB; **must match what harness.exe expects** (this was the fix)
- `-instrument_module shell32.dll` — collect coverage from shell32.dll, the actual parser
- `-target_module harness.exe` — the binary containing the function to call repeatedly
- `-target_method fuzz` — name of the function inside harness.exe to enter on each iteration
- `-nargs 1` — that `fuzz` function takes 1 argument (the shm name)
- `-iterations 10000` — restart the harness process every 10k samples to clear memory bloat
- `-persist` — don't relaunch harness.exe per sample; just call `fuzz` again
- `-loop` — make the function "return" jump back to its start so it loops forever
- `-cmp_coverage` — also track byte-comparison instructions, helps blast through magic numbers (LNK has lots: 0x4C header, CLSID, signatures)
- `-generate_unwind` — handle Windows exception unwinding so shell32's own SEH doesn't look like crashes
- `--` — divider: everything after this is the harness command line, not a fuzzer flag
- `build\Release\harness.exe -m @@` — the actual program the fuzzer launches; `@@` gets swapped for the shm name at runtime

## Parallelism
LNKFuzzer just subclasses Jackalope's Fuzzer (lnk_fuzzer_main.cc:36), so it inherits the full -start_server / -server client-server distribution model — the server collects coverage + crashes + samples from all workers and broadcasts new-coverage samples back. Nothing LNK-specific was disabled.

PC #1 (server, doesn't fuzz, just coordinates):
```
build\Release\lnk_fuzzer.exe -start_server -out server_findings
Default port 8000 (server.h:50). Open it on the firewall.
```

PC #1 (worker, same box as server):
```
build\Release\lnk_fuzzer.exe -server 127.0.0.1:8000 ^
  -in corpus\seeds -out findings_pc1 -nthreads 20 ^
  -t 5000 -t1 10000 -delivery shmem ^
  -instrument_module shell32.dll ^
  -target_module harness.exe -target_method fuzz -nargs 1 ^
  -iterations 10000 -persist -loop -cmp_coverage -generate_unwind ^
  -- build\Release\harness.exe -m @@
```

PC #2 (worker):
Same command, but -server <PC1_LAN_IP>:8000 and -out findings_pc2. Each PC needs its own build + seed copy

One detail worth knowing: when -server is used, Jackalope defaults -deterministic_mutations to false (main.cpp:33). If you want one node to grind deterministic mutations while the other does random, add -deterministic_only on PC #1's worker and leave PC #2's worker as default.