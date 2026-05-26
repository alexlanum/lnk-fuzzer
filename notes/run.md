Build
```
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
python tools\generate_seeds.py
```

Run
```
build\Release\lnk_fuzzer.exe ^
  -in corpus\seeds -out findings ^
  -nthreads 24 ^
  -t 5000 -t1 10000 ^
  -delivery shmem ^
  -instrument_module shell32.dll ^
  -target_module harness.exe -target_method fuzz -nargs 1 ^
  -iterations 10000 -persist -loop ^
  -cmp_coverage -generate_unwind ^
  -- build\Release\harness.exe -m @@
```

Parallelism
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