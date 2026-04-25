# Fuzzing



## AFL

**Coverage collection**: Instruments the target at compile time (or via DynamoRIO in WinAFL) to write a 64KB shared memory space. Each edge (block->block transition) hashes to a byte in the shared memory space. Hitting an edge increments that byte.

**Fork-based execution harness**: The forkserver is a parent process that uses the `fork()` syscall to spawn a child process on each loop iteration. The child process runs the target function and exits. The parent reads the shared memory space after each child exits, for coverage. This is fast on Linux (copy-on-write), but cannot be done on Windows, which is why WinAFL was invented. WinAFL replaces the forkserver with persistent mode.

**Mutator + scheduler**: Byte mutations (bit flip, arithmetic, havoc, etc.). Seeds that produce new edges in the shared memory space get saved to the queue. The queue is walked in a roughly round-robin way with power-based weights.

It assumes Linux, source code, compile-time instrumentation, fork syscall, and a single-node single-thread loop. Everything else (WinAFL, AFL++, etc.), is based on this core design.



## Jackalope

Ivan Fratric’s 2021 rewrite of the same core idea: mutation-based coverage-guided fuzzing. It shares zero lines of code with AFL.

Jackalope describes itself as a customizable, distributed fuzzer that "can be used stand-alone, but is more powerful when used as a library, where users can plug in custom components that would replace the default behavior. Mutation scheduling (which operator, in what order), is supported cleanly via custom and meta-mutators.

Jackalope is a C++ library of base classes that you add your own subclasses to + it has a `main()` that writes them together into a `Fuzzer` object and calls `Run()`.

There is no `afl-fuzz` binary to run, rather, you include a `fuzzer.h`, construct a `Fuzzer` class with your chosen implementations, call `Run(argc, argv)`, and then you get a fuzzer executable. Command line flags such as `-iterations` are parsed by `Fuzzer::Run`.

Base classes:

```c++
// Fuzzer
// 	Orchestrator. Holds everything below and runs the main loop.
//  Rarely subclassed.
class Fuzzer{...}
  class Fuzzer::ThreadContext{...};

// Sample
//  Just a wrapper for {uint8_t* bytes; size_t size}, but with a comparison
//  operator and a small set of helper methods. Samples are what flow through
//  the whole fuzzing pipeline.
class Sample{...};

// Mutator
//  Produces a mutated sample from an input sample.
//  Implementations include ByteFlipMutator, BlockInsertMutator, SpliceMutator.
//  This is where the LNK custom mutator plugs in.
class Mutator{...};

class MutatorSampleContext{...};

// PRNG
//  Thread-local random number generator. Instead of using the one it ships,
//  you will wire your xoroshiro128++ in.
class PRNG{...};

// Instrumentation
// 	Collects coverage from the target. Implementations: TinyInst (DBI),
//  LiteCov (compile-time instr), and a stub for supplying coverage another way.
class Instrumentation{...};

// SampleDelivery
//  Delivers bytes from fuzzer to target, File-on-disk shared memory, or TCP
//	socket. You will use shared memory.
class SampleDelivery{...};

class Minimizer{...};

class RangeTracker{...};

class CoverageClient{...};
```



### Jackalope iteration

1. Worker thread pulls a `Sample` from the priority queue. Selection is weighted by priority, where previously successful inputs are prioritized.
2. The `Sample` is handed to `Mutator::Mutate()`. For the LNK fuzzer, `Mutate()` is `deserialize_lnk` -> `mutate_apply` -> `serialize_lnk`.
3. The mutated sample goes to `SampleDelivery`. Shared memory delivery writes to a buffer backed by `CreateFileMapping`, then signals the target via named event. Your harness reads from the same mapping. This does not require any disk I/O or file handles. It is 10-50x faster than file-based delivery for small inputs, which is most parser fuzzing.
4. The target executes the mutated `Sample`. This is where instrumentation matters. `TinyInst` has already rewritten the target’s basic blocks before the first run; each block ends with a hook that writes the block ID into the coverage buffer. Most importantly, `TinyInst` rewrites per module you ask for, such as `shell32.dll`, with zero hash collisions.
5. Target returns, or crashes, or times out. Jackalope collects the edge set from this run.
6. Coverage diff against the union of all previously seen edges. New edges -> the sample goes into the priority queue, flagged “interesting”. Timeout -> logged. Crashed -> deduplicated by crash site hash, saved to `crashes/`.
7. `Mutator::NotifyResult(has_new_coverage)` is called on your mutator instance. This is the feedback hook. This is where the `mutate_report(last_op, new_coverage ? 1 : 0)` call goes. The Thompson Sampling scheduler receives ground-truth per iteration signal, not SHM bitmap-diff stuff.
8. Loop



### Jackalope TinyInst

TinyInst is a dynamic binary instrumentation (DBI) framework library for Windows, macOS, and Linux, written by Ivan Fratric (owner of Jackalope and WinAFL). https://github.com/googleprojectzero/TinyInst

Dynamic binary instrumentation means:

- take a compiled binary
- rewrite its machine code to add your own instructions at runtime
- typically observe or alter behavior
- target has no idea it's being instrumented. no recompilation. no source code. no debug symbols required.

You need a way to measure coverage in a binary you cannot recompile. That's DBI's whole reason to exist. The alternative to DBI for binaries that you cannot recompile is hardware tracing: Intel PT, ARM CoreSight. These observe the CPU's branch decisions directly, at essentially zero software overhead. There is zero overhead (~1-5%) because they write branch decisions directly into a CPU-side ring buffer via dedicated silicon.

There are a few DBI frameworks:

- **PIN (Intel 2005)**: heavyweight, feature-rich, slow startup, excellent for one-off analysis. Not designed for fuzzing.

- **DynamoRIO (2001, now community)**: full process just-in-time. It recompiles everything the target executes, including ntdll, kernel32, combase. Massive overhead (30-80%+ for typical Windows apps), massive surface area for bugs, but you can instrument anything. This is what WinAFL uses by default.

- **Frida (2013)**: Scriptable, driven by JavaScript, great for hooking. API calls. Overhead is fine for RE, bad for fuzzing.

- **TinyInst (2019)**: Minimal by design. Only instruments modules you explicitly ask for, such as `shell32.dll`. Much smaller code cache. Much faster. 

  TinyInst's explicit design philosophy, stated in its README: *"just-enough DBI, not an all-purpose DBI framework."* It exists because Fratric, after years of fighting DynamoRIO's edgecases in WinAFL, decided the fuzzing use case is narrow enough to build a specialized tool that does 5% of what DynamoRIO does but does that 5% at 3x the speed with 1/10 of the bugs.



## Hardware assisted fuzzing

The PT trace is a stream of TNT (taken/not-taken) and TIP (target IP) packets. To turn that into "which edges executed," the decoder has to:

1. walk the original binary's disassembly in lockstep with the packet stream
2. at each conditional branch, consume a taken/not-taken bit to know which way
3. at each indirect branch, consume target IP packet to get the target
4. keep a running map of `last_block`, `current_block` edges



### Overhead

Intel PT's hardware overhead is near-zero:

- **kAFL (Schumilo et al., USENIX Security 2017)** measured the overhead of their KVM-PT capture layer (the kernel-side piece that configures PT, catches traces, and exposes them to userspace) at 1-4% empirically. The paper explicitly notes this overhead is small enough that it doesn't meaningfully influence fuzzing throughput.

- **Jane Street's magic-trace writeup** (production use outside fuzzing) reports PT hardware overhead of 2-20% depending on the program, typically under 5% across their benchmarked services.

The time it takes and how much CPU it takes (latency) to turn a raw PT trace into usable coverage data (decode) is not zero. PT produces a compressed trace that then has to be decoded into edge coverage. That decode happens in software, post-execution, and it is not free.



While Intel PT minimizes runtime overhead:

```
Execution:         Fast (hardware-assisted)
Trace generation:  Cheap
Decoding:          Expensive (bottleneck)
```

The software decoding of traces into coverage introduces significant overhead, which reduces fuzzer execs/sec rather than just increasing decode latency.



This problem is now largely solved. kAFL flagged decode as the real cost in their paper: *"In contrast to KVM-PT, the decoder has significant influence on the overall performance of the fuzzing process since the decoding process is – other than Intel PT and hence KVM-PT – not hardware-accelerated. Therefore, this process is costly and has to be as efficient as possible."*



There are a few decoder implementations:

- **libipt**: Intel's official reference decoder. Full edge coverage, slow. Trail of Bits measured ~85% of CPU time spent inside its instruction decode loop. Canonical but not optimized for fuzzing. https://github.com/intel/libipt
- **WinAFL-libipt**: Ivan Fratric's fork of libipt with an added caching layer for use inside WinAFL's PT mode. Still full edge coverage, faster than raw libipt, slower than libxdc. This is what `afl-fuzz.exe -P` uses under the hood.
- **libxdc**: Nyx team's decoder, purposed for fuzzing. Full edge coverage preserved. 15-30x faster than libipt on fuzzing-representative work per their own benchmark. Used by kAFL and Nyx. https://github.com/nyx-fuzz/libxdc
- **Honeybee (Trail of Bits' decoder, 2021)**: Uses an ahead-of-time cache ("hive") built once per target binary, then reused across all traces. Full edge coverage. On small fuzzing-shaped traces, renders ~70x faster than libipt; roughly comparable to libxdc (libxdc slightly faster on hot caches, Honeybee slightly faster on cold caches, per nyx-fuzz's re-run of the experiments). https://github.com/trailofbits/Honeybee
- **PTrix decoder (NDSS 2019)**: Skips disassembly entirely by hashing runs of taken/not-taken decisions together. Much faster than libipt but does not recover true edges. Coverage signal is noisy, with collisions between very different paths. Speed comes at the cost of precision.
- **Honggfuzz PT decoder**: Extracts only TIP (target instruction pointer) packets which alert things like "execution just moved to 0xdead”, and ignores conditional branches entirely. Like PTrix, trades precision for speed. libxdc's authors note honggfuzz additionally appears to ignore TIP compression, causing significant bitmap collisions.
- **Killerbeez PT decoder**: the most extreme point on the speed/precision tradeoff: hashes the raw trace data into two streams without any structural decoding. Fast but produces the noisiest coverage of any option.



Conclusion: libipt and WinAFL-libipt are full-fidelity but slow. libxdc and Honeybee are full-fidelity and fast. These are the ones modern PT fuzzers use. If I wanna go the PT route, libxdc or Honeybee would be the decoder, not libipt.

The bottleneck of my LNK fuzzer is not execs/sec, it's signal quality into the scheduler.

Suppose a generous upper bound for PT: 2x per-worker execs/sec over TinyInst on `shell32.dll`. Based on Honeybee's 28% overhead vs honggfuzz-software's 41%, and the fact that `shell32.dll` is small enough that decode stays cheap.

In practice: within 20-30% of TinyInst once you factor in how the workers actually scale, with Jackalope+TinyInst possibly ahead at 3+ workers per machine, the 2x collapses:

- PT's operational cost is per-machine each PC needs its own driver, test-signing mode enabled, decoder pipeline set up.
- PT implies WinAFL. Jackalope has no first-class PT support on Windows. Choosing PT means inheriting WinAFL's bad ABI and corpus coordination (unacceptable 2013 filesystem-sync design).
- WinAFL's `-M/-S` corpus sync scales sublinearly past ~3 workers per host. Jackalope has real in-process multi-threaded corpus sharing within a host, with corpus merging between hosts via tooling. The 2x per-worker PT advantage gets killed by WinAFL's sublinear parallel scaling.

The decisive argument isn't throughput, rather, it's scheduler feedback. Jackalope's `Mutator::NotifyResult(bool has_new_coverage)` gives per-iteration coverage feedback natively, as a designed-in API. WinAFL has no equivalent. Getting the same signal there means reading its SHM bitmap and diffing around each `common_fuzz_stuff` call, which is a hack against a fuzzer that wasn't designed for it.

For my Thompson Sampling scheduler, noisy priors are strictly worse than no scheduler at all. They systematically misallocate attention toward operators that got lucky with a noise spike. A correct scheduler at 10k exec/sec finds more bugs than a broken scheduler at 20k exec/sec. This is the architectural reason to prefer Jackalope+TinyInst independent of any throughput delta.

**Decision:** Jackalope + TinyInst. Run independent Jackalope instances on each PC, `-nthreads N` per host to use the cores, merge corpora periodically between hosts. Gives up a possible 1.5-2x per-worker throughput vs hypothetical WinAFL+PT; in exchange, gets a correctly-functioning scheduler, real within-host parallelism, stock Windows (no kernel driver, no test-signing, no MSR fragility), and a readable codebase when something breaks at 2am.

## Jackalope test
```
C:\fuzzing\
├── Jackalope\         ← the fuzzer engine itself (clone from GitHub)
│   ├── TinyInst\      ← Jackalope's required submodule (clone from GitHub)
│   └── build\         ← where fuzzer.exe lands after you build it
│
├── pe-parse\          ← the target library (clone from GitHub)
│   └── build\         ← where pe-parse.lib lands after you build it (harness links against the .lib)
│
└── pe-fuzz\           ← YOUR project: the harness, corpus, output
    ├── harness.cpp    ← ~40 lines you write, calls pe-parse on input bytes
    ├── CMakeLists.txt ← ~20 lines, links harness against pe-parse
    ├── build\         ← where harness.exe lands
    ├── corpus\        ← input seeds (a few small .exe files)
    └── output\        ← Jackalope writes crashes/ and queue/ here at runtime
```



```
.\Release\fuzzer.exe -in in -out out -t 1000 -delivery shmem -instrument_module test.exe -target_module test.exe -target_method fuzz -nargs 1 -iterations 10000 -persist -loop -- .\Release\test.exe -m "@@"
```

- `fuzzer.exe` process creates a shared memory mapping:

  ```c++
  if(!strcmp(option, "shmem")){ // -delivery shmem
      // build a name. both processes will use this string to find the same mapping.
      string shm_name = string("shm_fuzz_") + std::to_string(GetCurrentProcessId()) + "_" + std::to_string(tc->thread_id);
      
      // walk cmd line args, find any @@ token, replace it with the actual shared-memory name.
      // @@ in `test.exe -m @@` becomes `test.exe -m shm_fuzz_12345_1` at runtime.
      ReplaceTargetCmdArg(tc, "@@", shm_name);
  
      // construct the delivery object. internally calls CreateFileMapping.
      SHMSampleDelivery* sampleDelivery = new SHMSampleDelivery((char*)shm_name.c_str(), Sample::max_size + 4);
      sampleDelivery->Init(argc, argv);
      return sampleDelivery;
  }
  ```

  

- `test.exe` process opens that mapping via `setup_shmem(argv[2])`:

  ```c++
  HANDLE map_file = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, name);
  shm_data = (unsigned char*)MapViewOfFile(map_file, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
  ```

  

  Both processes now see the same memory region.

  

- `fuzzer.exe` runs a loop (`Fuzzer::FuzzJob`):

  ```c++
  void Fuzzer::FuzzJob(ThreadContext* tc, FuzzerJob* job) {
      // 1. Pull a sample from sample_queue (priority queue of seeds).
      // The job was already populated by SynchronizeAndGetJob() which did
      // sample_queue.top() / pop() under queue_mutex.
      SampleQueueEntry* entry = job->entry;
  
      // 2. Per-seed setup. Lets the Mutator do work that's expensive to repeat
      // per iteration (ex. for LNKMutator: deserialize_lnk into a cached state).
      tc->mutator->InitRound(entry->sample, entry->context);
  
      // Optional: hand the mutator a list of "interesting" byte ranges to focus
      // mutations on. Off by default; only on when -track_ranges is set.
      if (track_ranges) tc->mutator->SetRanges(&entry->ranges);
  
      printf("Fuzzing sample %05lld\n", entry->sample_index);
  
      // Default: keep the sample in the queue after this round. Set to true
      // below if the sample turns out to be pathological (too many hangs/crashes).
      job->discard_sample = false;
  
      // If -keep_samples_in_memory=false, the sample bytes were freed to disk;
      // load them back before mutating.
      entry->sample->EnsureLoaded();
  
      // 3. The actual fuzzing loop. Runs until Mutate() returns false.
      while (1) {
          // Fresh copy of the SEED for this iteration. Critical: each iteration
          // starts from the original sample bytes, not the previous mutation.
          // Mutations don't accumulate across iterations.
          Sample mutated_sample = *entry->sample;
  
          // Mutate the bytes in place. Returning false signals "I'm done with
          // this seed, move to the next one" — that's the round budget exit.
          if (!tc->mutator->Mutate(&mutated_sample, tc->prng, tc->all_samples_local)) break;
  
          // Mutator may produce oversized samples; skip them rather than crash
          // on the size cap downstream.
          if (mutated_sample.size > Sample::max_size) {
              continue;
          }
  
          int has_new_coverage;
  
          // RunSample wraps the full deliver-run-measure pipeline:
          //   - sampleDelivery->DeliverSample(mutated)  // bytes into shmem
          //   - instrumentation->Run()                  // resume test.exe; TinyInst loops fuzz()
          //   - instrumentation->GetCoverage()          // read edge set
          //   - if new edges -> SaveSample() to out/queue/
          //   - returns OK / CRASH / HANG / OTHER_ERROR
          RunResult result = RunSample(tc, &mutated_sample, &has_new_coverage,
                                       true, true, init_timeout, timeout, entry->sample);
  
          // Default policy: reset priority on new coverage, decrement otherwise.
          // Productive seeds bubble to the top of the queue.
          AdjustSamplePriority(tc, entry, has_new_coverage);
  
          // Scheduler feedback. The hook your LNKMutator uses to call
          // mutate_report(last_op, has_new_coverage) for Thompson Sampling.
          tc->mutator->NotifyResult(result, has_new_coverage);
  
          // Per-seed bookkeeping.
          entry->num_runs++;
          if (has_new_coverage) {
              entry->num_newcoverage++;
              // Hot-offset tracking: record which byte the productive mutation
              // touched, so future Mutate() calls can bias toward that region.
              if (TrackHotOffsets()) {
                  size_t diff_offset = entry->sample->FindFirstDiff(mutated_sample);
                  tc->mutator->AddHotOffset(entry->context, diff_offset);
              }
          }
  
          if (result == HANG) entry->num_hangs++;
          if (result == CRASH) entry->num_crashes++;
  
          // Pathological-sample detection: if a seed reliably produces hangs
          // or crashes, it wastes cycles. Discard it from the queue.
          if ((entry->num_hangs > 10) &&
              (entry->num_hangs > (entry->num_runs * acceptable_hang_ratio))) {
              WARN("Sample %lld produces too many hangs. Discarding\n", entry->sample_index);
              job->discard_sample = true;
              break;
          }
          if ((entry->num_crashes > 100) &&
              (entry->num_crashes > (entry->num_runs * acceptable_crash_ratio))) {
              WARN("Sample %lld produces too many crashes. Discarding\n", entry->sample_index);
              job->discard_sample = true;
              break;
          }
      }
      // Loop ends when Mutate() returns false (round budget exhausted)
      // or the sample was flagged as pathological.
  
      // If -keep_samples_in_memory=false, drop the bytes back to disk-only
      // until next time this seed is selected.
      if (!keep_samples_in_memory) {
          entry->sample->FreeMemory();
      }
  }
  ```

  Observe: `mutated_sample = *entry->sample` – Mutations are not cumulative. Every iteration starts fresh from the seed. If you want compound mutations (ex.. apply two operators), your mutator has to do both inside one `Mutate()` call.



- `test.exe` side per iteration (the `fuzz()` function):

  ```c++
    uint32_t sample_size = *(uint32_t*)shm_data;     // first 4 bytes = length prefix
    memcpy(sample_bytes, shm_data + 4, sample_size); // rest = sample data
    ... do work on sample_bytes ...
    return; // TinyInst overwrote this RET to jump back to top of fuzz() *PERSISTENT MODE*
  ```



- TinyInst attaches to `test.exe` as a debugger, marks `test.exe` code pages `PAGE_NOACCESS`, catches the AVs as code executes, copies basic blocks into a code cache, rewrites each block with a coverage stub at the end of it, redirects execution there. After the first execution of any block, subsequent runs hit the cache directly with one extra store per block.



- Crash detection: if `fuzz()` AVs (ex `test.cpp`'s `crash[0] = 1` when sample starts with "test"), TinyInst's debugger catches the exception and reports `CRASH` to `fuzzer.exe`. Fuzzer dedups by crash-site hash, saves to `out/crashes/`.



### Jackalope pe-parse harness

```
C:\Users\Me\source\repos\fuzzing\Jackalope\build\Release\fuzzer.exe -in corpus -out output -t 5000 -delivery shmem -instrument_module harness.exe -target_module harness.exe -target_method fuzz -nargs 1 -iterations 5000 -persist -loop -- .\build\Release\harness.exe -m "@@"
```

- `-instrument_module harness.exe` — instrument your harness binary (pe-parse is statically linked inside it)
- `-target_module harness.exe` — target function lives in your harness
- `-target_method fuzz` — same function name (your harness defined `fuzz()`)
- `-iterations 5000` — PE parsing may accumulate heap fragmentation, so restart more often than `test.exe`'s 10000
- `-t 5000` — 5 second timeout per iteration; some pathological PE inputs can make pe-parse loop briefly before returning

