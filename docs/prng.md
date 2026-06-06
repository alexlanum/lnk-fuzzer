# PRNG — xoroshiro128++ seeded by splitmix64

The scheduler burns ~1000 uniform draws per decision (Beta → Gamma → Box-Muller, see
[scheduler.md](scheduler.md)). The PRNG is therefore on the hot path *and* its statistical quality
directly shapes the Beta posteriors. `rand()` is unfit on every axis that matters here; this
project owns its generator.

Implementation: [`lnk_prng.c`](../lnk_prng.c) / [`lnk_prng.h`](../lnk_prng.h). Jackalope adapter:
[`lnk_prng_jackalope.cc`](../lnk_prng_jackalope.cc).

## Requirements

| property | why it matters here |
|---|---|
| **long period** | sustained campaigns must not loop and silently re-explore covered code |
| **full-width output** | every bit uniform — precise Beta samples, true `uint16/uint32` mutations that reach high-range parser branches, 53-bit doubles |
| **statistical quality** | bias propagates through the distribution transforms into skewed scheduling; must pass BigCrush |
| **speed** | ~1000 draws/decision; a library-call PRNG becomes the bottleneck |
| **seedability** | pure function of seed — reproducible campaigns, replayable crashes |

Why `rand()` fails all of them: MSVCRT's LCG yields 15 bits (`(seed*214013+2531011)>>16 & 0x7FFF`),
so `uint16` mutations never exceed 32767 (high-range branches unreachable); its period is ~2³¹
(minutes at fuzzing rates); and it is a single global generator — thread-unsafe, uncheckpointable.

## Generator — xoroshiro128++ 1.0

128-bit state (two `uint64_t`), period `2¹²⁸ − 1`, full 64-bit output, passes BigCrush. Chosen over
xoshiro256++ deliberately: 256-bit state buys headroom this workload never exhausts.

```c
result = rotl(s0 + s1, 17) + s0;          // ++ scrambler — full-width, well-distributed
s1 ^= s0;
state[0] = rotl(s0,49) ^ s1 ^ (s1 << 21); // xoroshiro state advance
state[1] = rotl(s1,28);
```

Output draws built on the 64-bit core:
- `lnk_rand` — upper 32 bits (the high bits have the best equidistribution).
- `lnk_rand_below(n)` — `x % n`; modulo bias ≤ `n / 2⁶⁴`, undetectable for the small `n` used.
- `lnk_rand_double` — `(x >> 11) · 2⁻⁵³`, full-mantissa double in `[0,1)`; may return exactly 0,
  so the Gamma sampler guards the `log(u1)` call.

## Seeding — splitmix64

A user/time seed is expanded into the 128-bit state by two splitmix64 pulls. splitmix64 is a
bijection with strong avalanche: a one-bit change in the seed flips ~half the output bits, so
adjacent seeds (two workers started a second apart) produce decorrelated streams — no shared
trajectory for the first millions of draws.

```c
rng->smstate = seed;
do {
    xstate[0] = splitmix64_next(rng);
    xstate[1] = splitmix64_next(rng);
} while (xstate[0] == 0 && xstate[1] == 0);   // guard the all-zero fixed point
```

xoroshiro emits zero forever from the all-zero state. splitmix64 produces that pair with
probability `2⁻¹²⁸` — effectively never — but the check costs one comparison at startup and the
failure mode (a silently deterministic, useless fuzzer) is the worst possible, so it is guarded
unconditionally.

## Threading & reproducibility

One `LNKRand` per worker thread, constructed by `LNKFuzzer::CreatePRNG`, seeded
`base ^ (thread_id · 0x9e3779b9)` so per-thread streams are well-separated. No locking on the RNG —
state is thread-local. Because the generator is a pure function of its seed, a campaign run with
`-prng_seed` is fully reproducible: the same seed replays the same mutation decisions, which is what
makes a saved crash bisectable months later.

The Jackalope base class asks for randomness through `PRNG::Rand()` (32-bit). `LNKPRNG` overrides it
and additionally exposes `state()` so the mutator can hand the raw `LNKRand*` to `mutate_apply` for
the 64-bit / 53-bit draws the 32-bit interface can't express.
