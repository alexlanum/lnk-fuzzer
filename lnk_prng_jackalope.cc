// lnk_prng_jackalope.cc
//
// Adapter: makes the xoroshiro128++ generator usable as a Jackalope PRNG.
//
// Jackalope's engine asks for random numbers through PRNG::Rand().
// We inherit from PRNG, override Rand() to call into the lnk_prng.c
// implementation, and then expose the underlying LNKRand* so LNKMutator
// can give it to mutate_apply for full 64-bit / 53-bit draws, which
// Jackalope's 32-bit interface can't do.
//
// One LNKPRNG instance per worker thread (Jackalope's CreatePRNG hook
// constructs them), so the LNKRand state is per-thread with no locking.

#include "lnk_prng_jackalope.h"

LNKPRNG::LNKPRNG(uint32_t seed) {
    // lnk_rand_seed takes uint64_t. Widening from uint32_t is safe;
    // splitmix64 inside lnk_rand_seed will spread the 32 bits across
    // the full 128-bit xoroshiro state.
    lnk_rand_seed(&r_, static_cast<uint64_t>(seed));
}

uint32_t LNKPRNG::Rand() {
    return lnk_rand(&r_);
}

LNKRand* LNKPRNG::state() {
    return &r_;
}
