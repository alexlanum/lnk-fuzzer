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