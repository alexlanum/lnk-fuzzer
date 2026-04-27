// Entry point. Produces lnk_fuzzer.exe.
//
// We subclass Jackalope's Fuzzer interface purely to access the CreatePRNG
// virtual method. We override it to use our own PRNG (each thread gets a
// LNKPRNG, backed by xoroshiro). Same reasoning for the CreateMutator lambda:
// it returns LNKMutator instances so our operators and scheduler can be the
// ones to drive each mutation round.
//
// Everything else: sample queueing, coverage tracking, crash dedup, persistence,
// the worker-thread loop, is normal Jackalope. We provide the format-aware pieces
// (PRNG, mutator, scheduler) and inherit the format-agnostic engine.