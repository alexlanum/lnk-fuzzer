// lnk_fuzzer_main.cc
//
// Entry point. Produces lnk_fuzzer.exe.
//
// We subclass Jackalope's Fuzzer to override CreatePRNG so every
// worker thread gets an LNKPRNG (backed by our xoroshiro) instead
// of Jackalope's stock generator. We also override CreateMutator
// (a pure-virtual on Fuzzer) to return LNKMutator instances so our
// operators and scheduler can be the ones to drive each mutation round.
//
// Everything else: sample queueing, coverage tracking, crash dedup,
// persistence, the worker-thread loop, is normal Jackalope.
// We provide the format-aware pieces (PRNG, mutator, scheduler) and
// inherit the format-agnostic engine.

// Bare-name includes match Jackalope's own internal pattern.
// Resolution requires -IJackalope on the compile line (see .clangd).
#include "fuzzer.h"
#include "mutator.h"
#include "prng.h"
#include "common.h"  // GetIntOption / GetBinaryOption / etc

#include "lnk_prng_jackalope.h"

extern "C" {
    #include "mutate.h"  // mutate_scheduler_init
}

#include <cstdint>
#include <ctime>

// Defined in lnk_mutator.cc. Lets that translation unit own the
// LNKMutator class definition without dragging it into this file.
extern Mutator* CreateLNKMutator();

class LNKFuzzer : public Fuzzer {
public:
    // Required override (CreateMutator is pure-virtual on Fuzzer).
    Mutator* CreateMutator(int /*argc*/, char** /*argv*/, ThreadContext* /*tc*/) override {
        return CreateLNKMutator();
    }

    // Optional override; replaces Jackalope's MTPRNG with our LNKPRNG
    // so the same xoroshiro stream drives the engine and our scheduler.
    PRNG* CreatePRNG(int argc, char** argv, ThreadContext* tc) override {
        // Read -prng_seed from argv if provided, else seed from time().
        // Mixing thread_id with the golden-ratio constant gives well-
        // separated streams across threads, even for adjacent ids.
        int user_seed = GetIntOption("-prng_seed", argc, argv, 0);
        uint32_t base = (user_seed != 0)
                        ? static_cast<uint32_t>(user_seed)
                        : static_cast<uint32_t>(std::time(nullptr));
        uint32_t seed = base ^ static_cast<uint32_t>(tc->thread_id * 0x9e3779b9u);
        return new LNKPRNG(seed);
    }
};

int main(int argc, char** argv) {
    // Initialize the Thompson Sampling scheduler arrays + the mutex
    // protecting them. Must happen before any worker thread is spawned
    // (Run() spawns -nthreads workers, each of which calls Mutate()).
    mutate_scheduler_init();

    Fuzzer* fuzzer = new LNKFuzzer();
    fuzzer->Run(argc, argv);
    return 0;
}
