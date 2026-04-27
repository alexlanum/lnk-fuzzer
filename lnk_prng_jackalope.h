// Header for the LNKPRNG adapter class. Separated from lnk_prng_jackalope.cc
// so lnk_mutator.cc can include it (to static_cast PRNG* and reach state()).

#ifndef LNK_PRNG_JACKALOPE_H
#define LNK_PRNG_JACKALOPE_H

#include "Jackalope/prng.h"

extern "C" {
    #include "lnk_prng.h"
}

class LNKPRNG : public PRNG{
public:
    explicit LNKPRNG(uint64_t seed);
    // only override that Jackalope's PRNG base class requires.
    // returns the upper 32 bits of the xoroshiro output.
    uint32_t Rand() override;

    // non virtual accessor. LNKMutator uses this to reach the generator
    // state and pass it to mutate_apply, which needs 64-bit / 53-bit
    // precision the Rand() interface can't provide.
    LNKRand* state();

private:
    LNKRand r_;
};

#endif