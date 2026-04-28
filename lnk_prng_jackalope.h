// lnk_prng_jackalope.h
//
// Header for the LNKPRNG adapter class. Separated from lnk_prng_jackalope.cc
// so lnk_mutator.cc can include it (to static_cast PRNG* and reach state()).

#ifndef LNK_PRNG_JACKALOPE_H
#define LNK_PRNG_JACKALOPE_H

// Jackalope's prng.h uses size_t without including <cstddef>.
// We include it ourselves so the header parses cleanly.
#include <cstddef>
#include <cstdint>

// Bare-name include matches Jackalope's own internal pattern.
// Resolution requires -IJackalope on the compile line (see .clangd).
#include "prng.h"

extern "C" {
    #include "lnk_prng.h"
}

class LNKPRNG : public PRNG {
public:
    explicit LNKPRNG(uint32_t seed);

    // Only override Jackalope's PRNG base class requires.
    // Returns the upper 32 bits of the xoroshiro output.
    uint32_t Rand() override;

    // Non-virtual accessor. LNKMutator uses this to reach the generator
    // state and pass it to mutate_apply, which needs 64-bit / 53-bit
    // precision the Rand() interface can't provide.
    LNKRand* state();

private:
    LNKRand r_;
};

#endif
