#ifndef LNK_PRNG_H
#define LNK_PRNG_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct{
    uint64_t smstate;   // splitmix64 state, used only at seed time
    uint64_t xstate[2]; // xoroshiro128++ state, used for all ouput
} LNKRand;

/**
 * Seed from a 64-bit input value. Loop guards against the 2^-128 case
 * where splitmix produces zero for both state vars (which would make
 * xoroshiro emit zero forever).
 */
void lnk_rand_seed(LNKRand* rng, uint64_t seed);
 
/** Raw 64-bit uniform draw. */
uint64_t lnk_rand_uniform64(LNKRand* rng);
 
/** 32-bit uniform draw (upper half of the 64-bit output). */
uint32_t lnk_rand(LNKRand* rng);
 
/**
 * Uniform in [0, n). For the N values we ever pass here, modulo bias is
 * at most n/2^64 — realistically undetectable.
 */
uint32_t lnk_rand_below(LNKRand* rng, uint32_t n);
 
/**
 * Uniform double in [0, 1) with full 53-bit mantissa precision.
 * Can return exactly 0 (probability 2^-53). Callers that take log()
 * of the result must guard against that.
 */
double lnk_rand_double(LNKRand* rng);
 
/** Biased coin flip. Returns 1 with probability p, else 0. */
int lnk_rand_bool(LNKRand* rng, double p);

#ifdef __cplusplus
}
#endif

#endif