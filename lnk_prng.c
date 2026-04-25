/**
 * Per-thread PRNG implementation. See lnk_prng.h for rationale.
 */
#include "lnk_prng.h"

// splitmix64: a bijective mixing function.
// Used at seed time to expand the 64-bit user seed into the 128-bit
// xoroshiro state.  https://prng.di.unimi.it/splitmix64.c
static uint64_t splitmix64_next(LNKRand* rng){
    uint64_t z = (rng->smstate += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

static inline uint64_t rotl64(uint64_t x, int k){
    k &= 63;                // mask k to 0-63
    if(k == 0) return x;    // avoid UB on x >> 64 when k = 0
    return (x << k)         // upper portion of result
         | (x >> (64 - k)); // lower portion (bits that wrapped around)
}

// xoroshiro128++ 1.0 https://prng.di.unimi.it/xoroshiro128plusplus.c
static uint64_t xoroshiro128pp(LNKRand* rng){
    const uint64_t s0 = rng->xstate[0];
    uint64_t s1 = rng->xstate[1];
    const uint64_t result = rotl64(s0 + s1, 17) + s0;
    s1 ^= s0;
    rng->xstate[0] = rotl64(s0, 49) ^ s1 ^ (s1 << 21);
    rng->xstate[1] = rotl64(s1, 28);
    return result;
}

void lnk_rand_seed(LNKRand* rng, uint64_t seed){
    rng->smstate = seed;
    do{
        rng->xstate[0] = splitmix64_next(rng);
        rng->xstate[1] = splitmix64_next(rng);
    } while (rng->xstate[0] == 0 && rng->xstate[1] == 0);
}

uint64_t lnk_rand_uniform64(LNKRand* rng){
    return xoroshiro128pp(rng);
}

uint32_t lnk_rand(LNKRand* rng){
    return (uint32_t)(xoroshiro128pp(rng) >> 32);
}

uint32_t lnk_rand_below(LNKRand* rng, uint32_t n){
    if(n == 0) return 0;
    return (uint32_t)(xoroshiro128pp(rng) % n);
}

double lnk_rand_double(LNKRand* rng){
    return (double)(xoroshiro128pp(rng) >> 11) * (1.0 / (double)(1ULL << 53));
}

int lnk_rand_bool(LNKRand* rng, double p){
    return lnk_rand_double(rng) < p;
}
