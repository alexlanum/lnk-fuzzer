/**
 * mutator.c is the AFL++ custom mutator entry point.
 * It wires the scheduler (from mutate.c) to AFL++'s fuzzing loop:
 *   AFL++ seed -> deserialize_lnk() -> mutate_apply() -> serialize_lnk()
 *   -> apply postserialize op (GROUP_FILE) -> back to AFL++.
 *
 * Built as a shared object loaded via AFL_CUSTOM_MUTATOR_LIBRARY.
 * Intended to run with AFL_CUSTOM_MUTATOR_ONLY=1 so every mutation flows
 * through the Thompson Sampling scheduler.
 * https://aflplus.plus/docs/custom_mutators/
 */

#include "model.h"
#include "mutate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// serialize.c / deserialize.c have no headers, forward-declare them
int serialize_lnk(uint8_t* buf, size_t cap, size_t* out_len, const LNKGeneratorState* state);
int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);

// state the mutator needs to remember between afl_custom_fuzz calls
// AFL++ may run multiple instances in parallel; each gets its own
// lnk_mutator_t via afl_custom_init.
typedef struct lnk_mutator{
    uint8_t* out_buf; // mutation output buffer, grown with realloc
    size_t   out_cap; // current capacity of out_buf
    
    MutationOperator last_op; // operator applied by last afl_custom_fuzz call,
                              // used by afl_custom_describe and for reporting
                              // coverage win/loss feedback

    LNKGeneratorState state;  // scratch parsed LNKGeneratorState
                              // reused on each afl_custom_fuzz call
} lnk_mutator_t;

size_t afl_custom_fuzz(
    lnk_mutator_t* mutator,
    uint8_t* buf,
    size_t buf_size,
    uint8_t** out_buf,
    uint8_t* add_buf,
    size_t add_buf_size,
    size_t max_size
){
    // these are never used, but are required by the ABI, cast to silence compiler warnings
    (void)add_buf;
    (void)add_buf_size;

    // ensure output buffer is large enough to store the serialized bytes
    if(mutator->out_cap < max_size){
        size_t new_cap;

        if(mutator->out_cap > 0)
            new_cap = mutator->out_cap;
        else
            new_cap = 65536; // first time allocation, no previous size to grow from
        
        while(new_cap < max_size)
            new_cap *= 2;

        uint8_t* p = (uint8_t*)realloc(mutator->out_buf, new_cap); // resize allocation
        if(!p){
            *out_buf = NULL;
            return 0;
        }

        mutator->out_buf = p;
        mutator->out_cap = new_cap;
    }

    // 1. parse the seed bytes into LNKGeneratorState (deserialize them)
    if(deserialize_lnk(buf, buf_size, &mutator->state) < 0){
        // unparseable seed, pass it through unchanged so AFL++ still has input
        size_t n = buf_size > max_size ? max_size : buf_size;
        memcpy(mutator->out_buf, buf, n);
        *out_buf = mutator->out_buf;
        return n;
    }

    // reset the postserialize request slot. deserialize memsets state to 0,
    // which makes postserialize_op = POSTSERIALIZE_TRUNCATE = 0 not NONE = -1.
    mutator->state.postserialize_op = POSTSERIALIZE_NONE;
    mutator->state.postserialize_arg = 0;

    // 2. run Thompson Sampling scheduler to pick and apply an operator
    LNKLayout layout = mutate_extract_layout(&mutator->state); // extract layout from a deserialized state
    MutationOperator op = mutate_apply(&mutator->state, &layout);
    mutator->last_op = op;

    if((int)op < 0){
        // no valid operator for this input, pass seed through unchanged
        state_free(&mutator->state);
        size_t n = buf_size > max_size ? max_size : buf_size;
        memcpy(mutator->out_buf, buf, n);
        *out_buf = mutator->out_buf;
        return n;
    }

    
}