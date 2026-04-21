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

// frees everything deserialize_lnk allocates and zeroes the struct so stale
// pointers can't be accidentally reused. call this at the end of every
// afl_custom_fuzz cycle to avoid LNKGeneratorState memory leak.
static void state_free(LNKGeneratorState* state){
    // PIDL items: each has a raw + payload buffer
    for(int i = 0; i < state->linktargetidlist.item_count; i++){
        ItemID* item = &state->linktargetidlist.items[i];
        free(item->raw);
        free(item->payload);
    }

    // StringData strings
    free(state->stringdata.name);
    free(state->stringdata.relative_path);
    free(state->stringdata.working_dir);
    free(state->stringdata.arguments);
    free(state->stringdata.icon_location);

    // ExtraData block payloads
    for(int i = 0; i < state->extradata.block_count; i++)
        free(state->extradata.blocks[i].data);

    // zero the struct so stale pointers can't be accidentally reused
    memset(state, 0, sizeof(*state));
}

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
        size_t n = buf_size;
        if(n > max_size){
            n = max_size;
        }
        memcpy(mutator->out_buf, buf, n);
        *out_buf = mutator->out_buf;
        return n;
    }

    // 2. run Thompson Sampling scheduler to pick and apply an operator
    LNKLayout layout = mutate_extract_layout(&mutator->state); // extract layout from a deserialized state
    MutationOperator op = mutate_apply(&mutator->state, &layout);
    mutator->last_op = op;

    if((int)op < 0){
        // no valid operator for this input, return the original seed bytes unchanged as if we did nothing
        state_free(&mutator->state);
        size_t n = buf_size;
        if(n > max_size){
            n = max_size;
        }
        memcpy(mutator->out_buf, buf, n);
        *out_buf = mutator->out_buf;
        return n;
    }

    // 3. convert the mutated LNKGeneratorState back to bytes (serialize it)
    size_t out_len = 0;
    if(serialize_lnk(mutator->out_buf, mutator->out_cap, &out_len, &mutator->state) < 0){
        // serialization failed (likely: buffer too small), return the original seed bytes unchanged as if we did nothing
        state_free(&mutator->state);
        size_t n = buf_size;
        if(n > max_size){
            n = max_size;
        }
        memcpy(mutator->out_buf, buf, n);
        *out_buf = mutator->out_buf;
        return n;
    }

    // 4. apply GROUP_FILE post-serialize operator if one was requested
    if(mutator->state.postserialize_op != POSTSERIALIZE_NONE){
        int pop = mutator->state.postserialize_op;
        int parg = mutator->state.postserialize_arg;

        if(pop == POSTSERIALIZE_TRUNCATE){
            int n = parg;
            if(n < 1) n = 1;
            if((size_t)n >= out_len) n = (int)out_len - 1;
            if(n > 0) out_len -= (size_t)n;
        } else if(pop == POSTSERIALIZE_APPEND_GARBAGE){
            size_t n = (size_t)parg;
            size_t new_len = out_len + n;
            if(new_len > max_size) new_len = max_size;
            for(size_t i = out_len; i < new_len; i++)
                mutator->out_buf[i] = (uint8_t)(rand() & 0xFF);
            out_len = new_len;
        }
        // POSTSERIALIZE_SECTION_OVERLAP not implemented yet
    }

    // 5. clean up and give bytes to AFL
    state_free(&mutator->state);

    if(out_len > max_size) out_len = max_size;
    *out_buf = mutator->out_buf;
    return out_len;
}