// lnk_mutator.cc
//
// Bridge between Jackalope's Mutator interface and our C mutation core.
//
// Per worker thread, Jackalope constructs one LNKMutator. On each
// mutation round it gives us a Sample (raw bytes) and a PRNG; we
// deserialize the bytes into an LNKGeneratorState, run mutate_apply
// to pick and apply one of our operators via the Thompson Sampling
// scheduler, and serialize back into the sample buffer.
//
// After Jackalope runs the target, it calls NotifyResult; we forward
// the coverage outcome to mutate_report so the scheduler updates its
// Beta posteriors and learns which operators are paying off.

// Bare-name includes match Jackalope's own internal pattern.
// Resolution requires -IJackalope on the compile line (see .clangd).
#include "mutator.h"
#include "prng.h"
#include "sample.h"
#include "runresult.h"

#include "lnk_prng_jackalope.h"

extern "C" {
    #include "model.h"
    #include "mutate.h"
    int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);
    int serialize_lnk(uint8_t* buf, size_t cap, size_t* out_len, const LNKGeneratorState* state);
}

#include <cstdint>
#include <cstring>
#include <vector>

// Upper bound on serialized .lnk size. The format's offset fields are
// 32-bit but practical samples are well under 1 MB; this gives generous
// headroom without pinning huge per-thread buffers.
static constexpr size_t LNK_MAX_BYTES = 1 << 20; // 1 MiB

class LNKMutator : public Mutator {
public:
    LNKMutator() : last_op_(-1), initialized_(false){
        std::memset(&state_, 0, sizeof(state_));
        std::memset(&layout_, 0, sizeof(layout_));
        buf_.resize(LNK_MAX_BYTES);
    }

    // Free any per-state heap (PIDL items, ExtraData blocks, StringData strings)
    // left over when the worker thread shuts down. Without this, every fuzz
    // campaign leaks N_workers × <last-round heap>; minor but tidy.
    ~LNKMutator() override {
        lnk_state_free(&state_);
    }

    // Called once per round, before Mutate(). The sample we get here is
    // the seed Jackalope picked from its queue. We parse it once and
    // cache the resulting state so subsequent Mutate() calls in this
    // round operate on structured data, not raw bytes.
    //
    // Note: Jackalope's InitRound returns void. If the seed fails to
    // parse we just leave initialized_ = false and let Mutate() bail.
    void InitRound(Sample* input_sample, MutatorSampleContext* /*context*/) override {
        // Drop the previous round's heap-owned pointers (PIDL items, ExtraData
        // block data, StringData strings) before deserialize_lnk overwrites the
        // count fields and pointer fields with fresh allocations. Without this
        // call every InitRound leaks the previous round's heap — at 24 workers ×
        // tens of thousands of rounds, the leak fills the heap and trips
        // ntdll's STATUS_HEAP_CORRUPTION guard (0xC0000374) within ~60s.
        lnk_state_free(&state_);

        // Sample::bytes is char*; our deserialize takes uint8_t*. Cast.
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(input_sample->bytes);
        if(deserialize_lnk(bytes, input_sample->size, &state_) < 0){
            // Malformed seed (shouldn't happen for queue samples — they
            // round-tripped successfully when added). Skip this round.
            initialized_ = false;
            return;
        }
        layout_ = mutate_extract_layout(&state_);
        initialized_ = true;
    }

    // Hot path. Runs once per mutation; Jackalope calls this many times
    // per round before moving to the next seed.
    bool Mutate(Sample* inout_sample, PRNG* prng,
                std::vector<Sample*>& /*all_samples*/) override {
        if(!initialized_) return false;

        // Recover our generator state from Jackalope's PRNG*. Safe
        // because LNKFuzzer::CreatePRNG is the only constructor of
        // PRNG instances in this binary.
        LNKRand* rng = static_cast<LNKPRNG*>(prng)->state();

        last_op_ = mutate_apply(rng, &state_, &layout_);
        if(last_op_ < 0){
            // No applicable operator (every precondition failed).
            return false;
        }

        size_t out_len = 0;
        if(serialize_lnk(buf_.data(), buf_.size(), &out_len, &state_) < 0){
            // Serialization failed (oversize, internal inconsistency).
            // Don't ship a torn buffer.
            return false;
        }

        // Defensive bound: out_len must never exceed the buffer we just wrote into.
        // We've seen crashes where stack-resident `out_len` ends up with garbage in its
        // upper 32 bits (~4 GiB) and Sample::Init's memcpy walks off the end of buf_.
        // Until the root cause is fully nailed, refuse to ship samples whose size
        // exceeds the buffer that produced them.
        if(out_len > buf_.size()) return false;

        // Sample::Init takes (const char*, size_t). buf_ is uint8_t*; cast.
        inout_sample->Init(reinterpret_cast<const char*>(buf_.data()), out_len);
        return true;
    }

    // Called after the target runs on the mutated sample. has_new_coverage
    // is the signal we feed back to the scheduler's Beta posteriors.
    void NotifyResult(RunResult /*result*/, bool has_new_coverage) override {
        if(last_op_ >= 0){
            mutate_report(static_cast<MutationOperator>(last_op_),
                          has_new_coverage ? 1 : 0);
            last_op_ = -1;  // consume; one report per Mutate() call
        }
    }

private:
    LNKGeneratorState  state_;        // parsed seed, mutated in place
    LNKLayout          layout_;       // size/offset cache for sizes-group ops
    int                last_op_;      // operator used in the most recent Mutate()
    bool               initialized_;  // false if InitRound's parse failed
    std::vector<uint8_t> buf_;        // reusable serialization buffer
};

// Factory used by lnk_fuzzer_main.cc. Defined here so that file doesn't
// need to know LNKMutator's class definition.
Mutator* CreateLNKMutator(){
    return new LNKMutator();
}
