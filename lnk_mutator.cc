// We subclass Jackalope's Mutator interface because we use our own mutation engine.
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
//
// SaveGlobalState / LoadGlobalState persist the scheduler arrays so
// learning survives across fuzzer restarts.

#include "Jackalope/mutator.h"
#include "Jackalope/prng.h"
#include "Jackalope/sample.h"
#include "lnk_prng_jackalope.h"

extern "C" {
    #include "model.h"
    #include "mutate.h"
    int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);
    int serialize_lnk(uint8_t* buf, size_t cap, size_t* out_len, const LNKGeneratorState* state);
}

#include <cstring>
#include <vector>

// Upper bound on serialized .lnk size. The format's offset fields are
// 32-bit but practical samples are well under 1 MB; this gives generous
// headroom without pinning huge per-thread buffers.
static constexpr size_t LNK_MAX_BYTES = 1 << 20; // 1 MiB

class LNKMutator : public Mutator{
public:
    LNKMutator() : last_op_(-1), initialized_(false){
        std::memset(&state_, 0, sizeof(state_));
        std::memset(&layout_, 0, sizeof(layout_));
        buf_.resize(LNK_MAX_BYTES);
    }

    // Called once per round, before Mutate(). The sample we get here is
    // the seed Jackalope picked from its queue. We parse it once and
    // cache the resulting state so subsequent Mutate() calls in this
    // round operate on structured data, not raw bytes.
    bool InitRound(Sample* input_sample, PRNG*) override{
        if(deserialize_lnk(input_sample->bytes, input_sample->size, &state_) < 0){
            // Malformed seed (shouldn't happen for queue samples — they
            // round-tripped successfully when added). Skip this round.
            initialized_ = false;
            return false;
        }
        layout_ = mutate_extract_layout(&state_);
        initialized_ = true;
        return true;
    }

    // Runs once per mutation; Jackalope calls this many times
    // per round before moving to the next seed.
    bool Mutate(Sample* inout_sample, PRNG* prng,
                std::vector<Sample*>& /*all_samples*/) overrid{
        if(!initialized_) return false;

        // Recover our generator state from Jackalope's PRNG*. Safe
        // because LNKFuzzer::CreatePRNG is the only constructor of
        // PRNG instances in this binary.
        LNKRand* rng = static_cast<LNKPRNG*>(prng)->state();

        last_op_ = mutate_apply(rng, &state_, &layout_);
        if(last_op_ < 0){
            // No applicable operator (every precondition failed).
            // Tell Jackalope this round produced no mutation.
            return false;
        }

        size_t out_len = 0;
        if(serialize_lnk(buf_.data(), buf_.size(), &out_len, &state_) < 0){
            // serialization failed (oversize, internal inconsistency)
            // dont ship a fucked buffer
            return false;
        }

        inout_sample->Init(buf_.data(), out_len);
        return true;
    }

    // Called after the target runs on the mutated sample. has_new_coverage
    // is the signal we feed back to the scheduler's Beta posteriors.
    void NotifyResult(RunResult, bool has_new_coverage) override{
        if(last_op_ >= 0){
            mutate_report(static_cast<MutationOperator>(last_op_),
                          has_new_coverage ? 1 : 0);
            last_op_ = -1;  // consume; one report per Mutate() call
        }
    }

private:
    LNKGeneratorState    state_;        // parsed seed, mutated in place
    LNKLayout            layout_;       // size/offset cache for sizes-group ops
    int                  last_op_;      // operator used in the most recent Mutate()
    bool                 initialized_;  // false if InitRound failed
    std::vector<uint8_t> buf_;          // reusable serialization buffer
};