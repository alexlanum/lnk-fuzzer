// Bridge between Jackalope's Mutator interface and our C mutation engine.
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