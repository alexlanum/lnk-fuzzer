# Mutation scheduler — hierarchical Thompson Sampling

The scheduler decides *which* structural mutation to apply next. It is the part of the fuzzer
that learns. This document specifies the statistical model, the algorithm, the sampling
machinery, and the concurrency contract.

Implementation: [`mutate.c`](../mutate.c) (`sample_gamma`, `sample_beta`, `mutate_apply`,
`mutate_report`, `mutate_scheduler_init`). Operator/group enums: [`mutate.h`](../mutate.h).

## Problem

A mutation operator either produces new code coverage when applied or it does not. Its success
rate is unknown, non-stationary (coverage saturates as the campaign explores an operator's
reachable branches), and wildly uneven across operators — `MUTATE_PROPSTORE_VT_VARIANT` keeps
unlocking branches in a deep parser; `MUTATE_TRACKER_VERSION_NONZERO` saturates after both sides
of one branch are hit. Spending equal budget on both is waste.

This is a **Bernoulli multi-armed bandit**: `K` arms, each arm `k` pays off with unknown
probability `θ_k`, finite pull budget, maximize total payoff (new coverage). The scheduler must
balance *exploiting* arms known to pay against *exploring* arms it is still unsure about.

## Model — Beta-Bernoulli conjugacy

Each arm's outcome is `Bernoulli(θ_k)`. We maintain a posterior belief over `θ_k`. The Beta
distribution is the conjugate prior for the Bernoulli likelihood, which makes the update
arithmetic exact and `O(1)`:

```
prior        θ_k ~ Beta(α_k, β_k)            α_k = 1 + successes,  β_k = 1 + failures
likelihood   x   ~ Bernoulli(θ_k)
posterior    θ_k | x ~ Beta(α_k + x, β_k + (1 − x))
```

All arms start at `Beta(1, 1)` — the uniform distribution on `[0, 1]`, i.e. "no evidence, the
rate could be anything." The posterior sharpens with evidence:

| posterior | meaning |
|---|---|
| `Beta(1, 1)`     | untried — flat, will be explored |
| `Beta(51, 6)`    | ~50 hits / 5 misses — concentrated near 1.0, strongly favored |
| `Beta(2, 100)`   | saturated — concentrated near 0, starved |
| `Beta(80, 80)`   | jack-of-all-trades — peaked at 0.5, picked at medium rate |

The update rule is the whole of the learning: **success → `α += 1`, failure → `β += 1`.** This is
optimal Bayesian updating under the Beta-Bernoulli pair.

## Algorithm — Thompson Sampling

Greedy "pick the highest posterior mean" never explores: with fixed counters it picks the same arm
forever. Thompson Sampling is the stochastic alternative — *probability matching*:

```
each decision:
    for each arm k:  draw  θ̂_k ~ Beta(α_k, β_k)      # one sample from the belief
    pull  argmax_k θ̂_k                                # act on the sampled belief
    observe success/failure, update that arm's posterior
```

Exploration is emergent, not a tuned parameter: a barely-tried arm has a wide posterior, so its
draw `θ̂_k` is occasionally high enough to win and get explored; a saturated arm's posterior has
collapsed near zero, so it is almost never drawn high. As evidence accumulates the best arm's
posterior concentrates above the rest and it wins most draws. No ε, no temperature, no decay
schedule to hand-tune — and because the belief, not a point estimate, drives selection, TS
re-explores automatically when an arm's true rate drifts (coverage saturation), which is why it is
preferred here over greedy/AFL-style scheduling and over MOPT (used only as a conceptual fallback).

## Two-level (hierarchical) bandit

Selection runs Thompson Sampling twice — over groups, then over operators within the chosen group:

```
level 1   sample θ̂_g ~ Beta(group_α[g], group_β[g])  for all 15 groups; pick best group
level 2   candidates ← operators in that group whose preconditions hold on this sample
          sample θ̂_o ~ Beta(op_α[o], op_β[o])  for each candidate; pick best operator
```

`mutate_report` credits **both** levels on every outcome — the operator's posterior *and* its
group's posterior are incremented together — so a group's belief is the pooled evidence of its
member operators. The hierarchy is what lets the scheduler converge with ~85 operators: it learns
"property-store mutations pay, tracker mutations don't" at the 15-arm group level (fast) before it
has enough data to rank individual operators (slow).

**Precondition filter (level 2).** An operator is a candidate only if it is applicable to the
current parsed sample — `op_precondition()` rejects, e.g., an ExtraData operator on a file with no
ExtraData, or `DUPLICATE_PID` on a property store with no storage holding ≥2 values. If the chosen
group has no applicable operator, the scheduler falls back to any applicable operator across all
groups; if nothing applies it returns `-1` and the round is skipped. This keeps the bandit's reward
signal clean — operators are never charged a failure for a sample they could not have mutated.

## Sampling a Beta variate

There is no closed-form inverse-CDF for the Beta distribution, so we sample it through the
Gamma-ratio identity:

```
X ~ Γ(α),  Y ~ Γ(β),  independent   ⟹   X / (X + Y) ~ Beta(α, β)
```

Gamma variates come from **Marsaglia–Tsang (2000)**, a squeeze/rejection method for `shape ≥ 1`
that consumes a standard normal (generated inline via Box–Muller) plus a uniform per trial and
accepts on the first try the large majority of the time:

```
d = shape − 1/3 ;  c = 1 / sqrt(9d)
repeat:
    x ~ N(0,1) ;  v = (1 + c·x)^3                      # reject if v ≤ 0
    u ~ U(0,1)
    accept d·v  if  u < 1 − 0.0331·x⁴                  # cheap squeeze
                or  ln u < ½x² + d(1 − v + ln v)        # exact bound
```

For `shape < 1` it boosts: `Γ(a) = Γ(a+1) · U^(1/a)`. The chain bottoms out at uniforms from the
PRNG — see [prng.md](prng.md). One decision costs `(15 + |candidates|)` Beta draws ≈ a few hundred
Gamma trials ≈ ~1000 uniform draws, which is why PRNG quality and speed are load-bearing, not
incidental: bias in the uniforms propagates through Box–Muller and the Gamma rejection into
mis-shaped Beta posteriors and therefore systematically skewed scheduling.

## Concurrency

`group_α/β` and `op_α/β` are process-global, shared by all worker threads; the xoroshiro PRNG is
per-thread. The contract:

- **`mutate_report`** takes a `CRITICAL_SECTION`, does four `+= 1.0` increments, releases. Sub-µs.
- **`mutate_apply`** takes the lock only to `memcpy` the four arrays into thread-local snapshots,
  then releases and does all sampling/selection/mutation lock-free against the snapshot.

A racing `mutate_report` may leave a snapshot one update stale, but Thompson Sampling is robust to
single-update staleness — it does not change which arm wins a draw. The design preserves shared
learning (every thread's outcomes update the one global posterior) while keeping the hot path off
the lock. `op_apply` mutates only thread-local state, layout, and the per-thread RNG, so it never
needs the lock.

> `mutate_scheduler_init()` seeds every posterior to `Beta(1,1)` and constructs the mutex. Call it
> once, before any worker thread starts (`InitializeCriticalSection` is not idempotent on Windows).
