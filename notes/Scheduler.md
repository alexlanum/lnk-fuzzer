

## Decision

In a casino with 16 slot machines. Each machine, when you pull its lever, either outputs a coin (success) or doesn't (fail). You do not know the payout rate of any machine. You have limited pulls. The goal is to maximize coins.

Naive strategy:

- pull every lever equally. Wastes pulls on bad machines.

Greedy strategy:

- pull each lever once, then commit forever to whichever paid out. This fails because you might have gotten unlucky on the best machine's first pull.

Smart strategy:

- keep trying each machine sometimes, but favor the ones that seem to be paying out more often. Balance exploiting what you know against exploring what you don't.

This is called a multi-armed bandit problem, and it is exactly what a scheduler solves in fuzzing.

Applying this to fuzzer architecture:

- each slot machine = a mutation operator, such as `MUTATE_FLAG_SINGLE_BIT`
- pulling the lever = applying that operator to an LNK file and running it through `Load`
- getting a coin = AFL++ reported that the mutation produced new coverage (fuzzer reached a basic block in `shell32.dll` it hadn't seen before)
- maximizing coins = finding as many new branches (and therefore bugs) as possible within your computation budget

The scheduler's job is to determine which mutation operator should be applied next.



## Do not pick randomly

The scheduler should not choose operators at random (`op = rand() % MUTATE_COUNT`) because the set of operators are wildly uneven:

- `MUTATE_PROPSTORE_VT_VARIANT` finds dozens of new branches in shell32's propstore parser.
- `MUTATE_TRACKER_VERSION_NONZERO` sets one byte to nonzero, parser likely has one branch on that byte, and once you've hit both sides, it will never produce new coverage again.
- After an hour, you'd have spent equal time poking the tracker byte (which is saturated) as you have on property store variants (which keep paying off). It is a waste.

You want a scheduler that learns from results and shifts its budget toward productive operators.



## Thompson Sampling

This is a bandit algorithm from 1993 that has an elegantly simple idea:

> For each arm, maintain a probability distribution over what you *believe* its payout rate might be. When deciding which arm to pull, sample one "belief" from each arm's distribution, and pull the arm whose sampled belief is highest.

This design naturally balances exploration and exploitation. Arms you've pulled a lot have narrow / concentrated beliefs (you're confident about their chance). Arms you've barely tried have wide / uncertain beliefs (they could be anything). The sampling sometimes gives an untried arm a lucky high draw, causing you to explore it. But over time, the best arm's distribution narrows and settles above the others, so its samples consistently beat the rest and it gets picked most often.

In bandit literature, an "arm" is one of the levers on a slot machine. In the fuzzer code, an arm is a single mutation operator or a mutation operator group. "Pulling an arm" means choosing an operator and applying it to an LNK file, then seeing whether AFL++ reports new coverage. "Success rate" represents the fraction of the time that operator produced new coverage when applied.

Strategy 1 (greedy, bad):
- For each arm, compute the mean of its belief distribution. Pick the arm with the highest mean.

Strategy 2 (Thompson, good):
- For each arm, draw one random sample from its belief distribution. Pick the arm with the highest sample.

Strategy 1 is deterministic. Given the same counters, it picks the same arm every time. You never explore.

Strategy 2 is stochastic. Given the same counters, it can pick different arms on different calls because the samples are random. This is where exploration comes from.



### Beta distribution

We need a probability distribution to represent "chance of success." The Beta distribution is the natural choice for this because:

1. Success rates live in [0, 1]. Beta lives in [0, 1].
2. It has two parameters, $\alpha$ (alpha) and $\beta$ (beta):
    - $\alpha$ = 1 + number of successes you've seen
    - $\beta$ = 1 + number of failures you've seen

$Beta(1, 1)$ is a flat uniform distribution on [0, 1]. There is no evidence about this operator yet; its new coverage rate could be anything.
- `MUTATE_STRUCTURE_ADD` just got added and hasn't been chosen yet: $Beta(1, 1)$. Scheduler has zero evidence; it'll happily try it.

$Beta(11, 1)$ means 10 coverage hits, 0 misses. Distribution is concentrated near 1.0. This operator has been extremely productive so far; nearly every mutation it produces unlocks new code paths in shell32.
- `MUTATE_PROPSTORE_VT_VARIANT` keeps finding new edges because the property-store parser is deep and messy. Drifts toward $Beta(50, 5)$. Scheduler strongly favors it.

$Beta(3, 8)$ means 2 coverage hits, 7 misses. Concentrated around 0.2. This operator occasionally pays off but typically wastes budget.
- `MUTATE_TRACKER_VERSION_NONZERO` has one branch in the parser; both sides got hit quickly and then nothing new. Drifts toward $Beta(2, 100)$. Scheduler basically stops picking it.

$Beta(501, 501)$ means 500 of each. Razor-sharp spike at 0.5. We can be confident that this operator finds new coverage exactly half the time.
- `MUTATE_FLAG_SINGLE_BIT` is a jack-of-all-trades: sometimes unlocks coverage, often doesn't. Stabilizes around $Beta(80, 80)$ or similar. Scheduler picks it at medium frequency.

The update rule is simple: pulled arm (used op), got success? $\alpha$ += 1. Got failure? $\beta$ += 1. This is mathematically optimal Bayesian updating under a Beta prior and Bernoulli outcomes (aka "Beta-Bernoulli conjugacy").



### Full algorithm

For each mutation operator, keep counters $\alpha$ and $\beta$, both starting at 1.

To pick which operator to use next:
- For each operator, sample on number from its $Beta(\alpha, \beta)$ distribution.
- Pick the operator whose sample was highest.

After running the fuzzer with the chosen operator:
- If new coverage found: $\alpha$ += 1 for that operator.
- Otherwise: $\beta$ += 1 for that operator.



### Two-level scheduler (hierarchical bandits)

There are currently 16 groups and ~77 individual operators distributed across them. The scheduler runs Thompson Sampling twice:

1. Across all 16 groups, sample a `0` from each $Beta(group_\alpha[g], group_\beta[g])$. Pick the group with the highest sample.
2. Among the operators inside that group, filter to operators whose preconditions are satisfied (ex. an op that mutated ExtraData blocks is useless if the file has none), then Thompson sample among survivors.

This two-layer design allows the scheduler to learn faster.

```c
// mutate.c
MutationOperator mutate_apply(LNKGeneratorState* state, LNKLayout* layout){
    // Lvl 1: Select a group using Thompson Sampling
    for(int g = 0; g < GROUP_COUNT; g++){
        double theta = sample_beta(group_alpha[g], group_beta[g]);  // <-- sample from Beta
        if(theta > best_score){ ... chosen_group = g; }
    }
    
    // Lvl 2: collect operators in that group that satisfy preconditions
    // ...

    // Thompson sample among candidates
    for(int i = 0; i < count; i++){
        double s = sample_beta(op_alpha[candidates[i]], op_beta[candidates[i]]);
        if(s > best_score){ ... chosen_op = candidates[i]; }
    }

    op_apply(chosen_op, state, layout);
    return chosen_op;
}
```



### Generating a number that follows a Beta distribution

Distributions are shapes of randomness:

- Uniform – flat line, every outcome equally likely
- Normal – bell curve, values cluster around the average ~0
- Beta – flexible curve between 0 and 1, can lean left/right/center

The CPU only provides uniform randomness (`rand()`). To get a Beta-distributed shape, we must transform that flat randomness.

```
Uniform -> [radius, angle] -> Normal -> Gamma -> Beta
```

**Step 1**: Uniform Foundation
Start with two uniform numbers from the fair randomness of `rand()`:
```math
u_1, u_2 \in [0, 1]
```
Using these two uniform numbers, we effectively pick a random point in a 2D square where every spot is equally likely.

**Step 2**: Normal -> Gamma (Box-Muller)
We turn the square into a circle to create a bell curve. This works because a 2D Normal distribution is perfectly symmetric around the center.

We need Gamma numbers because there is no simple way to turn a Normal bell curve into a Beta curve in step 3.

**Step 3**: Two Gammas -> Beta
You cannot jump directly from Normal to Beta. You must use the Gamma distribution as a bridge between them, then combine two Gamma values (X, Y) to squeeze the result into the [0,1] range:

```math
\text{Beta} = \frac{X}{X + Y}
```

```c
static double sample_beta(double a, double b){
    double x = sample_gamma(a);
    double y = sample_gamma(b);
    return x / (x + y);
}
```

So to produce one Beta sample, you need multiple Gamma samples (rejection loop), each of which needs multiple Normal samples (rejection loop), each of which needs multiple Uniform samples.

- Beta sampler needs many uniform random numbers to produce one Beta value.
- Scheduler calls the Beta sampler ~93 times, so ~1000 uniform random numbers per decision.
- If the PRNG is bad (not truly uniform), those 1000 inputs are biased – bias propagates through the math, your Beta outputs would be incorrectly shaped distribution.
- Result: scheduler makes systematically skewed decisions, not random ones. Bad.



### PRNG

`rand()` is a C stdlib function that retusn a "random" integer. There are many possible implementations, and the standard barely constrains them.

On Windows with MSVCRT, `rand()` is a Linear Congruential Generator (LCG):
```c
static unsigned long seed = 1;
int rand(void) {
    seed = seed * 214013 + 2531011;
    return (seed >> 16) & 0x7FFF;   // returns 15 bits
}
```



Why `rand()` is unfit for this fuzzer:

**Low resolution.** Only 32768 distinct values per call. Beta samples derived from these uniforms have low resolution, so operators with similar success rates can't be distinguished late in fuzzing.

**Unreachable high range.** `rand() & 0xFFFF` can never produce values above 32767. Mutations that ask for a random `uint16` silently cover only the bottom half of the range, missing parser branches that trigger on larger values.

**32-bit period.** The output stream repeats after ~2^31 calls, minutes to hours at fuzzing rates. Once it loops, the fuzzer replays the same mutation choices and re-explores covered code with no signal that this happened.

**Thread-unsafe global state.** `rand()` is spec'd as a single global generator; any concurrent use corrupts the sequence and there's no way to checkpoint or fork it.



#### Actual good PRNG
A good (non-cryptographic of course) PRNG has:

1. **A long period**. The "period" is how many calls before the output stream starts repeating. This is about the length of the sequence. Having a longer period fixes the "stream repeats" problem. Sustained fuzzing campaigns don't loop and silently re-explore covered code.



2. **Full-width output**. Every bit of the return value is uniformly random. A 64-bit return gives you a true 64-bit uniform value, not 15 bits padded with zeros. This fixes the "low resolution" and "unreachable high range" problems: each call yields enough entropy to derive precise Beta samples, full-width `uint16`/`uint32` mutations, and high-precision doubles.



3. **Statistical quality**. The output stream is indistinguishable from true randomness to any statistical test. Measured empirically by passing test batteries: TestU01's BigCrush is the gold standard, throwing dozens of tests at the generator looking for patterns, correlations, or biases. Without this, derived distributions (Beta samples, Gaussian samples, etc.) will silently inherit whatever structural flaws the PRNG has.



4. **Speed**. ~5-10 CPU cycles per call, inlined into the caller. `rand()` on MSVCRT is several times slower due to TLS-backed state and the library call boundary. Matters because the scheduler burns ~1000 PRNG calls per mutation decision; a slow PRNG becomes the bottleneck.



5.  **Seedability**. State can be set explicitly from a known value and checkpointed/restored. The generator becomes a pure function of its seed. Given the same seed, the same stream comes out every time.



6. **Reproducibility (consequence of 5)**. Crashes can be replayed deterministically months later. AFL++'s minimizer and bisection tools rely on the mutator behaving identically across runs (a separate concern from randomness quality). Without this, every fuzzing campaign is an independent experiment whose results can't be reconstructed.

   

   Reproducible crashes are one benefit of owning your PRNG. When AFL++ saves a crashing input, you can extract the seed and replay the mutation that caused the crash, even months later. Impossible with global `rand()`. Replaying would depend on every prior call in the process and the libc.



The family of generators that hits all of these is the xoshiro/xoroshiro family (2018). In the case of mutation operator scheduling in a single-threaded fuzzer that needs a 64-bit uniform, xoroshiro128++ makes the most sense. It has:

- 128-bit state (two `uint64_t`s)
- Period of 2^128 - 1
- one `ROT`, one `XOR`, one `ADD`, one `ROT` for output; a couple more ops for state update
- Passes BigCrush PRNG tests (confirmably indistinguishable from true randomness)

There is no need to use xoshiro256++ over xoroshiro128++, as it would only introduce better headroom for resources we will never exhaust.



### Seeding

xoroshiro128++ has a known degenerate state: if both words of the 128-bit state are zero, the generator emits zero forever. We also want similar seeds to produce dissimilar states. If we seed with `time(null)` in two processes 1s apart, we do not want their outputs to be correlated for the first few million samples.

splitmix64 is a PRNG that solves that. It has trivial state (one `uint64_t` of memory), is a bijection (every 64-bit input maps to a unique 64-bit output), and is specifically designed for seeding other generators. Running a user-supplied 64-bit seed through splitmix64 twice produces two outputs: the xoroshiro128++ state variables.

The probability that splitmix64 produces zero on two consecutive pulls is 2^-128. Astronomically small, essentially never happens. But "essentially never" isn't "never," and the cost of the check is one comparison per program startup. So we check anyway, because a fuzzer that silently outputs zero forever would be the worst possible failure mode: completely deterministic, completely useless, no error message.

```c
// defensive design to prevent [0, 0] state
do{
    xstate[0] = splitmix64_next();
    xstate[1] = splitmix64_next();
} while (xstate[0] == 0 && xstate[1] == 0);
```

splitmix64 is a bijection, meaning it defines perfect 1:1 pairing between input space and output space. Two different input seeds cannot produce the same output. Two adjacent seeds produce two guaranteed distinct splitmix outputs, which become two guaranteed distinct xoroshiro states. The avalanche effect of splitmix64's bijection (one bit flip in input = every output bit has ~50% chance of flipping), produces maximally dissimilar xoroshirostates.

Empirical sequence to follow:

```
user seed (64 bits)
    . splitmix64 state
    . 2 pulls of splitmix64
    . xoroshiro128++ state (128 bits)
    . all further random numbers
```



# group/op scheduler (mutate.c)

We have $K$ arms (mutation operators). Each arm either produces coverage or doesn't. We don't know the probability of any operator producing coverage. The scheduler must determine which arms produce coverage and prioritize them over arms that do not.

This is a Bernoulli bandit problem.

$BernTS(K, \alpha, \beta)$ algorithm:

```
for each round:
    # sample model
    for each arm k:
        sample θ̂_k from Beta(α_k, β_k)
    
    # select and apply action
    pick the arm with the highest θ̂_k
    apply it, observe success or failure
    
    # update distribution
    if success: α_k += 1
    if failure: β_k += 1
```

This specific Thompson Sampling algorithm is used for the scheduler because it is not greedy. Rather than always selecting the operator with the highest estimated mean, it draws a random sample from each operator's Beta distribution and selects the operator whose sample is highest. Because an operator's distribution shape reflects its history, operators with many successes have distributions concentrated near high values, while operators with little data have widely spread distributions. Proven operators win most rounds, but uncertain operators occasionally sample high enough to win. This allows the scheduler to naturally explore underused operators while still favoring ones with proven track records, without needing an explicit exploration parameter.

If the scheduler were to use a greedy algorithm like that of standard AFL, then operator x ($m$ 0.60) would always prevail over operator y ($m$ 0.40) without exploration. Similarly with LibFuzzer, it schedules mutations at random (slightly better than AFL) with no feedback about which operators are productive. MOPT (Optimized Mutation Scheduling) was specially created to solve this problem, but this fuzzer uses it as a fallback rather than a primary design. Thompson Sampling draws a random sample from each operator's Beta distribution, which is what enables exploration of uncertain operators. Thompson Sampling is the scheduler's algorithm of choice because it adapts quicker than MOPT when mutation operator effectiveness changes (coverage saturation will always cause this) and it avoids the local optima that would otherwise be imposed on the scheduler by formerly productive operators.

There's no simple formula to turn a uniform random number into a Beta-distributed random number, meaning we cannot sample from the Beta distribution of each operator directly. To get around this, a formula relating Beta to Gamma is used:

```math
X \sim \Gamma(\alpha), \quad Y \sim \Gamma(\beta) \quad \Rightarrow \quad \frac{X}{X + Y} \sim \text{Beta}(\alpha, \beta)
```

Two independent Gamma samples are drawn and combined. Gamma samples are generated using Marsaglia and Tsang's method (2000), a standard rejection sampling algorithm that transforms uniform random numbers into Gamma-distributed values.
The trick is that if you sample from two Gamma distributions and divide, you get a Beta distribution. Gamma samples can be efficiently generated from uniform random numbers using known algorithms. For this reason, we go through Gamma as an intermediate step to draw samples from the Beta distribution of each operator.