# AFL Custom Mutators

The custom mutator API is how you replace AFL++'s dumb fuzzing style mutator with your own smart one. You provide AFL++ with a shared library exposing specific function names. AFL++ calls your functions at specific points in its main loop. Your functions produce mutated bytes using their own strategy.



You:

- Write a `.c` file with functions named *exactly* `afl_custom_init`, `afl_custom_fuzz`, etc.
- Compile that `.c` file into a `.so` shared library
- Launch `./afl-fuzz` with `AFL_CUSTOM_MUTATOR_LIBRARY=./your.so`

AFL:

- Loads your `.so` into the `./afl-fuzz` process memory
- Finds your functions by name (`dlsym`)
- Calls `afl_custom_init` once at startup
- Calls `afl_custom_fuzz` millions of times during fuzzing in a loop
- Runs the target with the bytes that `afl_custom_fuzz` returned
- Checks if the target crashed or hit new coverage
- Calls `afl_custom_queue_new_entry` when you produced new coverage
- Calls `afl_custom_deinit` at shutdown



The functions you write MUST match AFL's required names (ex. `afl_custom_init`).

The functions you write MUST match the AFL ABI's required signature (parameter types, return type)

Inside the function body, you write whatever C code accomplishes the contract.

For example, the contract for `afl_custom_fuzz` is:

- NAME: `afl_custom_fuzz`

- SIGNATURE:

  ```c
  size_t afl_custom_fuzz(void* data, uint8_t* buf,
                         size_t buf_size, uint8_t** out_buf,
                         uint8_t* add_buf, size_t add_buf_size,
                         size_t max_size);
  ```

- CONTRACT: Given the seed bytes in `buf`, produce mutated bytes, write their address to `*out_buf`, return their length.

AFL does not care *how* you produce mutated bytes; you can do whatever you want inside the body to achieve mutation. AFL just receives the bytes you return and runs the target on them.

For the LNK fuzzer, `afl_custom_fuzz`:

```c
size_t afl_custom_fuzz(
	lnk_mutator_t* mutator, // void* data
    uint8_t* buf,			// uint8_t* buf
    size_t buf_size,		// size_t buf_size
    uint8_t** out_buf,		// uint8_t** out_buf
    uint8_t* add_buf,		// uint8_t* add_buf
    size_t add_buf_size,  	// size_t add_buf_size,
    size_t max_size			// size_t max_size
){
    // 1. parse the seed bytes into LNKGeneratorState (deserialize them)
    deserialize_lnk(buf, buf_size, &mutator->state);
    
    // 2. run Thompson Sampling scheduler to pick and apply an operator
    LNKLayout layout = mutate_extract_layout(&mutator->state); // extract deserialized state layout
    MutationOperator op = mutate_apply(&mutator->state, &layout);
    mutator->last_op = op; // feedback: op applied by previous afl_custom_fuzz call
    
    // 3. convert the mutated LNKGeneratorState back to bytes (serialize it)
    size_t out_len = 0;
    serialize_lnk(mutator->out_buf, mutator->out_cap, &out_len, &mutator->state);

    // 4. give the bytes back to AFL
    *out_buf = mutator->out_buf;
    return out_len
}
```

After your `afl_custom_fuzz` returns the mutated bytes to AFL, AFL gives the bytes to the target (harness exe) as input, runs it, and checks coverage after the run. Then it calls `afl_custom_fuzz` again, usually with the same seed entry, expecting your mutator to produce a *different* mutation this time. After it finishes its assigned thousands of iterations on that seed, AFL moves onto a different queue entry. This repeats millions of times throughout the fuzzing campaign.