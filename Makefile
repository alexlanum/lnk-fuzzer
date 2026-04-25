# Offline development/debugging only.
# The actual fuzzer build is Windows/CMake against Jackalope —
# this Makefile does not touch that.

CC      = cc
CFLAGS  = -Wall -Wextra -Werror -g -fsanitize=address,undefined
LDFLAGS = -fsanitize=address,undefined

# Core mutator sources. These same files get pulled into the
# Windows fuzzer build via CMake; keep this list in sync.
CORE = serialize.c deserialize.c mutate.c gen.c

# Round-trip sanity check. Run this when the Windows fuzzer
# misbehaves to rule out the C core before blaming Jackalope.
lnk_test: test.c $(CORE)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: lnk_test
	./lnk_test

clean:
	rm -f lnk_test *.o

.PHONY: test clean