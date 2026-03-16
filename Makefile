#
# Rerun bear -- make test whenever you add a new .c file
# to the Makefile so compile_commands.json stays current.
#
CC = cc
CFLAGS = -Wall -Wextra -Werror -g -fsanitize=address,undefined
LDFLAGS = -fsanitize=address,undefined

# Offline test binary
lnk_test: test.c gen.c serialize.c deserialize.c mutate.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# AFL++ custom mutator shared library
mutator.so: mutator.c gen.c serialize.c deserialize.c mutate.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $^ $(LDFLAGS)

# # Target harness
# harness: harness.c
# 	afl-clang-fast $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: lnk_test
	./lnk_test

clean:
	rm -f lnk_test mutator.so harness

.PHONY: test clean