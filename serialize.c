// 1. AFL++ gives raw bytes (seed)
// 2. seed bytes are deserialized (parsed into an LNKGeneratorState struct)
// 3. LNKGeneratorState struct is mutated
// 4. mutated LNKGeneratorState struct is serialized (converted back to bytes)
// 5. AFL++ feeds those bytes to the target
// serialize.c enables the mutator to feed AFL++ its output

#include "model.h"
#include <string.h>
#include <stdlib.h>