// Scheduler state
// Scheduler functions
// Mutation operators
#include "mutate.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/**
 * Scheduler state — Thompson Sampling
 * Each operator has alpha/beta for its Beta distribution.
 * Each group has alpha/beta too (hierarchical selection).
 */