// Scheduler state
// Scheduler functions
// Mutation operators
#include "mutate.h"
#include "model.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>

/**
 * Scheduler state — Thompson Sampling
 * Each operator and operator group maintain a Beta distribution
 */

// each group/op is declared static so that mutate_apply and mutate_report can know
// about previous failures/successes and learn from them without clearing per return.
static double group_alpha[GROUP_COUNT];
static double group_beta[GROUP_COUNT];
static double op_alpha[MUTATE_COUNT];
static double op_beta[MUTATE_COUNT];

// designated initializer to map each operator to its group
static MutationOperatorGroup op_to_group[MUTATE_COUNT] = {
    [MUTATE_STRUCTURE_ADD]                      = GROUP_STRUCTURE,
    [MUTATE_STRUCTURE_REMOVE]                   = GROUP_STRUCTURE,
    [MUTATE_STRUCTURE_DESYNC_FLAG]              = GROUP_STRUCTURE,

    [MUTATE_FLAG_SINGLE_BIT]                    = GROUP_FLAGS,
    [MUTATE_FLAG_ALL_SET]                       = GROUP_FLAGS,
    [MUTATE_FLAG_ALL_CLEAR]                     = GROUP_FLAGS,
    [MUTATE_FLAG_RESERVED_BITS]                 = GROUP_FLAGS,
    [MUTATE_FLAG_DESYNC_ISUNICODE]              = GROUP_FLAGS,

    [MUTATE_OFFSET_ZERO]                        = GROUP_OFFSETS,
    [MUTATE_OFFSET_PAST_EOF]                    = GROUP_OFFSETS,
    [MUTATE_OFFSET_OVERLAP]                     = GROUP_OFFSETS,
    [MUTATE_OFFSET_WITHIN_HEADER]               = GROUP_OFFSETS,
    [MUTATE_OFFSET_CHAIN]                       = GROUP_OFFSETS,

    [MUTATE_SIZE_ZERO]                          = GROUP_SIZES,
    [MUTATE_SIZE_UNDERFLOW]                     = GROUP_SIZES,
    [MUTATE_SIZE_DESYNC]                        = GROUP_SIZES,
    [MUTATE_SIZE_BOUNDARY]                      = GROUP_SIZES,

    [MUTATE_PIDL_REORDER_ITEM]                  = GROUP_PIDL,
    [MUTATE_PIDL_INSERT_ITEM]                   = GROUP_PIDL,
    [MUTATE_PIDL_REMOVE_ITEM]                   = GROUP_PIDL,
    [MUTATE_PIDL_DUPLICATE_ITEM]                = GROUP_PIDL,
    [MUTATE_PIDL_PARENT_CHILD_MISMATCH]         = GROUP_PIDL,
    [MUTATE_PIDL_CHAIN_TRUNCATION]              = GROUP_PIDL,
    [MUTATE_PIDL_TOTAL_SIZE_DESYNC]             = GROUP_PIDL,
    [MUTATE_PIDL_CLASS_TYPE]                    = GROUP_PIDL,
    [MUTATE_PIDL_DELEGATE_CLSID]                = GROUP_PIDL,
    [MUTATE_PIDL_MISSING_TERMINAL]              = GROUP_PIDL,
    [MUTATE_PIDL_NONZERO_TERMINAL]              = GROUP_PIDL,
    [MUTATE_PIDL_INNER_CB]                      = GROUP_PIDL,
    [MUTATE_PIDL_DEPTH]                         = GROUP_PIDL,

    [MUTATE_EXTRA_INSERT_BLOCK]                 = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_REMOVE_BLOCK]                 = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_DUPLICATE_BLOCK]              = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_REORDER_BLOCKS]               = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_MISSING_TERMINATOR]           = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_EARLY_TERMINATOR]             = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_DOUBLE_TERMINATOR]            = GROUP_EXTRA_SEQ,

    [MUTATE_BLOCK_SIZE_ZERO]                    = GROUP_EXTRA_HDR,
    [MUTATE_BLOCK_SIZE_UNDERFLOW]               = GROUP_EXTRA_HDR,
    [MUTATE_BLOCK_SIZE_OVERFLOW]                = GROUP_EXTRA_HDR,
    [MUTATE_BLOCK_SIGNATURE_UNKNOWN]            = GROUP_EXTRA_HDR,
    [MUTATE_BLOCK_SIGNATURE_WRONG]              = GROUP_EXTRA_HDR,

    [MUTATE_PROPSTORE_STORAGE_SIZE_ZERO]        = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_STORAGE_SIZE_UNDERFLOW]   = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_STORAGE_SIZE_DESYNC]      = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_STORAGE_SIZE_128MB]       = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_VERSION_WRONG]            = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_FORMAT_ID_RANDOM]         = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_FORMAT_ID_STRING_NAMED]   = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_NAMING_MISMATCH]          = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_DUPLICATE_FORMAT_ID]      = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_MISSING_TERMINATOR]       = GROUP_PROPSTORE_SET,
    [MUTATE_PROPSTORE_EARLY_TERMINATOR]         = GROUP_PROPSTORE_SET,

    [MUTATE_PROPSTORE_VALUE_SIZE_ZERO]          = GROUP_PROPSTORE_VAL,
    [MUTATE_PROPSTORE_VALUE_SIZE_UNDERFLOW]     = GROUP_PROPSTORE_VAL,
    [MUTATE_PROPSTORE_VALUE_SIZE_DESYNC]        = GROUP_PROPSTORE_VAL,
    [MUTATE_PROPSTORE_DUPLICATE_PID]            = GROUP_PROPSTORE_VAL,
    [MUTATE_PROPSTORE_RESERVED_NONZERO]         = GROUP_PROPSTORE_VAL,
    [MUTATE_PROPSTORE_MISSING_VALUE_TERMINATOR] = GROUP_PROPSTORE_VAL,

    [MUTATE_PROPSTORE_VT_INVALID]               = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_VT_BYREF]                 = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_VT_VECTOR]                = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_VT_STREAM]                = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_VT_VARIANT]               = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_VT_RESERVED]              = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_PADDING_NONZERO]          = GROUP_PROPSTORE_TPV,
    [MUTATE_PROPSTORE_FORCE_MISALIGN]           = GROUP_PROPSTORE_TPV,

    [MUTATE_DARWIN_FORMAT_STRING]               = GROUP_DARWIN,
    [MUTATE_DARWIN_OVERLONG]                    = GROUP_DARWIN,
    [MUTATE_DARWIN_INVALID_GUID]                = GROUP_DARWIN,
    [MUTATE_DARWIN_NULL_BYTES]                  = GROUP_DARWIN,
    [MUTATE_DARWIN_RANDOM]                      = GROUP_DARWIN,

    [MUTATE_TRACKER_LENGTH_WRONG]               = GROUP_TRACKER,
    [MUTATE_TRACKER_VERSION_NONZERO]            = GROUP_TRACKER,
    [MUTATE_TRACKER_DROID_CORRUPT]              = GROUP_TRACKER,
    [MUTATE_TRACKER_MACHINE_ID_CORRUPT]         = GROUP_TRACKER,

    [MUTATE_KNOWNFOLDER_GUID_UNKNOWN]           = GROUP_KNOWNFOLDER,
    [MUTATE_KNOWNFOLDER_GUID_ZERO]              = GROUP_KNOWNFOLDER,
    [MUTATE_KNOWNFOLDER_OFFSET_OOB]             = GROUP_KNOWNFOLDER,

    [MUTATE_FILE_TRUNCATE]                      = GROUP_FILE,
    [MUTATE_FILE_APPEND_GARBAGE]                = GROUP_FILE,
    [MUTATE_FILE_SECTION_OVERLAP]               = GROUP_FILE,
};

/**
 * Scheduler infrastructure functions
 */

// convert uniform random numbers into Gamma-distributed ones (produce Gamma samples)
static double sample_gamma(double shape){    
    if(shape < 1.0){
        // unlikely that this will trigger
        // Gamma(shape) = Gamma(shape + 1) * U^(1 / shape)
        double u = (double)rand() / RAND_MAX;
        return sample_gamma(shape + 1.0) * pow(u, 1.0 / shape);
    }

    // Marsaglia and Tsang method for shape >= 1
    double d = shape = 1.0/3.0;
    double c = 1.0 / sqrt(9.0 * d);
    while(1){
        double x, v;
        do{
            // generate standard normal using Box-Muller
            double u1 = (double)rand() / RAND_MAX;
            double u2 = (double)rand() / RAND_MAX;
            x = sqrt(-2.0 * log(u1)) * cos(2.0 * 3.14159265358979 * u2);
            v = 1.0 + c * x;
        } while (v <= 0.0);
        v = v * v * v;
        double u = (double)rand() / RAND_MAX;
        if (u < 1.0 - 0.0331 * (x * x) * (x*x)) return d * v;
        if (log(u) < 0.5*x*x + d * (1.0 - v + log(v))) return d * v;
    }
}

// produce Beta samples (Beta = Gamma/Gamma)
static double sample_beta(double a, double b){
    double x = sample_gamma(a); // x = Gamma(alpha)
    double y = sample_gamma(b); // y = Gamma(beta)
    return x / (x + y); // Beta = x / (x + y)
}

static MutationOperator mutate_apply(LNKGeneratorState* state, LNKLayout* layout){
    
    // Lvl 1: Mutation operator group
    // for k = 1..K, sample θ̂_k ~ Beta(α_k, β_k)
    // in this case, K = groups, not individual operators
    double best = -1.0;
    MutationOperatorGroup group = 0;
    for(int g = 0; g < GROUP_COUNT; g++){
        double theta = sample_beta(group_alpha[g], group_beta[g]);
        if(theta > best){
            best = theta;
            group = g;
        }
    }
    // x_t = argmax_k θ̂_k
    // meaning the group with the highest sample wins

}


/**
 * Operators
 */