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

// check if an operator is valid for this input by ensuring satisfaction of required preconditions
static int op_precondition(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    switch(op){
        case MUTATE_FLAG_SINGLE_BIT:
        case MUTATE_FLAG_ALL_SET:
        case MUTATE_FLAG_ALL_CLEAR:
        case MUTATE_FLAG_RESERVED_BITS:
        case MUTATE_FLAG_DESYNC_ISUNICODE:
            return 1; // no precondition, header always exists
        
        case MUTATE_PIDL_INSERT_ITEM:
        case MUTATE_PIDL_DEPTH:
            return layout->has_link_target_idlist; // item_count < 0 allowed bc these add items, the rest need something already there
        case MUTATE_PIDL_CLASS_TYPE:
        case MUTATE_PIDL_REORDER_ITEM:
        case MUTATE_PIDL_REMOVE_ITEM:
        case MUTATE_PIDL_DUPLICATE_ITEM:
        case MUTATE_PIDL_PARENT_CHILD_MISMATCH:
        case MUTATE_PIDL_CHAIN_TRUNCATION:
        case MUTATE_PIDL_TOTAL_SIZE_DESYNC:
        case MUTATE_PIDL_DELEGATE_CLSID:
        case MUTATE_PIDL_MISSING_TERMINAL:
        case MUTATE_PIDL_NONZERO_TERMINAL:
        case MUTATE_PIDL_INNER_CB:
            return layout->has_link_target_idlist && state->linktargetidlist.item_count > 0;

        // add more as i go ...

        default:
            return 0; // not implemented
    }
}

// GROUP_FLAGS (LinkFlags) mutation operators
static void apply_flags(MutationOperator op, LNKGeneratorState* state){
    switch(op){
        case MUTATE_FLAG_SINGLE_BIT:{
            int rndm_bit = rand() % 32; // pick a random bit 0-31 to toggle inside link_flags
            state->header.link_flags ^= (1u << rndm_bit); // shift by that many bits and set it
            break;
        }

        case MUTATE_FLAG_ALL_SET:{
            // forces the presence of every optional section
            state->header.link_flags = 0xFFFFFFFF;
            break;
        }

        case MUTATE_FLAG_ALL_CLEAR:{
            // no sections present, but file still has data after header
            // parser expects nothing but finds bytes
            state->header.link_flags = 0x00000000;
            break;
        }

        case MUTATE_FLAG_RESERVED_BITS:{
            // bits 27-31 are unused/reserved
            int mode = rand() % 3;
            if(mode == 0){
                // force set a reserved bit
                int rndm_bit = 27 + (rand() % 5);
                state->header.link_flags |= (1u << rndm_bit);
            } else if(mode == 1){
                // flip
                int rndm_bit = 27 + (rand() % 5);
                state->header.link_flags ^= (1u << rndm_bit);
            } else{
                // overwrite all reserved bits
                state->header.link_flags &= ~0xF8000000;
                state->header.link_flags |= ((rand() & 0x1F) << 27); // shift results in any 5-bit pattern, maximum exploration
            }
            break;
        }

        case MUTATE_FLAG_DESYNC_ISUNICODE:{
            // flip bit 7 (IsUnicode) to make the parser interpret data wrong
            // RE revealed that IsUnicode flows directly into string parsing, no independent validation.
            state->header.link_flags ^= 0x00000080;
            break;
        }

        default: break;
    }
}

// GROUP_SIZES mutation operators
static void apply_sizes(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    uint32_t boundaries[] = {
        0, 1, 2, 3, 4, 0x0F, 0x10, 0x13, 0x14,
        0x1B, 0x1C, 0x23, 0x24, 0xFFFF, 0x10000,
        0x7FFFFFFF, 0xFFFFFFFF
    };

    int bcount = sizeof(boundaries) / sizeof(boundaries[0]);

    switch(op){
        case MUTATE_SIZE_ZERO:{
            // ...
        }

        case MUTATE_SIZE_UNDERFLOW:{
            // smaller than minimum valid
        }

        case MUTATE_SIZE_DESYNC:{
            // size field inconsistent with actual content
        }

        case MUTATE_SIZE_BOUNDARY:{
            uint32_t val = boundaries[rand() % bcount];
            int av = rand() % 4;
            if(av == 0)
                state->linkinfo.link_info_size = val;
            /*
             * LinkInfoSize < 4               . allocation skipped
             * LinkInfoSize >= 4 but < 0x1C   . allocated, fails IsValidLinkInfo
             * LinkInfoSize >= 0x1C           . passes header check, deeper validation
             * VolumeIDSize < 0x10            . fails VolumeID check
             * VolumeIDSize > remaining       . fails bounds check
             */
        }
        default: break;
    }
}

// GROUP_PIDL (LinkTargetIDList) mutation operators
static void apply_pidl(MutationOperator op, LNKGeneratorState* state){

}

// do mutation
static void op_apply(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    switch(op_to_group[op]){
        case GROUP_FLAGS: apply_flags(op, state);         break;
        case GROUP_SIZES: apply_sizes(op, state, layout); break;
        case GROUP_PIDL:  apply_pidl(op, state);          break;
        
        // add more...

        default: break;
    }
}

MutationOperator mutate_apply(LNKGeneratorState* state, LNKLayout* layout){
    // Lvl 1: Select a group using Thompson Sampling
    // for k = 1..K, sample θ̂_k ~ Beta(α_k, β_k)
    // K = groups
    double best_score = -1.0;
    MutationOperatorGroup chosen_group = 0;
    for(int g = 0; g < GROUP_COUNT; g++){
        double theta = sample_beta(group_alpha[g], group_beta[g]);
        if(theta > best_score){
            best_score = theta;
            chosen_group = g;
        }
    }
    
    // Lvl 2: Collect valid operators within the group
    MutationOperator candidates[MUTATE_COUNT];
    int count = 0;
    for(int op = 0; op < MUTATE_COUNT; op++){
        if(op_to_group[op] != chosen_group) continue;
        if(!op_precondition(op, state, layout)) continue;
        candidates[count++] = op;
    }

    if(count == 0){
        // no valid operators in this group, use a random valid operator
        for(int op = 0; op < MUTATE_COUNT; op++){
            if(op_precondition(op, state, layout)) continue;
            candidates[count++] = op;
        }
    }

    if(count == 0) return -1; // nothing applicable

    // Thompson sample among candidates
    // K = individual operators
    best_score = -1.0;
    MutationOperator chosen_op = candidates[0];
    for(int i = 0; i < count; i++){
        double s = sample_beta(op_alpha[candidates[i]], op_beta[candidates[i]]);
        if(s > best_score){
            best_score = s;
            chosen_op = candidates[i];
        }
    }

    // apply mutation
    op_apply(chosen_op, state, layout);

    return chosen_op;
}


/**
 * Operators
 */