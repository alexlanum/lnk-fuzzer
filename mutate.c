// Scheduler state
// Scheduler functions
// Mutation operators
#include "mutate.h"
#include "lnk_prng.h"
#include "model.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "clsids.h"

/**
 * Mutex protecting the shared scheduler arrays.
 * CRITICAL_SECTION is the fast in-proc mutex on Windows
 * (~50-100 ns per lock/unlock pair, no kernel transition
 * for the uncontended case). This matches Jackalope's
 * mutex.h pattern. See usage in mutate_apply / mutate_report.
 */
#if defined(_WIN32) || defined(WIN32) || defined(__WIN32)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    static CRITICAL_SECTION scheduler_mutex;
    static inline void scheduler_lock(void)   { EnterCriticalSection(&scheduler_mutex); }
    static inline void scheduler_unlock(void) { LeaveCriticalSection(&scheduler_mutex); }
#else
    #include <pthread.h>
    static pthread_mutex_t scheduler_mutex = PTHREAD_MUTEX_INITIALIZER;
    static inline void scheduler_lock(void)   { pthread_mutex_lock(&scheduler_mutex); }
    static inline void scheduler_unlock(void) { pthread_mutex_unlock(&scheduler_mutex); }
#endif

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
    [MUTATE_PIDL_INJECT_CLSID]                  = GROUP_PIDL,
    [MUTATE_PIDL_MISSING_TERMINAL]              = GROUP_PIDL,
    [MUTATE_PIDL_NONZERO_TERMINAL]              = GROUP_PIDL,
    [MUTATE_PIDL_DELEGATEITEMID]                = GROUP_PIDL,
    [MUTATE_PIDL_DEPTH]                         = GROUP_PIDL,

    [MUTATE_EXTRA_INSERT_BLOCK]                 = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_REMOVE_BLOCK]                 = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_DUPLICATE_BLOCK]              = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_REORDER_BLOCKS]               = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_MISSING_TERMINATOR]           = GROUP_EXTRA_SEQ,
    [MUTATE_EXTRA_EARLY_TERMINATOR]             = GROUP_EXTRA_SEQ,

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

    [MUTATE_SPECIALFOLDER_CSIDL]                = GROUP_SPECIALFOLDER,
    [MUTATE_SPECIALFOLDER_RANDOM]               = GROUP_SPECIALFOLDER,
    [MUTATE_SPECIALFOLDER_OFFSET]               = GROUP_SPECIALFOLDER,
    [MUTATE_SPECIALFOLDER_INJECT]               = GROUP_SPECIALFOLDER,

    [MUTATE_FILE_TRUNCATE]                      = GROUP_FILE,
    [MUTATE_FILE_APPEND_GARBAGE]                = GROUP_FILE,
    [MUTATE_FILE_SECTION_OVERLAP]               = GROUP_FILE,
};

// convert uniform random numbers into Gamma-distributed ones (produce Gamma samples)
static double sample_gamma(LNKRand* rng, double shape){
    if(shape < 1.0){
        // unlikely that this will trigger
        // Gamma(shape) = Gamma(shape + 1) * U^(1 / shape)
        double u = lnk_rand_double(rng);
        return sample_gamma(rng, shape + 1.0) * pow(u, 1.0 / shape);
    }

    // Marsaglia and Tsang method for shape >= 1
    double d = shape - 1.0/3.0; // shape - 1/3: shifted mean of the distribution
    double c = 1.0 / sqrt(9.0 * d);
    while(1){
        double x, v;
        do{
            double u1, u2;
            do{
                u1 = lnk_rand_double(rng);
            } while (u1 == 0.0);
            u2 = lnk_rand_double(rng);
            x = sqrt(-2.0 * log(u1)) * cos(2.0 * 3.14159265358979 * u2);
            v = 1.0 + c * x;
        } while (v <= 0.0);
        
        v = v * v * v;
        
        double u = lnk_rand_double(rng);
        if(u < 1.0 - 0.0331 * (x * x) * (x*x))
            return d * v;
        if(log(u) < 0.5*x*x + d * (1.0 - v + log(v)))
            return d * v;
    }
}

// produce Beta samples (Beta = Gamma/Gamma)
static double sample_beta(LNKRand* rng, double a, double b){
    double x = sample_gamma(rng, a); // x = Gamma(alpha)
    double y = sample_gamma(rng, b); // y = Gamma(beta)
    return x / (x + y); // Beta = x / (x + y)
}

// true if the propstore has at least one value across all its storages
static int propstore_has_any_value(SerializedPropertyStore* ps){
    for(int i = 0; i < ps->storage_count; i++)
        if(ps->storages[i].value_count > 0)
            return 1;
    return 0;
}

// true if at least one storage has >= 2 values (needed for DUPLICATE_PID)
static int propstore_storage_has_2plus_vals(SerializedPropertyStore* ps){
    for(int i = 0; i < ps->storage_count; i++)
        if(ps->storages[i].value_count >= 2)
            return 1;
    return 0;
}

// check if an operator is valid for this input by ensuring satisfaction of required preconditions
static int op_precondition(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    switch(op){
        // GROUP_STRUCTURE: no precondition. all ops touch header.link_flags, which always exists.
        case MUTATE_STRUCTURE_ADD:
        case MUTATE_STRUCTURE_REMOVE:
        case MUTATE_STRUCTURE_DESYNC_FLAG:
            return 1;

        // GROUP_FLAGS: no precondition. all ops touch header.link_flags, which always exists.
        case MUTATE_FLAG_SINGLE_BIT:
        case MUTATE_FLAG_ALL_SET:
        case MUTATE_FLAG_ALL_CLEAR:
        case MUTATE_FLAG_RESERVED_BITS:
        case MUTATE_FLAG_DESYNC_ISUNICODE:
            return 1;
        
        // GROUP_SIZES: needs at least one section with a size field that can be targeted.
        // apply_sizes() has its own runtime fallback (returns if tcount == 0 (no targets)).
        // checking this lets the scheduler skip picking this op entirely when nothing is valid.
        case MUTATE_SIZE_ZERO:
        case MUTATE_SIZE_UNDERFLOW:
        case MUTATE_SIZE_DESYNC:
        case MUTATE_SIZE_BOUNDARY:
            return layout->has_link_target_idlist
                || layout->has_linkinfo
                || (layout->has_extradata && state->extradata.block_count > 0)
                || layout->has_propstore_block;

        // GROUP_PIDL: need at least the PIDL structure
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
        case MUTATE_PIDL_INJECT_CLSID:
        case MUTATE_PIDL_MISSING_TERMINAL:
        case MUTATE_PIDL_NONZERO_TERMINAL:
        case MUTATE_PIDL_DELEGATEITEMID:
            return layout->has_link_target_idlist && state->linktargetidlist.item_count > 0;

        // GROUP_OFFSETS
        case MUTATE_OFFSET_ZERO:
        case MUTATE_OFFSET_PAST_EOF:
        case MUTATE_OFFSET_OVERLAP:
        case MUTATE_OFFSET_WITHIN_HEADER:
        case MUTATE_OFFSET_CHAIN:
            return layout->has_linkinfo || layout->has_knownfolder_block; // at least one offset field must be present to target

        // GROUP_EXTRA_SEQ: ExtraData block list level operators
        // INSERT adds a block, so an empty list is fine as long as there's room.
        // all others need at least one existing block to operate on.
        case MUTATE_EXTRA_INSERT_BLOCK:
            return layout->has_extradata && state->extradata.block_count < MAX_EXTRA_DATA_BLOCKS;
        case MUTATE_EXTRA_REMOVE_BLOCK:
        case MUTATE_EXTRA_DUPLICATE_BLOCK:
        case MUTATE_EXTRA_MISSING_TERMINATOR:
        case MUTATE_EXTRA_EARLY_TERMINATOR:
            return layout->has_extradata && state->extradata.block_count > 0;
        case MUTATE_EXTRA_REORDER_BLOCKS:
            // reorder needs >= 2 blocks or its a NOP
            return layout->has_extradata && state->extradata.block_count >= 2;

        // GROUP_EXTRA_HDR: corrupt individual block headers, needs >= 1 block
        case MUTATE_BLOCK_SIZE_ZERO:
        case MUTATE_BLOCK_SIZE_UNDERFLOW:
        case MUTATE_BLOCK_SIZE_OVERFLOW:
        case MUTATE_BLOCK_SIGNATURE_UNKNOWN:
        case MUTATE_BLOCK_SIGNATURE_WRONG:
            return layout->has_extradata && state->extradata.block_count > 0;

        // GROUP_PROPSTORE_SET: storage level operators, need PropertyStoreDataBlock
        // and at least one storage to operate on
        case MUTATE_PROPSTORE_STORAGE_SIZE_ZERO:
        case MUTATE_PROPSTORE_STORAGE_SIZE_UNDERFLOW:
        case MUTATE_PROPSTORE_STORAGE_SIZE_DESYNC:
        case MUTATE_PROPSTORE_STORAGE_SIZE_128MB:
        case MUTATE_PROPSTORE_VERSION_WRONG:
        case MUTATE_PROPSTORE_FORMAT_ID_RANDOM:
        case MUTATE_PROPSTORE_FORMAT_ID_STRING_NAMED:
        case MUTATE_PROPSTORE_NAMING_MISMATCH:
        case MUTATE_PROPSTORE_MISSING_TERMINATOR:
            return layout->has_propstore_block && state->propstore.storage_count > 0;
        case MUTATE_PROPSTORE_DUPLICATE_FORMAT_ID:
        case MUTATE_PROPSTORE_EARLY_TERMINATOR:
            // need >= 2 storages. duplicate needs another in order to copy the FMTID into.
            // EARLY_TERMINATOR places the terminator before the last storage
            return layout->has_propstore_block && state->propstore.storage_count >= 2;
        
        // GROUP_PROPSTORE_VAL: value level operators, need >= 1 storage with >= 1 value
        case MUTATE_PROPSTORE_VALUE_SIZE_ZERO:
        case MUTATE_PROPSTORE_VALUE_SIZE_UNDERFLOW:
        case MUTATE_PROPSTORE_VALUE_SIZE_DESYNC:
        case MUTATE_PROPSTORE_RESERVED_NONZERO:
        case MUTATE_PROPSTORE_MISSING_VALUE_TERMINATOR:
            return layout->has_propstore_block
                && state->propstore.storage_count > 0
                && propstore_has_any_value(&state->propstore);
        case MUTATE_PROPSTORE_DUPLICATE_PID:
            // need a s torage with >= 2 values so one PID can dupe another's
            return layout->has_propstore_block
                && propstore_storage_has_2plus_vals(&state->propstore);

        // GROUP_PROPSTORE_TPV: TypedPropertyValue operators, need >= 1 value
        case MUTATE_PROPSTORE_VT_INVALID:
        case MUTATE_PROPSTORE_VT_BYREF:
        case MUTATE_PROPSTORE_VT_VECTOR:
        case MUTATE_PROPSTORE_VT_STREAM:
        case MUTATE_PROPSTORE_VT_VARIANT:
        case MUTATE_PROPSTORE_VT_RESERVED:
        case MUTATE_PROPSTORE_PADDING_NONZERO:
        case MUTATE_PROPSTORE_FORCE_MISALIGN:
            return layout->has_propstore_block
                && state->propstore.storage_count > 0
                && propstore_has_any_value(&state->propstore);
        
        // GROUP_DARWIN: needs DarwinDataBlock
        case MUTATE_DARWIN_FORMAT_STRING:
        case MUTATE_DARWIN_OVERLONG:
        case MUTATE_DARWIN_INVALID_GUID:
        case MUTATE_DARWIN_NULL_BYTES:
        case MUTATE_DARWIN_RANDOM:
            return layout->has_darwin_block;

        // GROUP_TRACKER: needs TrackerDataBlock
        case MUTATE_TRACKER_LENGTH_WRONG:
        case MUTATE_TRACKER_VERSION_NONZERO:
        case MUTATE_TRACKER_DROID_CORRUPT:
        case MUTATE_TRACKER_MACHINE_ID_CORRUPT:
            return layout->has_tracker_block;

        // GROUP_SPECIALFOLDER: INJECT needs SpecialFolderDataBlock absent (it adds one);
        // the rest need SpecialFolderDataBlock present
        case MUTATE_SPECIALFOLDER_INJECT:
            return !layout->has_specialfolder_block
                && state->extradata.block_count < MAX_EXTRA_DATA_BLOCKS;
        case MUTATE_SPECIALFOLDER_CSIDL:
        case MUTATE_SPECIALFOLDER_RANDOM:
        case MUTATE_SPECIALFOLDER_OFFSET:
            return layout->has_specialfolder_block;

        // GROUP_KNOWNFOLDER
        case MUTATE_KNOWNFOLDER_GUID_UNKNOWN:
        case MUTATE_KNOWNFOLDER_GUID_ZERO:
        case MUTATE_KNOWNFOLDER_OFFSET_OOB:
            return layout->has_knownfolder_block;

        // GROUP_FILE: always valid. these operate on the serialized byte buffer,
        // which always exists after serialize() runs.
        case MUTATE_FILE_TRUNCATE:
        case MUTATE_FILE_APPEND_GARBAGE:
        case MUTATE_FILE_SECTION_OVERLAP:
            return 1;

        default:
            return 0; // not implemented
    }
}

// all ExtraData blocks use the same approach: call find_extra_block -> work on block->data directly at known offsets
static ExtraDataBlock* find_extra_block(ExtraDataState* extra, ExtraDataType type){
    for(int i = 0; i < extra->block_count; i++)
        if(extra->blocks[i].type == type)
            return &extra->blocks[i];
    return NULL;
}

// ensures an ExtraData block does not exist in order to mismatch with LinkFlags
static void remove_extra_block(ExtraDataState* extra, ExtraDataType type){
    for(int i = 0; i < extra->block_count; i++){
        if(extra->blocks[i].type == type){
            free(extra->blocks[i].data);
            for(int j = i; j < extra->block_count - 1; j++)
                extra->blocks[j] = extra->blocks[j + 1];
            extra->block_count--;
            return;
        }
    }
}

// GROUP_STRUCTURE
static void apply_structure(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    uint32_t flags[] = {
        0x00000001, // HasLinkTargetIDList
        0x00000002, // HasLinkInfo
        0x00000004, // HasName
        0x00000008, // HasRelativePath
        0x00000010, // HasWorkingDir
        0x00000020, // HasArguments
        0x00000040, // HasIconLocation
        0x00001000, // HasDarwinID
        0x02000000, // PreferEnvironmentPath
    };

    switch(op){
        case MUTATE_STRUCTURE_ADD:{
            // enable a section flag for a section that does not exist
            // parser expects data that is not there
            state->header.link_flags |= flags[lnk_rand(rng) % 9];
            break;
        }

        case MUTATE_STRUCTURE_REMOVE:{
            // disable a section flag for a section that does not exist
            // parser skips the section but the bytes are still in the file
            // subsequent sections will be read from the wrong offset
            state->header.link_flags &= ~flags[lnk_rand(rng) % 9];
            break;
        }

        case MUTATE_STRUCTURE_DESYNC_FLAG:{
            // set contradictory or orphan flags simultaneously
            int r = lnk_rand(rng) % 100;
            if(r < 40){
                // HasLinkInfo + ForceNoLinkInfo
                // parser reads and deserializes LinkInfo entirely, then frees it.
                // it is parsed before the discard. any bug in LinkInfo_LoadFromStream
                // is reachable through this path even though the result gets freed.
                state->header.link_flags |= 0x02;  // set HasLinkInfo
                state->header.link_flags |= 0x100; // set ForceNoLinkInfo
            } else if(r < 60){
                // HasDarwinID (LinkFlags bit 0x1000) without DarwinDataBlock in ExtraData
                // _LoadFromStream calls SHFindDataBlock(0xA0000006) which returns NULL
                // tests null check on the result
                state->header.link_flags |= 0x1000;
                remove_extra_block(&state->extradata, EXTRA_DARWIN);
            } else if(r < 75){
                // PreferEnvironmentPath without EnvironmentVariableDataBlock
                // resolution prefers env path but block is missing
                state->header.link_flags |= 0x2000000;
                remove_extra_block(&state->extradata, EXTRA_ENVIRONMENT);
            } else if(r < 85){
                // HasExpString without EnvironmentVariableDataBlock
                state->header.link_flags |= 0x200;
                remove_extra_block(&state->extradata, EXTRA_ENVIRONMENT);
            } else if(r < 95){
                // HasExpIcon without IconEnvironmentDataBlock
                state->header.link_flags |= 0x4000;
                remove_extra_block(&state->extradata, EXTRA_ICON_ENVIRONMENT);
            } else{
                // RunWithShimLayer without ShimDataBlock
                state->header.link_flags |= 0x20000;
                remove_extra_block(&state->extradata, EXTRA_SHIM);
            }
            break;
        }

        default:
            break;
    }
}

// GROUP_FLAGS (LinkFlags) mutation operators
static void apply_flags(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    switch(op){
        case MUTATE_FLAG_SINGLE_BIT:{
            int rndm_bit = lnk_rand(rng) % 32; // pick a random bit 0-31 to toggle inside link_flags
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
            int mode = lnk_rand(rng) % 3;
            if(mode == 0){
                // force set a reserved bit
                int rndm_bit = 27 + (lnk_rand(rng) % 5);
                state->header.link_flags |= (1u << rndm_bit);
            } else if(mode == 1){
                // flip
                int rndm_bit = 27 + (lnk_rand(rng) % 5);
                state->header.link_flags ^= (1u << rndm_bit);
            } else{
                // overwrite all reserved bits
                state->header.link_flags &= ~0xF8000000;
                state->header.link_flags |= ((lnk_rand(rng) & 0x1F) << 27); // shift results in any 5-bit pattern, maximum exploration
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

// GROUP_SIZES mutation operators, multiple fields targeted
static void apply_sizes(LNKRand* rng, MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    uint32_t boundaries[] = {
        0, 1, 2, 3, 4, 0x0F, 0x10, 0x13, 0x14,
        0x1B, 0x1C, 0x23, 0x24, 0xFFFF, 0x10000,
        0x7FFFFFFF, 0xFFFFFFFF
    };
    
    int bcount = sizeof(boundaries) / sizeof(boundaries[0]);

    // valid targets
    enum{
        T_IDLIST,
        T_LINKINFO,
        T_VOLUMEID,
        T_CNRL,
        T_EXTRA,
        T_PROPSTORE_STOR,
        T_PROPSTORE_VAL,
        T_COUNT
    };
    int targets[T_COUNT];
    int tcount = 0;

    if(layout->has_link_target_idlist) targets[tcount++]                                           = T_IDLIST;
    if(layout->has_linkinfo) targets[tcount++]                                                     = T_LINKINFO;
    if(layout->has_linkinfo && state->linkinfo.has_volume_id) targets[tcount++]                    = T_VOLUMEID;
    if(layout->has_linkinfo && state->linkinfo.has_common_network_relative_link) targets[tcount++] = T_CNRL;
    if(layout->has_extradata && state->extradata.block_count > 0) targets[tcount++]                = T_EXTRA;
    if(layout->has_propstore_block) targets[tcount++]                                              = T_PROPSTORE_STOR;
    if(layout->has_propstore_block)targets[tcount++]                                               = T_PROPSTORE_VAL;

    if(tcount == 0) return;
    int t = targets[lnk_rand(rng) % tcount]; // choose a random valid field to mutate

    switch(op){
        case MUTATE_SIZE_ZERO:{
            switch(t){
                case T_IDLIST:
                    // total_size controls IDList allocation in ILCreate
                    // IDListContainerIsConsistent check fail: parser continues with a failed PIDL
                    state->linktargetidlist.total_size = 0;
                    break;
                case T_LINKINFO:
                    // LinkInfoSize < 4: allocation is skipped in LinkInfo_LoadFromStream
                    state->linkinfo.link_info_size = 0;
                    break;
                case T_VOLUMEID:
                    // VolumeIDSize < 0x10: fails VolumeID check in IsValidLinkInfo
                    state->linkinfo.volume_id.volume_id_size = 0;
                    break;
                case T_CNRL:
                    // CNRL size < 0x14: early rejection, tests err path handling
                    state->linkinfo.common_network_relative_link.common_network_relative_link_size = 0;
                    break;
                case T_EXTRA:
                    // BlockSize < header size
                    state->extradata.blocks[lnk_rand(rng) % state->extradata.block_count].size = 0;
                    break;
                case T_PROPSTORE_STOR:
                    // storage_size = 0: terminates chunk walk early (while(chunkSize != 0))
                    for(int i = 0; i < state->extradata.block_count; i++)
                        if(state->extradata.blocks[i].type == EXTRA_PROPERTY_STORE && state->extradata.blocks[i].data)
                            memset(state->extradata.blocks[i].data, 0, 4);
                    break;
                case T_PROPSTORE_VAL:
                    // value_size = 0: terminates serialized value walk (while(*(ULONG*)prop != 0))
                    for(int i = 0; i < state->extradata.block_count; i++)
                        if(state->extradata.blocks[i].type == EXTRA_PROPERTY_STORE && state->extradata.blocks[i].data){
                            uint32_t payload_len = state->extradata.blocks[i].size - 8;
                            if(payload_len > 28) // ensure bytes 24-27 exist before writing
                                memset(state->extradata.blocks[i].data + 24, 0, 4); // offset 24 is value_size
                            break;
                        }
                    break;
                default:
                    break;
            }
            break;
        }

        case MUTATE_SIZE_UNDERFLOW:{
            switch(t){
                case T_LINKINFO:
                    // LinkInfoSize not big enough to hold the size field (< 4)
                    state->linkinfo.link_info_size = lnk_rand(rng) % 4;
                    break;
                case T_VOLUMEID:
                    // VolumeIDSize < 0x10: fails VolumeID check
                    state->linkinfo.volume_id.volume_id_size = lnk_rand(rng) % 0x10;
                    break;
                case T_CNRL:
                    // CNRL size must be >= 0x14    
                    state->linkinfo.common_network_relative_link.common_network_relative_link_size = lnk_rand(rng) % 0x14;
                    break;
                case T_EXTRA:
                    // BlockSize must be >= 8
                    state->extradata.blocks[lnk_rand(rng) % state->extradata.block_count].size = lnk_rand(rng) % 8;
                    break;
                case T_IDLIST:
                    // minimum total_size is 2 (only terminator, two zero bytes): 0 and 1 both underflow
                    state->linktargetidlist.total_size = lnk_rand(rng) % 2;
                    break;
                case T_PROPSTORE_STOR:
                    // storage_size < 24 (4 size + 4 version + 16 fmtid)
                    for(int i = 0; i < state->extradata.block_count; i++)
                        if(state->extradata.blocks[i].type == EXTRA_PROPERTY_STORE && state->extradata.blocks[i].data){
                            uint32_t undersized = lnk_rand(rng) % 24;
                            memcpy(state->extradata.blocks[i].data, &undersized, 4);
                            break;
                        }
                    break;
                case T_PROPSTORE_VAL:
                    // value_size > 0 but < 9: enters serialized walk with undersized entry
                    for(int i = 0; i < state->extradata.block_count; i++){
                        if(state->extradata.blocks[i].type == EXTRA_PROPERTY_STORE && state->extradata.blocks[i].data){
                            uint32_t payload_len = state->extradata.blocks[i].size - 8;
                            if(payload_len > 28){ // enough room for storage header + value_size
                                uint32_t undersized = 1 + (lnk_rand(rng) % 8);
                                memcpy(state->extradata.blocks[i].data + 24, &undersized, 4);
                            }
                            break;
                        }
                    }
                    break;
                default:
                    break;
            }
            break;
        }

        case MUTATE_SIZE_DESYNC:{
            int delta = (lnk_rand(rng) % 100) - 50;
            switch(t){
                case T_LINKINFO:
                    // size mismatch causes reads past LinkInfo into StringData/ExtraData bytes
                    state->linkinfo.link_info_size += delta;
                    break;
                case T_VOLUMEID:
                    // inflated size reads past VolumeID into LocalBasePath/CNRL bytes
                    state->linkinfo.volume_id.volume_id_size += delta;
                    break;
                case T_CNRL:
                    // misaligned jump lands in middle of CNRL strings, reads garbage as next field
                    state->linkinfo.common_network_relative_link.common_network_relative_link_size += delta;
                    break;
                case T_IDLIST:
                    // size/content mismatch: IDListContainerIsConsistent may accept but later walks read wrong
                    state->linktargetidlist.total_size += delta;
                    break;
                case T_EXTRA:
                    // wrong block size: next block header read from middle of current payload
                    state->extradata.blocks[lnk_rand(rng) % state->extradata.block_count].size += delta;
                    break;
                default: break;
            }
            break;
        }

        case MUTATE_SIZE_BOUNDARY:{
            uint32_t val = boundaries[lnk_rand(rng) % bcount];
            switch(t){
                case T_IDLIST:
                    // mismatch between declared size and actual PIDL items in IDListContainerIsConsistent
                    state->linktargetidlist.total_size = val;
                    break;
                case T_LINKINFO:
                    // < 4 skips alloc, < 0x1C fails IsValidLinkInfo, >= 0x1C reaches deep validation
                    state->linkinfo.link_info_size = val;
                    break;
                case T_VOLUMEID:
                    // < 0x10 fails size check, > remaining fails bounds check
                    state->linkinfo.volume_id.volume_id_size = val;
                    break;
                case T_CNRL:
                    // < 0x14 fails minimum check, triggers unicode field misparse
                    state->linkinfo.common_network_relative_link.common_network_relative_link_size = val;
                    break;
                case T_EXTRA:
                    // > 0xFFFF seeks backwards, < 8 terminates block loop
                    state->extradata.blocks[lnk_rand(rng) % state->extradata.block_count].size = val;
                    break;
                default:
                    break;
            }
            break;
        }
        default: break;
    }
}

// used by MUTATE_PIDL_DELEGATEITEMID
// checks if raw SHITEMID is a DELEGATEITEMID by verifying marker CLSID {5E591A74-DF96-48D3-8D67-1733BCEE28BA}
// returns offset to marker CLSID if found, -1 otherwise
static int check_delegate(uint8_t* raw, int raw_len){
    // DELEGATEITEMID:
    // 0x00 cb              [2]   (size of entire item)
    // 0x02 class type      [2]   (same as parent)
    // 0x04 outer data size [2]   (size of delegate folder's data)
    // 0x06 outer data      [var] (delegate folder's data for item – only the delegate's COM handler interprets these bytes)
    // var  GUID            [16]  (delegate folder marker CLSID)
    // var  delegate clsid  [16]  (COM handler to delegate to)
    
    // min size = 38
    if(raw_len < 38) return -1;
    
    // read outer data size from offset 0x04 to know how many bytes to skip past to reach the marker CLSID
    uint16_t outer_size;
    memcpy(&outer_size, raw + 4, 2);

    // marker clsid @ offset + outer_size + 6
    int marker = outer_size + 6;
    if(marker + 32 > raw_len) return -1; // 16 marker CLSID, 16 delegate CLSID

    static const uint8_t marker_clsid[16] = {0x74, 0x1A, 0x59, 0x5E, 0x96, 0xDF, 0xD3, 0x48, 0x8D, 0x67, 0x17, 0x33, 0xBC, 0xEE, 0x28, 0xBA};

    if(memcmp(raw + marker, marker_clsid, 16) == 0)
        return marker;

    return -1;
}

// GROUP_PIDL (LinkTargetIDList) mutation operators
static void apply_pidl(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    // operators manipulate shell items in the items[] array
    LinkTargetIDList* pidl = &state->linktargetidlist;
    switch(op){
        case MUTATE_PIDL_REORDER_ITEM:{
            // swap two random items: parent/child relationship breaks
            if(pidl->item_count < 2) break;
            int i = lnk_rand(rng) % pidl->item_count;
            int j;
            do{
                j = lnk_rand(rng) % pidl->item_count;
            } while(j == i);
            ItemID tmp = pidl->items[i];
            pidl->items[i] = pidl->items[j];
            pidl->items[j] = tmp;
            break;
        }

        case MUTATE_PIDL_INSERT_ITEM:{
            // extra node in namespace walk: handler gets unexpected child
            // example: [Desktop] -> [C: drive] -> [INSERTION] -> [Users folder] -> [file.txt]
            if(pidl->item_count >= MAX_PIDL_ITEMS) break;
            int pos = lnk_rand(rng) % (pidl->item_count + 1); // pick a random pos in the list, insert there
            
            // shift existing items right to make a gap for the insertion at the pos we want
            for(int i = pidl->item_count; i > pos; i--)
                pidl->items[i] = pidl->items[i - 1];

            // now that the position is free, build a minimal item there (random class type)
            ItemID* item = &pidl->items[pos];
            memset(item, 0, sizeof(ItemID));
            item->size = 4;                   // cb = 4 (smallest valid: 2 cb + 1 class type + 1 byte)
            item->class_type = lnk_rand(rng) & 0xFF; // rndm class type
            item->type = IDTYPE_UNKNOWN;
            item->payload_len = 1;            // 1 byte of payload after class type
            item->payload = malloc(1);
            item->payload[0] = 0;
            item->raw_len = 4;                // raw SHITEMID is 4 bytes total
            item->raw = malloc(4);
            uint16_t cb = 4;
            memcpy(item->raw, &cb, 2);        // bytes 0-1 is cb
            item->raw[2] = item->class_type;  // byte 2 is abID[0] (class type)
            item->raw[3] = lnk_rand(rng) & 0xFF;     // byte 3 is payload, random here, doesn't rly matter can be 0 or wateva
            pidl->item_count++;               // +1 item in the list
            break;
        }

        case MUTATE_PIDL_REMOVE_ITEM:{
            // remove a random item in the list, namespace walk is shorter, children lose their parent
            if(pidl->item_count <= 1) break;
            int idx = lnk_rand(rng) % pidl->item_count;
            free(pidl->items[idx].raw);
            free(pidl->items[idx].payload);
            // shift everything after the removed item to the left to fill the gap so the array is contiguous again
            for(int i = idx; i < pidl->item_count - 1; i++) // shift items left starting at the gap
                pidl->items[i] = pidl->items[i + 1]; // each item moves one position left
            pidl->item_count--;
            break;
        }

        case MUTATE_PIDL_DUPLICATE_ITEM:{
            // repeated namespace node, handler sees same ID twice
            // RE shows the parser walks items sequentially
            // duplicate items may confuse ref count or caching
            // The duplicate is inserted at the end of the list rather than at a random
            // position because random insertion would just test parent/child confusion
            if(pidl->item_count < 1 || pidl->item_count >= MAX_PIDL_ITEMS) break;
            int idx = lnk_rand(rng) % pidl->item_count;
            ItemID* src = &pidl->items[idx];
            ItemID* dst = &pidl->items[pidl->item_count]; // end
            *dst = *src; // get the struct fields
            dst->raw = malloc(src->raw_len);
            memcpy(dst->raw, src->raw, src->raw_len);
            if(src->payload_len > 0){
                dst->payload = malloc(src->payload_len);
                memcpy(dst->payload, src->payload, src->payload_len);
            }
            pidl->item_count++;
            break;
        }

        case MUTATE_PIDL_PARENT_CHILD_MISMATCH:{
            // break parent/child relationship to confuse the namespace dispatch into misparsing payload bytes
            if(pidl->item_count < 2) break;
            
            // choose a child item (skip idx 0 to keep root valid so we reach namespace dispatch)
            int i = 1 + (lnk_rand(rng) % (pidl->item_count - 1)); // 0 to item_count - 2, skips idx 0 (root item) to keep root valid

            // set to a class type that conflicts with parent namespace
            uint8_t types[] = { // https://www.geoffchappell.com/studies/windows/shell/shell32/classes/regfolder.htm
                0x1F,                                     // root folder / CLSID
                0x23, 0x25, 0x29, 0x2A, 0x2E, 0x2F,       // volume variants (mask 0x70 == 0x20)
                0x31, 0x32, 0x35, 0x36,                   // file entry variants (mask 0x70 == 0x30)
                0x41, 0x42, 0x46, 0x47, 0x4C, 0x4D, 0x4E, // network location variants (mask 0x70 == 0x40)
                0x52,                                     // compressed folder
                0x61,                                     // URI
                0x70, 0x71,                               // control panel
                0x72,                                     // printers
                0x73,                                     // CommonPlacesFolder
                0x74,                                     // UsersFilesFolder
            };
            uint8_t parent_type = pidl->items[i - 1].class_type; // i - 1 is the parent
            uint8_t new_type;
            do{
                new_type = types[lnk_rand(rng) % (sizeof(types) / sizeof(types[0]))];
            } while(new_type == parent_type); // ensure they are different

            pidl->items[i].class_type = new_type;
            if(pidl->items[i].raw_len >= 3) // ensure raw buffer is big enough to have a byte at index 2
                pidl->items[i].raw[2] = new_type; // byte 0-1 are cb, byte 2 is abID[0] aka class type
            
            break;
        }

        case MUTATE_PIDL_CHAIN_TRUNCATION:{
            // shorten an item's payload so the parser reads past the end of it, ex:
            //  abID[0] = 0x1F (CLSID shell item)
            //  Payload = TRUNCATED GUID
            if(pidl->item_count < 1) break;
            int idx = lnk_rand(rng) % pidl->item_count;
            ItemID* item = &pidl->items[idx];
            if(item->payload_len <= 1) break; // ned at least 2 bytes of payload to have a range of possible truncation lengths
            
            // pick a new shorter payload_len
            uint16_t new_len = lnk_rand(rng) % item->payload_len;
            item->payload_len = new_len; // truncate

            // rebuild raw buffer to match
            uint16_t new_cb = 2 + 1 + new_len; // cb + class_type + payload
            free(item->raw);
            item->raw = malloc(new_cb);
            item->raw_len = new_cb;
            memcpy(item->raw, &new_cb, 2);    // bytes 0-1 new cb
            item->raw[2] = item->class_type;  // byte 2 class_type preserved
            if(new_len > 0)
                memcpy(item->raw + 3, item->payload, new_len); // truncated payload
            item->size = new_cb;
            break;
        }
        
        case MUTATE_PIDL_TOTAL_SIZE_DESYNC:{
            // make IDListSize field inconsistent with items
            int r = lnk_rand(rng) % 100;
            if(r < 40){
                // off-by-one: most likely to slip past validation
                pidl->total_size += (lnk_rand(rng) % 2 == 0) ? 1 : -1;
            }else if(r < 70){
                // small drift: +/- 8 bytes
                pidl->total_size += (lnk_rand(rng) % 16) - 8;
            }else if(r < 80){
                // large positive: big overallocation
                pidl->total_size += 500 + (lnk_rand(rng) % 1000);
            }else if(r < 90){
                // boundary values
                uint16_t vals[] = {0, 1, 2, 0x7FFF, 0xFFFF};
                pidl->total_size = vals[lnk_rand(rng) % 5];
            }else{
                // zero: allocation skipped or fails
                pidl->total_size = 0;
            }
            break;
        }
        
        case MUTATE_PIDL_CLASS_TYPE:{
            if(pidl->item_count < 1) break;
            int idx = lnk_rand(rng) % pidl->item_count;
            ItemID* item = &pidl->items[idx];
            // 70% random byte to test undocumented handlers
            // 30% documented type to test known handlers with wrong payload
            if(lnk_rand(rng) % 100 < 70)
                item->class_type = lnk_rand(rng) & 0xFF;
            else{
                uint8_t types[] = { // https://www.geoffchappell.com/studies/windows/shell/shell32/classes/regfolder.htm
                    0x1F,                                     // root folder / CLSID
                    0x23, 0x25, 0x29, 0x2A, 0x2E, 0x2F,       // volume variants (mask 0x70 == 0x20)
                    0x31, 0x32, 0x35, 0x36,                   // file entry variants (mask 0x70 == 0x30)
                    0x41, 0x42, 0x46, 0x47, 0x4C, 0x4D, 0x4E, // network location variants (mask 0x70 == 0x40)
                    0x52,                                     // compressed folder
                    0x61,                                     // URI
                    0x70, 0x71,                               // control panel
                    0x72,                                     // printers
                    0x73,                                     // CommonPlacesFolder
                    0x74,                                     // UsersFilesFolder
                };
                item->class_type = types[lnk_rand(rng) % (sizeof(types) / sizeof(types[0]))];
            }
            if(item->raw_len >= 3)
                item->raw[2] = item->class_type;
            break;
        }
        
        case MUTATE_PIDL_INJECT_CLSID:{
            if(pidl->item_count >= MAX_PIDL_ITEMS || pidl->item_count < 1) break;
            // arbtrary COM load via CLSID injection
            // 0x1f (root folder item) with a random GUID. Since this is not a .lnk file, it
            // bypasses the _IsTargetAnotherLink check in _LoadIDList and reaches namespace dispatch
            ItemID* item = &pidl->items[pidl->item_count];
            memset(item, 0, sizeof(ItemID));      // space for new item
            item->size = 20;                      // cb + class_type + sort order + GUID
            item->class_type = 0x1F;              // first byte of payload
            item->type = IDTYPE_CLSID_ITEM;
            item->payload_len = 17;               // sort order (1), GUID (16)
            item->payload = malloc(17);
            item->payload[0] = lnk_rand(rng) & 0xFF;     // random sort order
            for(int i = 0; i < 16; i++)
                item->payload[1 + i] = lnk_rand(rng) & 0xFF; // random GUID
            item->raw_len = 20;
            item->raw = malloc(20);
            uint16_t cb = 20;
            memcpy(item->raw, &cb, 2);                    // cb
            item->raw[2] = 0x1F;                          // class type
            item->raw[3] = item->payload[0];              // sort order
            memcpy(item->raw + 4, item->payload + 1, 16); // GUID
            pidl->item_count++;
            break;
        }

        case MUTATE_PIDL_MISSING_TERMINAL:{
            pidl->has_terminal = 0;
            break;
        }

        case MUTATE_PIDL_NONZERO_TERMINAL:{
            // a non-zero terminal could make the parser think another item exists to read and therefore read past the real end of IDList
            // ex. walker reads [83 23] (cb = 9091) and jumps forward 9091 bytes – hits another section or somewhere unexpected
            pidl->has_terminal = 1;
            int r = lnk_rand(rng) % 100;
            if(r < 50)
                pidl->terminal_value = 1 + (lnk_rand(rng) % 10); // small
            else if(r < 80)
                pidl->terminal_value = lnk_rand(rng) & 0xFFFF;   // random uint16_t
            else
                pidl->terminal_value = 0xFFFF;            // cb max
            break;
        }

        case MUTATE_PIDL_DELEGATEITEMID:{
            // chooses a random item from the PIDL, calls check_delagate on it:
            //   DELEGATEITEMID found: targeted surgical mutation on four delegate-specific fields
            //   normal SHITEMID: skip, other operators handle non-delegate mutations
            //
            // four cases target fields that RegFolder reads during delegate check and dispatch:
            //   case 0: outer data size (shifts marker CLSID read offset)
            //   case 1: marker CLSID bytes (breaks delegate identification)
            //   case 2: folder class identifier (wrong parent folder context)
            //   case 3: delegate item CLSID (wrong COM handler loaded)
            //
            // some delegate items also contain extension blocks (0xbeef0004, 0xbeef0013, etc.)
            // after the delegate CLSID. these are parsed by the delegate's own COM handler,
            // not by RegFolder.
            if(pidl->item_count < 1) break;
            int idx = lnk_rand(rng) % pidl->item_count;
            ItemID* item = &pidl->items[idx];

            int marker_offset = check_delegate(item->raw, item->raw_len);
            if(marker_offset >= 0){ // is DELEGATEITEMID
                int mode = lnk_rand(rng) % 4;
                switch(mode){
                    case 0:{
                        // TARGET: DELEGATEITEMID outer data size field @0x04
                        // in BindToObject dispatch, RegFolder calculates the
                        // marker CLSID position as item + outer data size + 6.
                        // corrupting outer data size displaces that position.
                        // RegFolder will read 16 bytes from the wrong location
                        // and compare them against the marker.
                        uint16_t val;
                        int r = lnk_rand(rng) % 100;
                        if(r < 40){
                            val = lnk_rand(rng) % 10;     // small, read position is still inside the item buffer
                        } else if(r < 70){
                            val = lnk_rand(rng) & 0xFFFF; // land anywhere, unpredictable misalignment
                        } else if(r < 85){
                            val = 0;               // skip outer data, read from offset 6
                        } else{
                            val = 0xFFFF;          // overflow item buffer
                        }
                        memcpy(item->raw + 4, &val, 2); // corrupt 0x04, 0x05
                        break;
                    }

                    case 1:{
                        // TARGET: marker CLSID bytes @Item + outer data size + 6
                        // corrupt the marker CLSID bytes so RegFolder can't match
                        // them to {5E591A74-DF96-48D3-8D67-1733BCEE28BA}.
                        // ex. comparison fails because byte 4 is now 0xA9 not 0x96
                        // RegFolder concludes "not a delegate," and processes the
                        // delegate item using standard format.
                        int byte_offset = marker_offset + (lnk_rand(rng) % 16);
                        item->raw[byte_offset] ^= (1 + (lnk_rand(rng) % 255)); // change a random byte in marker
                        break;
                    }

                    case 2:{
                        // TARGET: folder class identifier @0x02
                        // RegFolder reaads this to determine which parent folder
                        // type (ex. Control Panel) created this delegate. a wrong
                        // value means the item doesn't match any known parent.
                        // RegFolder may reject, dispatch to another handler, or
                        // process it with wrong assumptions about its outer data.
                        uint16_t val = lnk_rand(rng) & 0xFFFF;
                        memcpy(item->raw + 2, &val, 2); // corrupt 0x02, 0x03
                        break;
                    }

                    case 3:{
                        // TARGET: delegate item CLSID (16 bytes AFTER marker)
                        // after marker check passes, RegFolder reads these 16
                        // bytes and passes them to _CreateCachedDelegateFolder
                        // which calls _SHCoCreateInstance to load the COM object.
                        int clsid_offset = marker_offset + 16;
                        if(clsid_offset + 16 > item->raw_len) break;
                        
                        int r = lnk_rand(rng) % 100;
                        if(r < 30){
                            // 30% rndm: test error handling when CLSID doesn't exist
                            for(int i = 0; i < 16; i++)
                                item->raw[clsid_offset + i] = lnk_rand(rng) & 0xFF;
                        } else{
                            // 70% known IShellFolder: test real handlers receiving
                            // DELEGATEITEMID outer data they weren't designed to parse
                            int ci = lnk_rand(rng) % KNOWN_SHELL_CLSIDS_COUNT;
                            memcpy(item->raw + clsid_offset, KNOWN_SHELL_CLSIDS[ci], 16);
                        }
                        break;
                    }
                }
            } else{ // not a DELEGATEITEMID
                break;
            }

            break;
        }

        case MUTATE_PIDL_DEPTH:{
            // PIDL namespace resolution is done by walking each item left-right, calling
            // BindToObject at each level. Each call goes deeper into the call stack
            // Each item adds at least 2 stack frames (outer folder + RegFolder)
            // Adding 50 items to the PIDL means 100+ nested BindToObject calls
            // The stack is finite, so this will exhaust the thread's stack space
            // This tests if the Shell has a depth check before recursing, and if so,
            // whether it handles the limit correctly.

            // need at least 1 existing item because we are gonna duplicate it
            // chose duplication instead of item creation because its simpler and
            // ensures each item is valid enough to reach the BindToObject recursion
            if(pidl->item_count < 1 || pidl->item_count >= MAX_PIDL_ITEMS) break;

            int src = lnk_rand(rng) % pidl->item_count;
            ItemID* dupe = &pidl->items[src];

            // fill remaining PIDL with copies
            int capacity = (MAX_PIDL_ITEMS - pidl->item_count);
            // but randomize how many, sometimes moderate depth, sometimes extreme
            int r = lnk_rand(rng) % 100;
            if(r < 50){
                capacity = 10 + (lnk_rand(rng) % 20); // moderate: 10-29 items
            } else if(r < 80){
                capacity = 30 + (lnk_rand(rng) % 30); // deep: 30-59 items
            } else{
                capacity = capacity;           // max: fill up with items
            }

            if(pidl->item_count + capacity > MAX_PIDL_ITEMS)
                capacity = MAX_PIDL_ITEMS - pidl->item_count;

            for(int i = 0; i < capacity; i++){
                // go through the entire capacity and place the dupes
                ItemID* dst = &pidl->items[pidl->item_count]; // IDList end
                memset(dst, 0, sizeof(ItemID));
                dst->size = dupe->size;
                dst->class_type = dupe->class_type;
                dst->type = dupe->type;
                dst->payload_len = dupe->payload_len;
                if(dupe->payload && dupe->payload_len > 0){
                    dst->payload = malloc(dupe->payload_len);
                    memcpy(dst->payload, dupe->payload, dupe->payload_len);
                }
                dst->raw_len = dupe->raw_len;
                if(dupe->raw && dupe->raw_len > 0){
                    dst->raw = malloc(dupe->raw_len);
                    memcpy(dst->raw, dupe->raw, dupe->raw_len);
                }
                pidl->item_count++;
            }
            break;
        }

        default:
            break;
    }
}

// GROUP_OFFSETS
static void apply_offsets(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    // LinkInfo:
    //   [0] volume_id_offset
    //   [1] local_base_path_offset
    //   [2] common_network_relative_link_offset
    //   [3] common_path_suffix_offset
    //
    // LinkInfo Unicode (header size >= 0x24):
    //   [4] local_base_path_offset_unicode
    //   [5] common_path_suffix_offset_unicode
    //
    // LinkInfo CNRL (if HasCommonNetworkRelativeLink):
    //   [6] net_name_offset
    //   [7] device_name_offset
    //
    // LinkInfo CNRL Unicode (if CNRL size >= 0x14):
    //   [8] net_name_offset_unicode
    //   [9] device_name_offset_unicode
    //
    // ExtraData (0-2 blocks with offsets, CVE-2017-8464 AS):
    //   [10] SpecialFolderDataBlock PIDL index
    //   [11] KnownFolderDataBlock PIDL index
    uint32_t* offset_fields[12];
    int field_count = 0; // will typically be 4-8, max 12

    if(state->core.has_linkinfo){
        // these offset fields are always present in the 0x1C header if a LinkInfo exists
        offset_fields[field_count++] = &state->linkinfo.volume_id_offset;
        offset_fields[field_count++] = &state->linkinfo.local_base_path_offset;
        offset_fields[field_count++] = &state->linkinfo.common_network_relative_link_offset;
        offset_fields[field_count++] = &state->linkinfo.common_path_suffix_offset;
        
        // unicode offsets only present when LinkInfoHeaderSize >= 0x24
        if(state->linkinfo.link_info_header_size >= 0x24){
            offset_fields[field_count++] = &state->linkinfo.local_base_path_offset_unicode;
            offset_fields[field_count++] = &state->linkinfo.common_path_suffix_offset_unicode;
        }

        // CNRL is optional and has its own offsets for two name strings (these are always present if CNRL exists)
        if(state->linkinfo.has_common_network_relative_link){
            offset_fields[field_count++] = &state->linkinfo.common_network_relative_link.net_name_offset;
            offset_fields[field_count++] = &state->linkinfo.common_network_relative_link.device_name_offset;

            // optional fields which only exist when CommonNetworkRelativeLinkSize >= 0x14
            if(state->linkinfo.common_network_relative_link.common_network_relative_link_size >= 0x14){
                offset_fields[field_count++] = &state->linkinfo.common_network_relative_link.net_name_offset_unicode;
                offset_fields[field_count++] = &state->linkinfo.common_network_relative_link.device_name_offset_unicode;
            }
        }
    }

    // SpecialFolderDataBlock & KnownFolderDataBlock offsets
    // these are PIDL indices, not byte offsets into LinkInfo
    // but the mutation strategies still apply
    for(int i = 0; i < state->extradata.block_count; i++){
        ExtraDataBlock* edb = &state->extradata.blocks[i];
        if(edb->type == EXTRA_SPECIAL_FOLDER && edb->data){
            // SpecialFolderDataBlock:
            // 0x00  4  BlockSize        = 0x10
            // 0x04  4  BlockSignature   = 0xA0000005
            // 0x08  4  SpecialFolderID  = CSIDL value
            // 0x0C  4  Offset           = index into PIDL
            // payload layout: [SpecialFolderID:4][Offset:4]
            offset_fields[field_count++] = (uint32_t*)(edb->data + 4);
        } else if(edb->type == EXTRA_KNOWN_FOLDER && edb->data){
            // KnownFolderDataBlock:
            // 0x00  4   BlockSize       = 0x1C
            // 0x04  4   BlockSignature  = 0xA000000B
            // 0x08  16  KnownFolderID   = GUID, ex. Control Panel GUID
            // 0x18  4   Offset          = index into PIDL
            // payload layout: [KnownFolderID:16][Offset:4]
            offset_fields[field_count++] = (uint32_t*)(edb->data + 16);
        }
        
    }

    if(field_count == 0) return;

    int idx = lnk_rand(rng) % field_count;
    uint32_t* target = offset_fields[idx];

    switch(op){
        case MUTATE_OFFSET_ZERO:{
            // offset = 0: parser jumps to byte 0 of the structure (the size field),
            // reading header bytes as whatever data it expected (string, substructure, etc.)
            *target = 0;
            break;
        }

        case MUTATE_OFFSET_PAST_EOF:{
            // offset exceeds the containing structure's declared size:
            // parser dereferences data out of bounds, ex. adjacent sections, unmapped memory
            int r = lnk_rand(rng) % 100;
            if(r < 30) // 30%
                // max uint32 value. if the parser does pBase + offset, this wraps the pointer
                // around on 32-bit or produces a huge value on 64-bit.
                // observes:
                //  . if the parser checks bounds properly before adding offset to a base
                //  . if the parser recklessly casts the offset to another type
                *target = 0xFFFFFFFF; // fails > max checks, passes < 0 checks (seen as -1 if signed)
            else if(r < 50) // 20%
                // max int32 value. if the parser stores offset as int32, this is the largest
                // positive value. adding anything to it overflows to negative.
                // observes:
                //  . signed integer overflow in offset arithmetic
                *target = 0x7FFFFFFF; // passes < 0 checks, passes > 0 checks, fails only against max bounds checks
            else if(r < 75) // 25%
                // rndm val between 65536 (64KB) and 131071 (128KB).
                // far past than any LinkInfo or ExtraData section, but small enough
                // to potentially land in mapped memory (adjacent sections, heap data).
                // typical LinkInfo section is ~300 bytes, this is 100x-1000x that.
                // observes:
                //  . behavior that emerges when the parser reads bytes from completely different memory
                *target = 0x10000 + (lnk_rand(rng) % 0x10000);
            else // 25%
                // take the current (valid) offset and add 0x400 (1KB) to 0xFC00 (65KB) to it.
                // the offset now points past the end of the section.
                // observes:
                //  . if the parser compares offset against section size before dereferencing
                *target = *target + 0x400 + (lnk_rand(rng) % 0xFC00); // cur + large fwd jump
            break;
        }

        case MUTATE_OFFSET_OVERLAP:{
            // two offsets point to same region
            // set this offset to the value of another field: two parsers read the same bytes
            // with different type assumptions (ex. VolumeID parser and CNRL parser both start
            // at the same location, interpreting the same bytes with different type assumptions)
            if(field_count < 2) break;
            int idx2;
            do{
                idx2 = lnk_rand(rng) % field_count;
            } while(offset_fields[idx2] == target); // make sure not the same field
            *target = *offset_fields[idx2];
            break;
        }

        case MUTATE_OFFSET_WITHIN_HEADER:{
            // offset lands inside the structure's own fixed-size header:
            // parser expects a string or substructure but reads size/flags/offset bytes instead.
            // LinkInfo header occupies 0x00–0x1B (standard) or 0x00–0x23 (unicode offsets).
            // CNRL header occupies 0x00–0x13. For PIDL indices, small values address
            // the first items in the IDList or fall below item_count entirely.
            uint32_t header_positions[] = {0, 1, 2, 4, 8, 0x0C, 0x10, 0x14, 0x18};
            *target = header_positions[lnk_rand(rng) % (sizeof(header_positions) / sizeof(header_positions[0]))];
            break;
        }

        case MUTATE_OFFSET_CHAIN:{
            // point this offset at a position where another offset field is stored in
            // the binary representation of the structure. when the parser follows this
            // field it lands on the raw bytes of a neighbouring offset and reads them
            // as data — creating aliased interpretation of header content.
            //
            // LinkInfo binary layout (relative to start of LinkInfo):
            //   0x0C: volume_id_offset
            //   0x10: local_base_path_offset
            //   0x14: common_network_relative_link_offset
            //   0x18: common_path_suffix_offset
            //   0x1C: local_base_path_offset_unicode  (header >= 0x24 only)
            //   0x20: common_path_suffix_offset_unicode
            //
            // CNRL binary layout (relative to start of CNRL):
            //   0x08: net_name_offset
            //   0x0C: device_name_offset
            uint32_t chain_positions[] = {0x08, 0x0C, 0x10, 0x14, 0x18, 0x1C, 0x20};
            *target = chain_positions[lnk_rand(rng) % (sizeof(chain_positions) / sizeof(chain_positions[0]))];
            break;
        }

        default: break;
    }
}

// GROUP_EXTRA_SEQ ExtraData block ordering/presence
static void apply_extra_seq(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    // ExtraData is a list of blocks parsed by SHReadDataBlockList.
    //  . BlockSize > 0xFFFF: seek backward in stream, silently terminate loop
    //  . BlockSize < 8: terminate loop
    // valid range [8, 0xFFFF] -> IsValidDataBlock -> SHAddDataBlock
    // blocks are found by signature via SHFindDataBlock
    // order shouldn't atter per spec, but implementations may assume specific ordering/uniqueness
    ExtraDataState* extra = &state->extradata;
    switch(op){
        case MUTATE_EXTRA_REORDER_BLOCKS:{
            // swap two blocks, test if any code assumes specific ordering
            // ex. TrackerDataBlock before PropertyStoreDataBlock
            if(extra->block_count < 2) break;
            int a = lnk_rand(rng) % extra->block_count;
            int b;
            do{
                b = lnk_rand(rng) % extra->block_count;
            } while(b == a); // make sure a and b not the same block
            ExtraDataBlock tmp = extra->blocks[a];
            extra->blocks[a] = extra->blocks[b];
            extra->blocks[b] = tmp;
            break;
        }

        case MUTATE_EXTRA_REMOVE_BLOCK:{
            // remove a block from the list, tests if code handles missing blocks
            // that SHFindDataBlock returns NULL for. removing SpecialFolderDataBlock
            // or KnownFolderDataBlock changes namespace resolution context
            if(extra->block_count < 1) break;
            int idx = lnk_rand(rng) % extra->block_count;
            free(extra->blocks[idx].data);
            for(int i = idx; i < extra->block_count - 1; i++)
                extra->blocks[i] = extra->blocks[i + 1]; // shift every block after the removed one left by one position to fill the gap
            extra->block_count--;
            break;
        }

        case MUTATE_EXTRA_DUPLICATE_BLOCK:{
            // duplicate an ExtraData block in the list so there are two blocks with same signature
            // SHFindDataBlock will return the first match
            // tests if any code assumes uniqueness or processes both
            if(extra->block_count < 1 || extra->block_count >= MAX_EXTRA_DATA_BLOCKS) break;
            int src = lnk_rand(rng) % extra->block_count;
            ExtraDataBlock* s = &extra->blocks[src]; // random block
            ExtraDataBlock* d = &extra->blocks[extra->block_count]; // end
            d->size      = s->size;
            d->signature = s->signature;
            d->type      = s->type;
            // Bound the duplicate by s->data_len, not by s->size-8. If s was previously
            // mutated to claim a larger size than its actual data buffer, copying s->size-8
            // bytes from s->data would read past the heap allocation.
            uint32_t data_len = s->data_len;
            if(s->data && data_len > 0){
                d->data = malloc(data_len);
                if(!d->data) return;
                memcpy(d->data, s->data, data_len);
                d->data_len = data_len;
            } else{
                d->data = NULL;
                d->data_len = 0;
            }
            extra->block_count++;
            break;
        }

        case MUTATE_EXTRA_INSERT_BLOCK:{
            // inject an ExtraData block with a known signature that wasn't in the original.
            // SpecialFolderDataBlock and KnownFolderDataBlock are high value:
            //  CVE-2017-8464 used these to force namespace context switches.
            //  Microsoft patched the specific Control Panel values, but the
            //  mechanism (ExtraData influencing resolution context) still exists.
            //  random folder IDs and GUIDs test if other context switches are
            //  reachable through unhardened code paths.
            if(extra->block_count >= MAX_EXTRA_DATA_BLOCKS) break;
            ExtraDataBlock* block = &extra->blocks[extra->block_count];
            memset(block, 0, sizeof(ExtraDataBlock));
            ExtraDataType types[] = {
                EXTRA_ENVIRONMENT, EXTRA_CONSOLE, EXTRA_TRACKER,
                EXTRA_CONSOLE_FE, EXTRA_SPECIAL_FOLDER, EXTRA_DARWIN,
                EXTRA_ICON_ENVIRONMENT, EXTRA_PROPERTY_STORE,
                EXTRA_KNOWN_FOLDER, EXTRA_VISTA_IDLIST, EXTRA_SHIM,
            };
            block->type = types[lnk_rand(rng) % 11];

            int data_len = 8 + (lnk_rand(rng) % 32); // 8 + 0-31 = 8-39 payload size after the header
            // 8 minimum ensures enough bytes for handlers to start parsing
            // 39 maximum keeps it small enough to pass SHReadDataBlockList validation (< 0xFFFF)
            block->data = calloc(1, data_len);
            if(!block->data) break;
            for(int i = 0; i < data_len; i++)
                block->data[i] = lnk_rand(rng) & 0xFF; // fill payload w random stuff
            block->data_len = (uint32_t)data_len;
            block->size = 8 + data_len; // header + payload
            extra->block_count++;
            break;
        }

        case MUTATE_EXTRA_MISSING_TERMINATOR:{
            // remove terminator, SHReadDataBlockList reads past the end
            // of ExtraData into whatever follows in memory
            extra->has_terminator = 0;
            break;
        }

        case MUTATE_EXTRA_EARLY_TERMINATOR:{
            // inject a block with size < 8 before the real blocks
            // SHReadDataBlockList terminates loop early
            if(extra->block_count < 1 || extra->block_count >= MAX_EXTRA_DATA_BLOCKS) break;
            int pos = lnk_rand(rng) % extra->block_count; // insert before this block
            for(int i = extra->block_count; i > pos; i--)
                extra->blocks[i] = extra->blocks[i - 1];
            ExtraDataBlock* b = &extra->blocks[pos];
            memset(b, 0, sizeof(ExtraDataBlock));
            b->size = lnk_rand(rng) % 8; // 0-7 size triggers loop termination
            b->type = EXTRA_TERMINATOR;
            b->data = NULL;
            extra->block_count++;
            break;
        }
        
        default: break;
    }
}

// GROUP_EXTRA_HDR ExtraData block header corruption
static void apply_extra_hdr(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    // MUTATE_BLOCK_SIZE_ZERO,
    // MUTATE_BLOCK_SIZE_UNDERFLOW,        // < 8, smaller than header
    // MUTATE_BLOCK_SIZE_OVERFLOW,         // extends into next block
    // MUTATE_BLOCK_SIGNATURE_UNKNOWN,     // unrecognized signature
    // MUTATE_BLOCK_SIGNATURE_WRONG,       // valid signature on wrong block type
    ExtraDataState* extra = &state->extradata;
    if(extra->block_count < 1) return;

    int idx = lnk_rand(rng) % extra->block_count;
    ExtraDataBlock* block = &extra->blocks[idx];

    switch(op){
        case MUTATE_BLOCK_SIZE_ZERO:{
            // size 0 is the normal terminator for SHReadDataBlockList
            // paraer thinks the list ended early. blocks after this are never parsed
            block->size = 0;
            break;
        }

        case MUTATE_BLOCK_SIZE_UNDERFLOW:{
            // block size < 8 terminates the SHReadDataBlockList loop
            // parser stops walking and ignores remaining blocks
            // values 1-7 test if the termination path handles partial
            // header reads (size field exists but signature doesn't fit)
            block->size = 1 + (lnk_rand(rng) % 7);
            break;
        }

        case MUTATE_BLOCK_SIZE_OVERFLOW:{
            // size > 0xFFFF causes SHReadDataBlockList to seek backward
            // in stream, silently terminates loop
            int r = lnk_rand(rng) % 100;
            if(r < 40)
                block->size = 0x10000;                      // past 0xFFFF boundary
            else if(r < 70)
                block->size = 0x10000 + (lnk_rand(rng) % 0xF0000); // 64KB-1MB
            else if(r < 85)
                block->size = 0xFFFFFFFF;                   // max uint32
            else
                block->size = 0xFFFF;                       // exact boundary, valid or invalid
            break;
        }

        case MUTATE_BLOCK_SIGNATURE_UNKNOWN:{
            // unrecognized signature, IsValidDataBlock rejects the block
            // tests if rejection path correctly skips the abID[] payload bytes
            // or if the parser gets confused abt where the next block starts
            //
            // EXTRA_UNKNOWN + an explicit non-spec signature on `block->signature` is the
            // post-fix shape: the serializer writes the signature we put here verbatim, so
            // the mutator gets to choose what bytes the parser sees instead of relying on
            // a placeholder constant. We pick a value in the 0xA0000xxx family (the same
            // prefix Microsoft reserves for ExtraData signatures) so the parser exercises
            // its "looks like one of ours but isn't" rejection path rather than its
            // "obviously garbage" path.
            int r = lnk_rand(rng) % 100;
            block->type = EXTRA_UNKNOWN;
            if(r < 40){
                // unrecognized but well-formed — random low byte avoiding 0x01..0x0C
                uint8_t low;
                do { low = (uint8_t)(lnk_rand(rng) & 0xFF); } while (low >= 0x01 && low <= 0x0C);
                block->signature = 0xA0000000u | low;
            } else if(r < 70){
                // collide with a real type by stealing its signature but tagging type wrong.
                // exercises the type-vs-signature confusion path.
                uint32_t real_sigs[] = {
                    0xA0000001, 0xA0000002, 0xA0000003, 0xA0000004, 0xA0000005, 0xA0000006,
                    0xA0000007, 0xA0000008, 0xA0000009, 0xA000000B, 0xA000000C
                };
                block->signature = real_sigs[lnk_rand(rng) % 11];
            } else{
                // unknown signature with valid 8-byte size (just header, no payload)
                block->signature = 0xA00000FF;
                block->size = 8;
            }
            break;
        }

        case MUTATE_BLOCK_SIGNATURE_WRONG:{
            // signature emitted on disk no longer matches the block's payload class
            //
            // example:
            //   payload bytes look like a Tracker block, but BlockSignature on disk says
            //   PropertyStore (0xA0000009). SHFindDataBlock returns the bytes to the
            //   PropertyStore handler, which reads fields under wrong assumptions.
            //
            // Important: deserialize now preserves the raw 32-bit signature in
            // block->signature, and serialize prefers it over the type→sig table.
            // To flip the emitted signature we have to update `signature` directly,
            // not just `type`. The pairs below walk ExtraDataType + on-disk sig in lockstep.
            static const struct { ExtraDataType type; uint32_t sig; } kKnown[] = {
                { EXTRA_ENVIRONMENT,      0xA0000001 },
                { EXTRA_CONSOLE,          0xA0000002 },
                { EXTRA_TRACKER,          0xA0000003 },
                { EXTRA_CONSOLE_FE,       0xA0000004 },
                { EXTRA_SPECIAL_FOLDER,   0xA0000005 },
                { EXTRA_DARWIN,           0xA0000006 },
                { EXTRA_ICON_ENVIRONMENT, 0xA0000007 },
                { EXTRA_SHIM,             0xA0000008 },
                { EXTRA_PROPERTY_STORE,   0xA0000009 },
                { EXTRA_KNOWN_FOLDER,     0xA000000B },
                { EXTRA_VISTA_IDLIST,     0xA000000C },
            };
            const int kKnownCount = (int)(sizeof(kKnown) / sizeof(kKnown[0]));

            if(extra->block_count == 1){
                // single block: pick a known type different from the current one and
                // adopt its (type, signature) pair. Payload stays untouched on purpose —
                // that is the whole point of the mutation.
                int pick;
                do{
                    pick = lnk_rand(rng) % kKnownCount;
                } while(kKnown[pick].type == block->type);
                block->type = kKnown[pick].type;
                block->signature = kKnown[pick].sig;
            } else{
                // two or more blocks: swap (type, signature) pairs between two indices.
                // both handlers end up reading each other's payloads.
                int other;
                do{
                    other = lnk_rand(rng) % extra->block_count;
                } while(other == idx);
                ExtraDataType tmp_type = block->type;
                uint32_t      tmp_sig  = block->signature;
                block->type      = extra->blocks[other].type;
                block->signature = extra->blocks[other].signature;
                extra->blocks[other].type      = tmp_type;
                extra->blocks[other].signature = tmp_sig;
            }
            break;
        }

        default:
            break;
    }
}

// Serialized Property Storage (property set within property store)
static void apply_propstore_set(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    SerializedPropertyStore* ps = &state->propstore;
    if(ps->storage_count < 1) return;

    // pick random storage, mutate storage-level fields
    int idx = lnk_rand(rng) % ps->storage_count;
    SerializedPropertyStorage* storage = &ps->storages[idx];

    switch(op){
        case MUTATE_PROPSTORE_STORAGE_SIZE_ZERO:{
            // SetPropertyStorage walks: while(chunkSize != 0){ pStorage += chunkSize; }
            // zero terminates the walk early, storages after this are never processed
            storage->storage_size = 0; // treated as terminator, early exit
            break;
        }

        case MUTATE_PROPSTORE_STORAGE_SIZE_UNDERFLOW:{
            // minimum valid storage is 24 bytes (StorageSize + Version + FormatID)
            // values < 24 mean the parser can't read the full header
            storage->storage_size = 1 + (lnk_rand(rng) % 23); // 1-23 (smaller than header)
            break;
        }

        case MUTATE_PROPSTORE_STORAGE_SIZE_DESYNC:{
            // StorageSize is the skip distance to the next storage entry in the store.
            //
            // CMemPropStore::SetPropertyStorage:
            //   ULONG chunkSize = *(ULONG*)pStorage; <-- READS StorageSize
            //   computedSize = 4;
            //   pStorage += chunkSize;               <-- LANDS AT WRONG POS
            //   computedSize += chunkSize;
            //   chunkSize = *(ULONG*)pStorage;       <-- READS MUTATED BYTES AS NEXT StorageSize
            //
            // If chunkSize is wrong, pStorage += chunkSize jumps to the wrong byte offset.
            // Then *(ULONG*)pStorage reads whatever 4 bytes are at that wrong position as
            // the next storage's StorageSize. Those bytes could be anything. The loop keeps
            // walking with corrupted positions, accumulating a wrong computedSize, which
            // gets passed to CoTaskMemAlloc & memcpy.
            int r = lnk_rand(rng) % 100;
            if(r < 50)
                storage->storage_size += (lnk_rand(rng) % 16) - 8; // small drift +/- 8, lands nearby in the next storage's header
            else if(r < 80)
                storage->storage_size = 24 + (lnk_rand(rng) % 32); // assign a size that is >= 24 but is likely shorter than the actual storage content
            else
                storage->storage_size = storage->storage_size / 2; // half the actual size
            break;
        }

        case MUTATE_PROPSTORE_STORAGE_SIZE_128MB:{
            // CMemPropStore::SetPropertyStorage rejects if computedSize > 0x08000000 (128MB)
            // one below the boundary passes the check, then CoTaskMemAlloc tries to alloc ~128MB
            // may fail and return NULL
            int r = lnk_rand(rng) % 100;
            if(r < 60)
                storage->storage_size = 0x07FFFFFF; // 1 below boundary, passes check, massive alloc
            else
                storage->storage_size = 0x08000001; // 1 past boundary, fails check, tests rejection cleanup
            break;
        }

        case MUTATE_PROPSTORE_VERSION_WRONG:{
            // version must be 0x53505331 ("1SPS")
            // tests s_ValidateStorage rejection cleanup
            int r = lnk_rand(rng) % 100;
            if(r < 30)
                storage->version = 0; // zero
            else if(r < 60)
                storage->version = 0x53505332; // "2SPS" off by one
            else if(r < 80)
                storage->version = lnk_rand(rng); // random
            else
                storage->version = 0x53505331 ^ (1 << (lnk_rand(rng) % 32)); // single bit flip
            break;
        }

        case MUTATE_PROPSTORE_FORMAT_ID_RANDOM:{
            // unknown FormatID, no property schema registered for it
            // parser may fail to find handlers or fall through to default
            for(int i = 0; i < 16; i++)
                storage->fmtid[i] = lnk_rand(rng) & 0xFF;
            break;
        }

        case MUTATE_PROPSTORE_FORMAT_ID_STRING_NAMED:{
            // force FMTID to string-named. if values were serialized as
            // integer-named, parser reads PropertyID as NameSize: type confusion
            if(storage->name_scheme == PROPVAL_STRING_NAMED) break;
            memcpy(storage->fmtid, FMTID_STRING_NAMED, 16);
            storage->name_scheme = PROPVAL_STRING_NAMED;
            // intentionally don't convert the values: mismatch
            break;
        }

        case MUTATE_PROPSTORE_NAMING_MISMATCH:{
            // flip name scheme without changing FMTID
            // values will be parsed with the wrong format:
            //   integer-named reads [ValueSize][PropertyID][Reserved][TPV]
            //   string-named reads [ValueSize][NameSize][Reserved][NameString][TPV]
            if(storage->name_scheme == PROPVAL_INTEGER_NAMED)
                storage->name_scheme = PROPVAL_STRING_NAMED;
            else
                storage->name_scheme = PROPVAL_INTEGER_NAMED;
            break;
        }

        case MUTATE_PROPSTORE_DUPLICATE_FORMAT_ID:{
            // two storages with same FMTID, spec says FMTID must be unique
            // tests if the parser handles dupes: overwrites, merges, or crashes
            if(ps->storage_count < 2) break;
            int other;
            do{
                other = lnk_rand(rng) % ps->storage_count;
            } while(other == idx);
            memcpy(storage->fmtid, ps->storages[other].fmtid, 16);
            break;
        }

        case MUTATE_PROPSTORE_EARLY_TERMINATOR:{
            // set a middle storage's size to 0, terminates the walk early
            // storages after it are never processed
            if(ps->storage_count < 2) break;
            int middle = lnk_rand(rng) % (ps->storage_count - 1); // not the last one
            ps->storages[middle].storage_size = 0;
            break;
        }

        case MUTATE_PROPSTORE_MISSING_TERMINATOR:{
            // remove the store-level terminator (StorageSize == 0)
            // CMemPropStore::SetPropertyStorage walks until chunkSize == 0
            // without terminator, it reads past the store into whatever follows
            ps->has_terminator = 0;
            break;
        }

        default:
            break;
    }
}

// Serialized Property Value
static void apply_propstore_val(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    SerializedPropertyStore* ps = &state->propstore;
    if(ps->storage_count < 1) return;

    // pick random storage, pick randome value, mutate value-level fields
    int idx = lnk_rand(rng) % ps->storage_count;
    SerializedPropertyStorage* storage = &ps->storages[idx];
    int val_idx = lnk_rand(rng) % storage->value_count;
    SerializedPropertyValue* val = &storage->values[val_idx];
    
    // MUTATE_PROPSTORE_DUPLICATE_PID,             // duplicate property ID in same storage
    // MUTATE_PROPSTORE_RESERVED_NONZERO,          // reserved byte != 0x00
    // MUTATE_PROPSTORE_MISSING_VALUE_TERMINATOR,  // no 0x00000000 at end of storage

    switch(op){
        case MUTATE_PROPSTORE_VALUE_SIZE_ZERO:{
            // GetValue walks values:
            // 
            //   while(*(ULONG*)prop != 0)
            //      prop += entry->cbProp; <-- cbProp is ValueSize
            // 
            // if ValueSize is 0, prop will read 0 and think its the terminator.
            // so remaining properties in this storage will be skipped.
            // tests whether validation (s_ValidateStorage) and parsing (GetValue)
            // handle zero ValueSize the same way. If one keeps walking with ValueSize 0,
            // but the other treats it as terminator and stops: misaligned read.
            if(storage->name_scheme == PROPVAL_STRING_NAMED)
                val->string_named.value_size = 0;
            else
                val->integer_named.value_size = 0;
            break;
        }

        case MUTATE_PROPSTORE_VALUE_SIZE_UNDERFLOW:{
            // ValueSize smaller than header (< 9)
            if(storage->name_scheme == PROPVAL_STRING_NAMED)
                val->string_named.value_size = 1 + (lnk_rand(rng) % 8); // 1-9 (not 0, other op handles that)
            else
                val->integer_named.value_size = 1 + (lnk_rand(rng) % 8);
            break;
        }

        case MUTATE_PROPSTORE_VALUE_SIZE_DESYNC:{
            // ValueSize is the skip distance to the next value entry in the storage
            // wrong value makes GetValue land mid-field and read garbage as the next
            // value's PropertyID/NameSize/TypedPropertyValue
            int r = lnk_rand(rng) % 100;
            if(r < 50){
                // small drift, -8 to +7 range
                if(val->name_scheme == PROPVAL_STRING_NAMED)
                    val->string_named.value_size += (lnk_rand(rng) % 16) - 8;
                else
                    val->integer_named.value_size += (lnk_rand(rng) % 16) - 8;
            } else if(r < 80){
                // passes < 9 check but wrong
                if(val->name_scheme == PROPVAL_STRING_NAMED)
                    val->string_named.value_size = 9 + (lnk_rand(rng) % 32);
                else
                    val->integer_named.value_size = 9 + (lnk_rand(rng) % 32);
            } else{
                // half actual size
                if(val->name_scheme == PROPVAL_STRING_NAMED)
                    val->string_named.value_size /= 2;
                else
                    val->integer_named.value_size /= 2;
            }
            break;
        }

        case MUTATE_PROPSTORE_DUPLICATE_PID:{
            // PropertyID must be unique within a storage according to spec
            // duplicate PID means two values claim to be the same property
            // GetValue walks until it finds a matching PID and returns
            // tests whether the second duplicate causes issues during
            // materialization, enumeration, or deletion
            if(storage->value_count < 2) break;
            if(storage->name_scheme == PROPVAL_STRING_NAMED) break; // PIDs are for integer-named only
            int a = lnk_rand(rng) % storage->value_count;
            int b;
            do{
                b = lnk_rand(rng) % storage->value_count;
            } while(b == a);
            storage->values[b].integer_named.property_id = storage->values[a].integer_named.property_id;
            break;
        }

        case MUTATE_PROPSTORE_RESERVED_NONZERO:{
            // reserved byte must be 0x00 according to spec
            // tests if any parser uses this byte as a flag, index, or size
            uint8_t reserved = 1 + (lnk_rand(rng) % 255);
            if(val->name_scheme == PROPVAL_STRING_NAMED)
                val->string_named.reserved = reserved;
            else
                val->integer_named.reserved = reserved;
            break;
        }

        case MUTATE_PROPSTORE_MISSING_VALUE_TERMINATOR:{
            // each storage's value list ends with ValueSize == 0
            // GetValue walks: while(*(ULONG*)prop != 0)
            // removing the terminator means the walker reads past the value
            // list into the next storage's header or past the store entirely.
            storage->has_terminator = 0;
            break;
        }

        default:
            break;
    }
}

// TypedPropertyValue VARTYPE/padding
static void apply_propstore_tpv(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    SerializedPropertyStore* ps = &state->propstore;
    if(ps->storage_count < 1) return;

    // pick random storage, pick random value, corrupt TypedPropertyValue fields
    int idx = lnk_rand(rng) % ps->storage_count;
    SerializedPropertyStorage* storage = &ps->storages[idx];
    int val_idx = lnk_rand(rng) % storage->value_count;
    SerializedPropertyValue* val = &storage->values[val_idx];

    TypedPropertyValue* tpv;
    if(val->name_scheme == PROPVAL_STRING_NAMED)
        tpv = &val->string_named.typed_value;
    else
        tpv = &val->integer_named.typed_value;

    switch(op){
        case MUTATE_PROPSTORE_VT_INVALID:{
            // DeserializeHelper::Worker validates vt via CheckVarType() before dispatch.
            // if CheckVarType passes, Worker uses a jump table to route to type-specific handlers.
            // CheckVarType only accepts base types (vt & 0xFFF):
            //   0x00-0x0E (LNK_VT_EMPTY through LNK_VT_DECIMAL)
            //   0x10-0x1F (LNK_VT_I1 through LNK_VT_LPWSTR)
            //   0x24-0x26 (LNK_VT_RECORD, LNK_VT_INT_PTR, LNK_VT_UINT_PTR)
            //   0x40-0x49 (LNK_VT_FILETIME through LNK_VT_VERSIONED_STREAM)
            // rejects: negative (bit 15), LNK_VT_VECTOR|LNK_VT_ARRAY together, everything else.
            // 
            // tests for rejection cleanup:
            //   rejection path in CheckVarType
            //   error handling in Worker
            uint16_t invalid_vartypes[] = {
                0x000F,                         // gap: LNK_VT_DECIMAL+1, only gap inside the low range
                0x0020, 0x0021, 0x0022, 0x0023, // gap: after LNK_VT_LPWSTR
                0x0027, 0x0028, 0x0030,         // gap: after LNK_VT_UINT_PTR
                0x004A, 0x004B, 0x00FF,         // gap: after LNK_VT_VERSIONED_STREAM
                0x0100, 0x0200, 0x0FFF,         // mid-range: no handler exists
            };
            tpv->vt = invalid_vartypes[lnk_rand(rng) % (sizeof(invalid_vartypes) / sizeof(invalid_vartypes[0]))];
            break;
        }

        case MUTATE_PROPSTORE_VT_BYREF:{
            // attack vector
            // CheckVarType does not check for LNK_VT_BYREF:
            //   . a1 < 0 catches LNK_VT_RESERVED (0x8000) because int16 makes it negative
            //   . but 0x4000 as int16 is positive (16384), passes the sign check
            //   . base type (lower 12 bits) is whitelisted, passes the switch
            //   . CheckVarType returns 0 (success)
            // then in DeserializeHelper::Worker:
            //   bt di, 0Eh  <-- tests bit 14 (LNK_VT_BYREF flag)
            //   jb loc_...  <-- invokes BYREF handler
            // the BYREF handler interprets value bytes as pointer-sized data
            // this is the only modifier flag that passes CheckVarType and reaches
            // a dedicated handler, LNK_VT_RESERVED, LNK_VT_VECTOR|LNK_VT_ARRAY etc. get caught,
            // but LNK_VT_BYREF alone slips through.
            uint16_t base_vartypes[] = {
                LNK_VT_I2, LNK_VT_I4, LNK_VT_R4, LNK_VT_R8, LNK_VT_BSTR, LNK_VT_ERROR,
                LNK_VT_BOOL, LNK_VT_I1, LNK_VT_UI1, LNK_VT_UI2, LNK_VT_UI4,
                LNK_VT_I8, LNK_VT_UI8, LNK_VT_INT, LNK_VT_UINT,
                LNK_VT_LPSTR, LNK_VT_LPWSTR,
            };
            tpv->vt = LNK_VT_BYREF | base_vartypes[lnk_rand(rng) % (sizeof(base_vartypes) / sizeof(base_vartypes[0]))];
            break;
        }

        case MUTATE_PROPSTORE_VT_VECTOR:{
            // LNK_VT_VECTOR (0x1000) triggers count-prefixed array parsing in DeserializeHelper::Worker.
            // CheckVarType allows it: 0x1000 | base_type is positive, and the LNK_VT_VECTOR|LNK_VT_ARRAY check
            // only rejects when both bits are set. LNK_VT_VECTOR alone passes.
            // Worker reads a count from value bytes, allocates count * element_size,
            // then loops reading elements of the vector.
            // corrupted count with small buffer = OOB read
            // corrupted element_size with large count = int overflow in allocation
            uint16_t base_types[] = {
                LNK_VT_I2, LNK_VT_I4, LNK_VT_R4, LNK_VT_R8, LNK_VT_BSTR,
                LNK_VT_BOOL, LNK_VT_UI1, LNK_VT_UI4, LNK_VT_I8, LNK_VT_UI8,
                LNK_VT_LPSTR, LNK_VT_LPWSTR, LNK_VT_FILETIME, LNK_VT_CLSID,
                LNK_VT_VARIANT, // LNK_VT_VECTOR | LNK_VT_VARIANT = array of nested variants
            };
            tpv->vt = LNK_VT_VECTOR | base_types[lnk_rand(rng) % (sizeof(base_types) / sizeof(base_types[0]))];
            break;
        }

        case MUTATE_PROPSTORE_VT_STREAM:{
            // LNK_VT_STREAM (0x42), LNK_VT_STORAGE (0x43), LNK_VT_STREAMED_OBJECT (0x44),
            // LNK_VT_STORED_OBJECT (0x45) all pass CheckVarType (cases 66-69).
            // StgDeserializePropVariant pre-checks 0x43-0x46 before Worker:
            //   lea eax, [rcx-43h]
            //   test eax, 0FFFFFFF9h
            //   jz loc_...  ← separate handler for storage types
            // these types trigger COM IStream/IStorage creation from value bytes.
            // the separate handler may create COM objects from attacker-controlled data.
            uint16_t stream_types[] = {
                LNK_VT_STREAM, LNK_VT_STORAGE, LNK_VT_STREAMED_OBJECT, LNK_VT_STORED_OBJECT,
            };
            tpv->vt = stream_types[lnk_rand(rng) % 4];
            break;
        }

        case MUTATE_PROPSTORE_VT_VARIANT:{
            // LNK_VT_VARIANT (0x0C) passes CheckVarType (case 12).
            // in Worker's first jump table (byte_18000C6B0), vt 0x0C maps to
            // handler group 6 (default). but in the second jump table
            // (byte_18000C734 / jpt_18000BF21), it maps to handler group 5
            // which calls Worker recursively for nested PROPVARIANT parsing.
            // crafted nesting depth could overflow the stack.
            // crafted inner vt could reach handlers the outer CheckVarType
            // wouldn't normally allow.
            tpv->vt = LNK_VT_VARIANT;
            break;
        }

        case MUTATE_PROPSTORE_VT_RESERVED:{
            // LNK_VT_RESERVED (0x8000) — bit 15 set.
            // CheckVarType catches it: a1 < 0 (int16 sign check).
            // 0x8000 as int16 = -32768, rejected immediately.
            // this only tests rejection cleanup, not parsing.
            // kept because LNK_VT_RESERVED | base_type combinations might
            // behave differently than pure 0x8000 in the error path.
            uint16_t base_types[] = {
                LNK_VT_I4, LNK_VT_BSTR, LNK_VT_BOOL, LNK_VT_LPWSTR, LNK_VT_FILETIME, LNK_VT_CLSID,
            };
            tpv->vt = LNK_VT_RESERVED | base_types[lnk_rand(rng) % 6];
            break;
        }

        case MUTATE_PROPSTORE_PADDING_NONZERO:{
            // TypedPropertyValue layout: [vt:2][padding:2][value:var]
            // padding must be 0x0000 per spec.
            // Worker reads the full DWORD at offset 0 of the SERIALIZEDPROPERTYVALUE:
            //   mov edi, [rdx]  <-- reads vt + padding as one DWORD
            // if any code masks with 0xFFFF to extract vt but another code path
            // reads the full DWORD, the padding bytes become part of the type.
            // 0x0001 in padding makes the DWORD 0x0001xxxx instead of 0x0000xxxx.
            tpv->padding = 1 + (lnk_rand(rng) % 0xFFFE); // 1-0xFFFF, guaranteed non-zero
            break;
        }

        case MUTATE_PROPSTORE_FORCE_MISALIGN:{
            // GetValue checks: if((uintptr_t)valuePtr & 7) != 0
            //   aligned: StgDeserializePropVariant called directly on blob pointer
            //   misaligned: LocalAlloc temp buffer, memcpy, StgDeserializePropVariant on copy
            // both paths call the same function but from different memory:
            //   . aligned path operates on the original shared buffer (read-only expected)
            //   . misaligned path operates on a private heap copy (read-write)
            // if StgDeserializePropVariant writes back to the buffer (a bug), the
            // aligned path corrupts shared state while the misaligned path doesn't.
            // craft ValueSize so the NEXT value starts at a non-8-aligned offset.
            if(val->name_scheme == PROPVAL_STRING_NAMED){
                if((val->string_named.value_size & 7) == 0)
                    val->string_named.value_size += 1 + (lnk_rand(rng) % 7);
            } else{
                if((val->integer_named.value_size & 7) == 0)
                    val->integer_named.value_size += 1 + (lnk_rand(rng) % 7);
            }
            break;
        }

        default:
            break;
    }
}

// GROUP_DARWIN DarwinDataBlock
// payload layout inside block->data (780 bytes):
//   [0..260)    ANSI  descriptor     (char[260], NUL-terminated in well-formed files)
//   [260..780)  UTF-16LE descriptor  (uint16_t[260], NUL-terminated)
static void apply_darwin(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    ExtraDataBlock* block = find_extra_block(&state->extradata, EXTRA_DARWIN);
    if(!block || !block->data) return;

    // a proper DarwinDataBlock is 0x314 bytes on the wire -> 0x30C payload
    // so refuse to touch anything smaller; caller can use a size-mutation op for that
    if(block->size < 8 + 780) return;

    uint8_t* ansi = block->data; // 260
    uint8_t* uni = block->data + 260; // 520 UTF16-LE

    switch(op){
        case MUTATE_DARWIN_FORMAT_STRING:{
            // format string parsing attack.
            // inject format specifiers into Darwin product code string because it
            // passes through shell32 into msi.dll for resolution. if any function on the path
            // shell32!CShellLink::_DarwinResolve -> msi!MsiDecomposeDescriptorW -> msi!MsiProvideQualifiedComponentW
            // passes the descriptor through a wprintf/wsprintf/StringCchPrintf without "%s" as the format specifier,
            // we get r/w control primitives:
            //   %s/%ls  – deref stack as wchar_t*  → read AV / leak
            //   %n/%hn  – write count to stack ptr → arbitrary write
            //   %N$p    – positional leak, skip ahead
            //   %99999d – blow snprintf length calc            
            const char* payloads[] = {
                // stack walk, leak values
                "%x%x%x%x%x%x%x%x",
                "%p%p%p%p%p%p%p%p",
                "%lx%lx%lx%lx%lx%lx",
                "%llx%llx%llx%llx",

                // arbitrary read, dereference stack as pointer
                "%s%s%s%s%s%s%s%s%s%s",

                // arbitrary write, write byte count to stack address
                "%n%n%n%n",
                "%hn%hn%hn%hn",
                "%hhn%hhn%hhn%hhn",

                // direct parameter access, target specific stack offsets
                "%1$p%2$p%3$p%4$p%5$p%6$p%7$p%8$p",
                "%1$s%2$s%3$s%4$s",
                "%1$n%2$n%3$n%4$n",
                "%1$hhn%2$hhn%3$hhn%4$hhn",

                // width/precision, BOF in snprintf/vsnprintf
                "%9999999x",
                "%.9999999x",
                "%1024d%1024d%1024d%1024d",

                // combined, leak then write
                "%s%n%s%n%s%n",
                "AAAA%08x.%08x.%08x.%08x.%n",
                "%1$p%2$p%3$p%4$p%5$n",
            };

            int count = sizeof(payloads) / sizeof(payloads[0]);
            const char* payload = payloads[lnk_rand(rng) % count];
            size_t payload_len = strlen(payload);
            if(payload_len > 259) payload_len = 259;

            memset(ansi, 0, 260);
            memcpy(ansi, payload, payload_len);

            memset(uni, 0, 520);
            for(size_t i = 0; i < payload_len; i++){
                uni[i*2] = (uint8_t)payload[i];
                uni[i*2 + 1] = 0;
            }

            break;
        }

        case MUTATE_DARWIN_OVERLONG:{
            // fill entire buffer with non-null bytes, no terminator.
            // parser expects null-terminated string within 260 bytes.
            // without terminator, strlen/strcpy reads past buffer, reads
            // whatever comes after the buffer in the ExtraData stream or heap.
            int r = lnk_rand(rng) % 100;
            if(r < 50){
                memset(ansi, 'A', 260); // 'A' easy to read in crash dump or !heap
                for(int i = 0; i < 520; i+=2){
                    uni[i] = 'A';
                    uni[i+1] = 0;
                }
            } else{
                // random non-null bytes
                for(int i = 0; i < 260; i++)
                    ansi[i] = 1 + (lnk_rand(rng) % 255);
                for(int i = 0; i < 520; i+=2){
                    uni[i] = 1 + (lnk_rand(rng) % 255);
                    uni[i+1] = lnk_rand(rng) & 0xFF;
                }
            }
            // explicitly no null term
            break;
        }

        case MUTATE_DARWIN_INVALID_GUID:{
            // Darwin descriptor is parsed by msi!MsiDecomposeDescriptorW
            // which expects a packed descriptor containing:
            //   ProductCode {GUID} – 38 chars
            //   FeatureId   string – var
            //   ComponentId {GUID} – 38 chars
            // a valid GUID is {8-4-4-4-12} hex chars.
            // inject malformed GUIDs to test MSI parser:
            //   unclosed braces, wrong len, non-hex chars, extra dashes
            const char* bad_guids[] = {
                "{00000000-0000-0000-0000-00000000000",     // missing closing brace
                "00000000-0000-0000-0000-000000000000}",    // missing opening brace
                "{ZZZZZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZZZZZZZZZ}",   // non-hex chars
                "{00000000-0000-0000-0000-0000000000000}",  // too long
                "{0000-00000-0000-0000-000000000000}",      // wrong dash positions
                "{}",                                       // empty GUID
                "{00000000}",                               // truncated
                "{{00000000-0000-0000-0000-000000000000}}", // double braces
            };
            int r = lnk_rand(rng) % 8;
            size_t len = strlen(bad_guids[r]);
            if(len > 259) len = 259;

            memset(ansi, 0, 260);
            memcpy(ansi, bad_guids[r], len);

            memset(uni, 0, 520);
            for(size_t i = 0; i < len; i++){
                uni[i*2] = (uint8_t)bad_guids[r][i];
                uni[i*2 + 1] = 0;
            }
            break;
        }

        case MUTATE_DARWIN_NULL_BYTES:{
            // embed null bytes at random positions in the decriptor
            // MSI parser may stop at the first null (truncated parse),
            // while shell32 uses the full 260-byte field.
            // mismatch on string len
            int num_nulls = 1 + (lnk_rand(rng) % 10);
            for(int i = 0; i < num_nulls; i++){
                int pos = lnk_rand(rng) % 259; // not touching last byte
                ansi[pos] = '\0';
                uni[pos * 2] = 0;
                uni[pos * 2 + 1] = 0;
            }
            break;
        }

        case MUTATE_DARWIN_RANDOM:{
            // fill both fields with random bytes
            // no structure, no GUIDs, no null terminators
            // every parsing assumption is violated at once
            for(int i = 0; i < 260; i++)
                ansi[i] = lnk_rand(rng) & 0xFF;
            for(int i = 0; i < 520; i++)
                uni[i] = lnk_rand(rng) & 0xFF;
            break;
        }

        default:
            break;
    }
}

// GROUP_TRACKER TrackerDataBlock
// payload layout inside block->data (88 bytes):
//   [0..4)    Length                            (must be 0x58)
//   [4..8)    Version                           (must be 0)
//   [8..24)   MachineID                         (16 bytes, NULL-terminated NetBIOS name)
//   [24..40)  Droid[0] VolumeID GUID            (contains CrossVolumeMoveFlag in LSB of byte 0)
//   [40..56)  Droid[1] ObjectID GUID            (bytes 10-15 contain MAC address if UUIDv1)
//   [56..72)  DroidBirth[0] BirthVolumeID GUID
//   [72..88)  DroidBirth[1] BirthObjectID GUID
static void apply_tracker(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    ExtraDataBlock* block = find_extra_block(&state->extradata, EXTRA_TRACKER);
    if(!block || !block->data) return;
    if(block->size < 8 + 88) return; // 8 header + 88 payload
    uint8_t* data = block->data;

    switch(op){
        case MUTATE_TRACKER_LENGTH_WRONG:{
            // CTracker::Load checks a3 >= 0x58 AND Length >= 0x58 (NOT exact match)
            // the current spec says MUST be 0x58 but the code still uses >=
            // values below 0x58 return E_INVALIDARG. values above 0x58 pass.
            // on failure, the CALLER (_LoadFromStream) calls CTracker::InitNew.
            uint32_t val;
            int r = lnk_rand(rng) % 100;
            if(r < 20)
                val = 0;     // zero: E_INVALIDARG, tests _InitRPC leak on rejection
            else if(r < 40)
                val = 0x57;  // one byte short, E_INVALIDARG
            else if(r < 60)
                val = 0x59;  // passes >= check, code copies 80 bytes as normal
            else if(r < 75)
                val = 0x100; // passes >= check, but Length field mismatches actual payload size
            else if(r < 90)
                val = 4;     // below 0x58, E_INVALIDARG
            else
                val = lnk_rand(rng) & 0xFFFF;
            memcpy(data, &val, 4);
            break;
        }

        case MUTATE_TRACKER_VERSION_NONZERO:{
            // CTracker::Load checks *(DWORD*)(a2+4) == 0 after Length check.
            // non-zero returns ERROR_UNKNOWN_REVISION (2147943706).
            // content fields are not read before this check, so no partial reads.
            // _InitRPC runs before all checks: upon version rejection, RPC state
            // was initialized but never used. tests if caller cleans up RPC state.
            uint32_t val;
            int r = lnk_rand(rng) % 100;
            if(r < 40)
                val = 1; // min nonzero
            else if(r < 70)
                val = 0xFFFFFFFF; // max, tests signed/unsigned confusion
            else
                val = lnk_rand(rng);
            memcpy(data + 4, &val, 4);
            break;
        }

        case MUTATE_TRACKER_DROID_CORRUPT:{
            // Droid/DroidBirth GUIDs are NOT validated by CTracker::Load (confirmed).
            // raw OWORD copies, no format/null check. 80 bytes copied unconditionally
            // after Length and Version pass.
            //
            // AVs:
            //   . CrossVolumeMoveFlag (LSB of VolumeID byte 0) controls whether
            //     DLT takes same-volume or cross-volume resolution path.
            //     toggling it sends resolution down the wrong path.
            //   
            //   . Droid != DroidBirth triggers cross-volume move resolution
            //     which contacts the MachineID host over SMB.
            //
            //   . all zero GUIDs (GUID_NULL) may pass null ptr checks but
            //     fail NTFS $ObjId lookups in unexpected ways.
            int r = lnk_rand(rng) % 100;
            if(r < 15){
                data[24] ^= 0x01; // flip LSB of VolumeID byte 0 (toggles CrossVolumeMoveFlag)
            } else if(r < 30){
                memset(data + 24, 0, 32); // GUID_NULL Droid for both volume and object
            } else if(r < 45){
                memset(data + 56, 0, 32); // GUID_NULL DroidBirth
            } else if(r < 60){
                memset(data + 24 + (lnk_rand(rng) % 2) * 32, 0xFF, 32); // all 0xFF max GUID values
            } else if(r < 75){
                // make Droid != DroidBirth to trigger cross-volume resolution
                // copy Droid, flip some bytes so they differ
                memcpy(data + 24, data + 56, 32); // start equal
                int num = 1 + (lnk_rand(rng) % 8);
                for(int i = 0; i < num; i++)
                    data[24 + (lnk_rand(rng) % 32)] ^= 1 + (lnk_rand(rng) % 255);
            } else{
                // random bytes in one of the four GUID fields
                int field = lnk_rand(rng) % 4; // 0=VolumeID, 1=ObjectID, 2=BirthVolumeID, 3=BirthObjectID
                int offset = 24 + (field * 16);
                int num = 1 + (lnk_rand(rng) % 8);
                for(int i = 0; i < num; i++)
                    data[offset + (lnk_rand(rng) % 16)] ^= 1 + (lnk_rand(rng) % 255);
            }
            break;
        }

        case MUTATE_TRACKER_MACHINE_ID_CORRUPT:{
            // MachineID is NOT validated by CTracker::Load (confirmed).
            // raw 16-byte OWORD copy into this+72 with no null termination or
            // NetBIOS format check. downstream DLT resolution uses this as a
            // hostname for outbound SMB connection to \\MachineID\pipe\trkwks.
            int r = lnk_rand(rng) % 100;
            if(r < 25){
                // fill all 16 bytes non-zero, no null terminator.
                // trkwks.dll!CRpcClientBinding::RcInitialize calls RaiseIfInvalid
                // which checks byte 15 == 0. all-non-null is caught and throws
                // but CTracker::Load stores the raw bytes at this+72 without
                // checking. any OTHER consumer of MachineID that doesn't call
                // RaiseIfInvalid would hit a strlen overread.
                // also tests whether the exception from RaiseIfInvalid is
                // handled cleanly by the caller.
                for(int i = 8; i < 24; i++)
                    data[i] = 'A' + (lnk_rand(rng) % 26);
            } else if(r < 35){
                // byte 15 = 0x00, bytes 0-14 all non-zero.
                // passes RaiseIfInvalid (byte 15 == 0).
                // strlen returns 15, mbstowcs_s writes 16 wchars into DstBuf[16].
                // an exact fit will test boundary of stack buffer.
                for(int i = 8; i < 23; i++)
                    data[i] = 'A' + (lnk_rand(rng) % 26);
                data[23] = 0x00;
            } else if(r < 40){
                // all null, empty machine name
                memset(data + 8, 0, 16);
            } else if(r < 55){
                // embedded nulls at random positions
                // CTracker::Load copies all 16 bytes (confirmed via RE).
                // CRpcClientBinding::RcInitialize uses manual strlen (confirmed)
                // to measure MachineID before mbstowcs_s conversion.
                // embedded null truncates the hostname — DLT resolves a shorter
                // name than what CTracker stored. bytes after the null sit in
                // the CTracker object but are never used for resolution.
                for(int i = 8; i < 24; i++)
                    data[i] = 'A' + (lnk_rand(rng) % 26);
                int num_nulls = 1 + (lnk_rand(rng) % 4);
                for(int i = 0; i < num_nulls; i++)
                    data[8 + 1 + (lnk_rand(rng) % 14)] = '\0';
            } else if(r < 70){
                // non ASCII bytes, stress codepage conversion.
                // MachineID uses system default codepage (ASCII), high bytes
                // trigger MultiByteToWideChar conversion paths.
                for(int i = 8; i < 24; i++)
                    data[i] = 0x80 + (lnk_rand(rng) % 0x80);
            } else if(r < 85){
                // path separator characters: backslashes and dots.
                // if downstream code concats MachineID into a path
                // without sanitization, these could escape the context
                const char* hostile = "\\\\..\\..\\C$\\";
                size_t len = strlen(hostile);
                memset(data + 8, 0, 16);
                memcpy(data + 8, hostile, len > 15 ? 15 : len);
            } else{
                // fully random bytes
                for(int i = 8; i < 24; i++)
                    data[i] = lnk_rand(rng) & 0xFF;
            }
            break;
        }
        default:
            break;
    }
}

// GROUP_KNOWNFOLDER KnownFolderDataBlock
// payload layout inside block->data (20 bytes):
//   [0..16]   KnownFolderID  GUID
//   [16..20]  Offset         uint32 offset into IDList where the first child segment of the namespace ctx begins
static void apply_knownfolder(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    static const uint8_t KNOWN_FOLDER_GUIDS[][16] = {
        // virtual namespace folders — no filesystem path, create virtual PIDLs
        {0xEB,0x4A,0xA7,0x82,0xB4,0xAE,0x5C,0x46,0xA0,0x14,0xD0,0x97,0xEE,0x34,0x6D,0x63}, // ControlPanelFolder
        {0x2D,0x4E,0xFC,0x76,0xAD,0xD6,0x19,0x45,0xA6,0x63,0x37,0xBD,0x56,0x06,0x81,0x85}, // PrintersFolder
        {0x46,0x40,0x53,0xB7,0xCB,0x3E,0x18,0x4C,0xBE,0x4E,0x64,0xCD,0x4C,0xB7,0xD6,0xAC}, // RecycleBinFolder
        {0xC4,0xEE,0x0B,0xD2,0xA8,0x5C,0x05,0x49,0xAE,0x3B,0xBF,0x25,0x1E,0xA0,0x9B,0x53}, // NetworkFolder
        {0x7C,0x83,0xC0,0x0A,0xF8,0xBB,0x2A,0x45,0x85,0x0D,0x79,0xD0,0x8E,0x66,0x7C,0xA7}, // ComputerFolder
        {0x2B,0xD9,0x0C,0x6F,0x97,0x2E,0xD1,0x45,0x88,0xFF,0xB0,0xD1,0x86,0xB8,0xDE,0xDD}, // ConnectionsFolder

        // writable system folders
        {0x35,0xEA,0xA5,0x82,0xCD,0xD9,0xC5,0x47,0x96,0x29,0xE1,0x5D,0x2F,0x71,0x4E,0x6E}, // CommonStartup
        {0x82,0x5D,0xAB,0x62,0xC1,0xFD,0xC3,0x4D,0xA9,0xDD,0x07,0x0D,0x1D,0x49,0x5D,0x97}, // ProgramData
        {0x0D,0x34,0xAA,0xC4,0x0F,0xF2,0x63,0x48,0xAF,0xEF,0xF8,0x7E,0xF2,0xE6,0xBA,0x25}, // PublicDesktop
    };
    #define KNOWN_FOLDER_GUID_COUNT (sizeof(KNOWN_FOLDER_GUIDS) / sizeof(KNOWN_FOLDER_GUIDS[0]))
    
    ExtraDataBlock* block = find_extra_block(&state->extradata, EXTRA_KNOWN_FOLDER);
    if(!block || !block->data) return;
    if(block->size < 8 + 20) return; // 8 header + 20 payload
    uint8_t* data = block->data;

    switch(op){
        case MUTATE_KNOWNFOLDER_GUID_UNKNOWN:{
            // drive IKnownFolderManager::GetFolder() into a "not found" error path.
            // either pick a known GUID from KNOWN_FOLDER_GUIDS (likely valid but wrong for LNK),
            // or random bytes (almost certainly unregistered). 50/50 split.
            if(lnk_rand_bool(rng, 0.5)){
                int idx = lnk_rand(rng) % KNOWN_FOLDER_GUID_COUNT;
                memcpy(data, KNOWN_FOLDER_GUIDS[idx], 16);
            } else{
                for(int i = 0; i < KNOWN_FOLDER_GUID_COUNT; i++)
                    data[i] = lnk_rand(rng) & 0xFF;
            }
            break;
        }

        case MUTATE_KNOWNFOLDER_OFFSET_OOB:{
            // interesting boundary values that are likely to be past EOF or land mid-structure
            uint32_t boundaries[] = {
                0xFFFFFFFF,                             // MAX_UINT, definitely past EOF
                0x80000000,                             // negative int32, maybe signedness bug
                0xFFFF,                                 // max uint16, maybe casting boundary
                state->linktargetidlist.total_size,     // IDList end
                state->linktargetidlist.total_size + 1, // 1 past
                state->linktargetidlist.total_size - 1, // mid item
                0,                                      // zero offset, refers back to root
                4,                                      // tiny offset, lands inside size prefix of first item in IDList
            };
            uint32_t val = boundaries[lnk_rand(rng) % (sizeof(boundaries) / sizeof(boundaries[0]))];
            memcpy(data + 16, &val, 4);
            break;
        }

        case MUTATE_KNOWNFOLDER_GUID_ZERO:{
            // GUID_NULL. CKnownFolderManager::GetFolder does NOT check the GUID
            // before calling CKFFacade::GetFolderDefinition. an all zero GUID
            // flows straight into the lookup and returns 0x80070002 ERROR_FILE_NOT_FOUND.
            // the value of this mutation is in the error path. it forces the caller into
            // whatever cleanup or fallback code runs on GetFolder failure, which in LNK
            // resolution context means the SpecialFolderDataBlock fallback path if the LNK
            // has one, or outright resolution failure if it doesn't have one.
            memset(data, 0, 16);
            break;
        }

        default:
            break;
    }
}

// GROUP_SPECIALFOLDER SpecialFolderDataBlock
// payload layout inside block->data (16 bytes):
//   [0..4)   SpecialFolderID  CSIDL integer (Constant Special Item ID List)
//   [4..8)   Offset           uint32 offset into IDList for first child segment
//   [8..16)  Reserved         must be zero per spec
static void apply_specialfolder(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    // CSIDL constants of interest. CSIDL_CONTROLS (3) is the CVE-2017-8464
    // attack vector – it switches namespace context to Control Panel and treats
    // the LinkTargetIDList path as a CPL module to LoadLibrary.
    static const uint32_t CSIDL_INTERESTING[] = {
        0x0003, // CSIDL_CONTROLS Control Panel
        0x0014, // CSIDL_FONTS Fonts folder (special namespace handler)
        0x0004, // CSIDL_PRINTERS Printers folder
        0x0008, // CSIDL_STARTUP auto-launch context
        0x0017, // CSIDL_COMMON_STARTUP
        0x0011, // CSIDL_DRIVES My Computer
        0x0012, // CSIDL_NETWORK
        0x000A, // CSIDL_BITBUCKET Recycle Bin
        0x0026, // CSIDL_PROGRAM_FILES
        0x0028, // CSIDL_PROFILE
    };
    #define CSIDL_INTERESTING_COUNT (sizeof(CSIDL_INTERESTING) / sizeof(CSIDL_INTERESTING[0]))

    ExtraDataBlock* block = find_extra_block(&state->extradata, EXTRA_SPECIAL_FOLDER);
    uint8_t* data = NULL;
    if(block && block->data && block->size >= 8 + 16)
        data = block->data;
    
    switch(op){
        // Note: MUTATE_SPECIALFOLDER_INJECT operates on files that DONT have this block.
        // The other operators require the block to exist.
        case MUTATE_SPECIALFOLDER_INJECT:{
            // Inject a SpecialFolderDataBlock (CVE-2017-8464 reproduction)
            // forces _DecodeSpecialFolder to take the SpecialFolderDataBlock
            // fallback path on inputs that wouldn't normally have the block.
            //
            // _DecodeSpecialFolder tries KnownFolderDataBlock first, falls back to
            // SpecialFolderDataBlock only if the known-folder block is absent. With
            // CSIDL_CONTROLS, this routes into SHCloneSpecialIDList -> PIDL walk ->
            // ILCloneCB -> TranslateAliasWithEvent, which is the CVE-2017-8464
            // namespace-switch path. Post-patch _IsRegisteredCPLApplet mitigates
            // the original CPL load, but the surrounding validation and translation
            // code (ILValidateInnerPidlIfRooted, TranslateAliasWithEvent, _SetPIDLPath)
            // was not similarly hardened and remains productive fuzz surface.
            //
            // Offset = 0 is deliberate: it makes v12 == v13 trivially true (both equal
            // the IDList base), which bypasses the item-boundary walk and hands the
            // full IDList to ILCloneCB unchanged.
            if(block) return;
            if(state->extradata.block_count >= MAX_EXTRA_DATA_BLOCKS) return;

            ExtraDataBlock* b = &state->extradata.blocks[state->extradata.block_count++];
            b->type = EXTRA_SPECIAL_FOLDER;
            b->size = 8 + 16;
            b->data = calloc(16, 1);

            if(!b->data){ // fail alloc
                state->extradata.block_count--;
                return;
            }
            b->data_len = 16;

            uint32_t csidl = 0x0003; // CSIDL_CONTROLS
            memcpy(b->data, &csidl, 4);
            // offset = 0 and reserved bytes stay zero from calloc
            break;
        }

        case MUTATE_SPECIALFOLDER_CSIDL:{
            // Reach the PIDL walk and translation code paths that only run when
            // SHCloneSpecialIDList recognizes the CSIDL.
            //
            // _DecodeSpecialFolder's fallback branch calls SHCloneSpecialIDList(0, CSIDL, 0).
            // If it returns NULL, the function exits and nothing downstream runs.
            // If it returns non-null, processing continues into the item boundary walk,
            // ILCloneCB, both ILValidateInnerPidlIfRooted calls, and TranslateAliasWithEvent.
            //
            // The curated CSIDL list is the set of values SHCloneSpecialIDList is known to accept.
            // Random (unassigned) values return NULL and exit early, wasting the mutation.
            // MUTATE_SPECIALFOLDER_RANDOM still exists to occasionally exercise the NULL return path
            // for caller cleanup bugs.
            if(!data) return;
            uint32_t val = CSIDL_INTERESTING[lnk_rand(rng) % CSIDL_INTERESTING_COUNT];
            memcpy(data, &val, 4);
            break;
        }

        case MUTATE_SPECIALFOLDER_RANDOM:{
            // Exercise SHCloneSpecialIDList's NULL return path and the caller cleanup that runs on early exit.
            // 
            // _DecodeSpecialFolder's fallback branch has exactly one branch on the CSIDL value:
            //   SHCloneSpecialIDList returned NULL vs non-null.
            // It does not distinguish between valid and invalid CSIDLs. All unrecognized values
            // produce the same early exit.
            //
            // The usefulness of this operator depends on what the caller does with teh failed decode.
            if(!data) return;
            uint32_t val = lnk_rand(rng); // uniform. any extra weighting would be unjustified bias.
            memcpy(data, &val, 4);
            break;
        }

        case MUTATE_SPECIALFOLDER_OFFSET:{
            // Corrupt the Offset field in ways that defeat or satisfy the
            // SHITEMID boundary walk, driving execution toward different
            // failure paths in _DecodeSpecialFolder.
            //
            // The Offset field tells _DecodeSpecialFolder where inside the IDList
            // the sub-PIDL for the newly-switched-to namespace child context begins.
            // The walk verifies that Offset lands on a real SHITEMID boundary by stepping
            // through items one by one and checking if they arrive exactly at IDList + Offset:
            //
            //   v12 = IDList base
            //   v13 = IDList + Offset          (the sub-PIDL start we expect to reach)
            //   while(v12 && *v12){
            //       if(v12 >= v13) break;
            //       v12 += *(uint16*)v12;      // advance by this SHITEMID's cb
            //   }
            //   if (v12 != v13) goto cleanup;  // Offset must land EXACTLY on an item boundary
            //
            // After the check passes, v13 is passed to ILCloneCB as the sub-PIDL start.
            // This means Offset ultimately controls which portion of the IDList becomes
            // the cloned child PIDL that is validated and handed to TranslateAliasWithEvent.
            if(!data) return;
            // interesting boundary values that are likely to be past EOF or land mid-structure.
            // Past-EOF and mid-item offsets fail the v12 == v13 check and exit early.
            // Offset = 0 satisfies the check trivially (v12 and v13 both equal the IDList base,
            // so the full IDList gets cloned).
            // An Offset landing on a real item boundary (sum of first N items' cb values) satisfies
            // the check and proceeds into ILCloneCB -> ILValidateInnerPidlIfRooted -> TranslateAliasWithEvent,
            // which is where interesting bugs live.
            uint32_t boundaries[] = {
                0,                                      // zero trivially passes the walk check, ILCloneCB gets offset 0
                0xFFFFFFFF,                             // MAX_UINT, definitely past EOF
                0x80000000,                             // negative int32, maybe signedness bug
                0xFFFF,                                 // max uint16, maybe casting boundary
                state->linktargetidlist.total_size,     // IDList end
                state->linktargetidlist.total_size + 1, // 1 past
                state->linktargetidlist.total_size - 1, // 1 short of end, lands one byte before terminator
                4,                                      // 4 bytes in, inside first item's payload; passes only if first item has cb == 4
            };
            uint32_t val = boundaries[lnk_rand(rng) % (sizeof(boundaries) / sizeof(boundaries[0]))];
            memcpy(data + 4, &val, 4);
            break;
        }

        default:
            break;
    }
}

// GROUP_FILE is architecturally different from every other group.
// Other groups operate on LNKGeneratorState (parsed state) and the
// mutations are applied directly to that structure. GROUP_FILE operates
// on the raw byte buffer of the LNK file, which doesn't exist yet when
// op_apply (operator dispatcher) runs.
//
// Design: apply_file does not mutate anything. It stores a post-serialize
// request on the state (postserialize_op + postserialize_arg). After
// serialize() produces the LNK file byte buffer, the harness reads that
// request and applies the actual byte-level mutation (truncate, append, overlap)
// before returning to the fuzzer.
static void apply_file(LNKRand* rng, MutationOperator op, LNKGeneratorState* state){
    switch(op){
        case MUTATE_FILE_TRUNCATE:{
            // cut n bytes off the end of the serialized file
            int r = lnk_rand(rng) % 100;
            int n;
            if(r < 30)
                n = 1 + (lnk_rand(rng) % 8); // tiny, kills ExtraData 4-byte term, parser reads past EOF looking for next block
            else if(r < 60)
                n = 1 + (lnk_rand(rng) % 64); // small, drops an entire ExtraData block, tests handling when a block is declared present but isnt
            else if(r < 85)
                n = 64 + (lnk_rand(rng) % 256); // medium, truncates inside an ExtraData block's payload, produces a block with partial data
            else
                n = 256 + (lnk_rand(rng) % 1024); // large, lands inside PropertyStore or PIDL, produces malformed structure
            state->postserialize_op  = POSTSERIALIZE_TRUNCATE;
            state->postserialize_arg = n;
            break;
        }

        case MUTATE_FILE_APPEND_GARBAGE:{
            // append random bytes after the ExtraData terminator to test whether shell32 keeps reading under any circumstance.
            // the ExtraData parser is supposed to stop at a block with cb 00 (terminator). If it doesn't, if it reads past the
            // terminator and interprets the appended bytes as another block hdr, the mutation effectively produces a block whose
            // size and signature are attacker-controlled. Large appends are weighted higher bc they're more likely to contain
            // plausible looking block headers by chance.
            int r = lnk_rand(rng) % 100;
            int n;
            if(r < 40)
                n = 1 + (lnk_rand(rng) % 16); // small amnt of trailing garbage data
            else if(r < 75)
                n = 16 + (lnk_rand(rng) % 256); // moderate
            else
                n = 256 + (lnk_rand(rng) % 4096); // large, maybe parsed as new block somehow lol
            state->postserialize_op = POSTSERIALIZE_APPEND_GARBAGE;
            state->postserialize_arg = n;
            break;
        }

        case MUTATE_FILE_SECTION_OVERLAP:{
            // request the harness to find a size field and shrink it so the next section overlaps.
            // the section choice is made after serialization because it depends on the byte layout.
            // arg is a hint at which section to target:
            //   0 = IDList
            //   1 = LinkInfo
            //   2 = StringData
            //   3 = First ExtraData block
            state->postserialize_op = POSTSERIALIZE_SECTION_OVERLAP;
            state->postserialize_arg = lnk_rand(rng) % 4;
            break;
        }

        default:
            break;
    }
}

// do mutation
static void op_apply(LNKRand* rng, MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    switch(op_to_group[op]){
        case GROUP_STRUCTURE:     apply_structure(rng, op, state);     break;
        case GROUP_FLAGS:         apply_flags(rng, op, state);         break;
        case GROUP_SIZES:         apply_sizes(rng, op, state, layout); break;
        case GROUP_PIDL:          apply_pidl(rng, op, state);          break;
        case GROUP_OFFSETS:       apply_offsets(rng, op, state);       break;
        case GROUP_EXTRA_SEQ:     apply_extra_seq(rng, op, state);     break;
        case GROUP_EXTRA_HDR:     apply_extra_hdr(rng, op, state);     break;
        case GROUP_PROPSTORE_SET: apply_propstore_set(rng, op, state); break;
        case GROUP_PROPSTORE_VAL: apply_propstore_val(rng, op, state); break;
        case GROUP_PROPSTORE_TPV: apply_propstore_tpv(rng, op, state); break;
        case GROUP_DARWIN:        apply_darwin(rng, op, state);        break;
        case GROUP_TRACKER:       apply_tracker(rng, op, state);       break;
        case GROUP_KNOWNFOLDER:   apply_knownfolder(rng, op, state);   break;
        case GROUP_SPECIALFOLDER: apply_specialfolder(rng, op, state); break;
        case GROUP_FILE:          apply_file(rng, op, state);          break;
        default: break;
    }
}

// Snapshot the layout flags that the scheduler's precondition filter consults
// (which operators are applicable on this sample). The deserializer already
// populates state->core during parsing — we just hand that back. Recomputing
// from the live state instead of trusting the cached field would be defensive
// but redundant; deserialize_lnk and the mutator are the only writers of these
// fields, and the mutator calls this exactly once per round, immediately after
// deserialize, before any operator runs. If a future caller needs a fresh
// layout mid-round, swap the body for an explicit walk over state->extradata
// and state->stringdata.
LNKLayout mutate_extract_layout(LNKGeneratorState* state){
    return state->core;
}

// called once per LnkMutator (i.e., once per worker thread).
// seed comes from the caller — LnkMutator's ctor decides policy.
// Called once at startup, from main() before fuzzer->Run().
// PRNG seeding has moved into LNKPRNG's constructor; this function now
// only initializes the shared scheduler state and the mutex that protects
// it. Calling more than once is harmless on POSIX (re-zeros the prior)
// but undefined on Windows (InitializeCriticalSection isn't idempotent).
void mutate_scheduler_init(void){
#if defined(_WIN32) || defined(WIN32) || defined(__WIN32)
    InitializeCriticalSection(&scheduler_mutex);
#endif
    // POSIX: PTHREAD_MUTEX_INITIALIZER above; nothing to do at runtime.

    // Beta(1, 1) = uniform prior. no belief about any arm's rate yet.
    for(int g = 0; g < GROUP_COUNT; g++){
        group_alpha[g] = 1.0;
        group_beta[g]  = 1.0;
    }
    for(int op = 0; op < MUTATE_COUNT; op++){
        op_alpha[op] = 1.0;
        op_beta[op]  = 1.0;
    }
}

// called by LNKMutator::NotifyResult after Jackalope reports whether the last
// iteration produced new coverage.
// Lock window is just the four increments — single-digit nanoseconds of work
// inside the critical section.
void mutate_report(MutationOperator op, int new_cov){
    if(op < 0 || op >= MUTATE_COUNT) return;
    MutationOperatorGroup g = op_to_group[op];

    scheduler_lock();
    if(new_cov){
        op_alpha[op]   += 1.0;
        group_alpha[g] += 1.0;
    } else{
        op_beta[op]   += 1.0;
        group_beta[g] += 1.0;
    }
    scheduler_unlock();
}

MutationOperator mutate_apply(LNKRand* rng, LNKGeneratorState* state, LNKLayout* layout){
    // Snapshot the shared scheduler arrays under the lock so the rest of
    // the function can sample/decide/mutate without holding it. The lock
    // window is four memcpys — sub-microsecond — vs holding through
    // op_apply, which runs the actual operator and dwarfs the sampling.
    //
    // Effect on the algorithm: two threads racing this path may sample
    // from very-slightly-stale snapshots if mutate_report is also running,
    // but Thompson Sampling is robust to that — staleness on the order of
    // a single update doesn't change which arm wins. The pattern preserves
    // shared learning (every thread's mutate_report still updates the
    // global posterior) while keeping the hot path lock-free.
    double local_group_alpha[GROUP_COUNT];
    double local_group_beta [GROUP_COUNT];
    double local_op_alpha   [MUTATE_COUNT];
    double local_op_beta    [MUTATE_COUNT];

    scheduler_lock();
    memcpy(local_group_alpha, group_alpha, sizeof(group_alpha));
    memcpy(local_group_beta,  group_beta,  sizeof(group_beta));
    memcpy(local_op_alpha,    op_alpha,    sizeof(op_alpha));
    memcpy(local_op_beta,     op_beta,     sizeof(op_beta));
    scheduler_unlock();

    // Lvl 1: Select a group using Thompson Sampling
    // for k = 1..K, sample θ̂_k ~ Beta(α_k, β_k)
    // K = groups
    double best_score = -1.0;
    MutationOperatorGroup chosen_group = 0;
    for(int g = 0; g < GROUP_COUNT; g++){
        double theta = sample_beta(rng, local_group_alpha[g], local_group_beta[g]);
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
        // no valid operators in this group, fall back to any valid operator anywhere
        for(int op = 0; op < MUTATE_COUNT; op++){
            if(!op_precondition(op, state, layout)) continue;
            candidates[count++] = op;
        }
    }

    if(count == 0) return -1; // nothing applicable

    // Thompson sample among candidates
    // K = individual operators
    best_score = -1.0;
    MutationOperator chosen_op = candidates[0];
    for(int i = 0; i < count; i++){
        double s = sample_beta(rng, local_op_alpha[candidates[i]], local_op_beta[candidates[i]]);
        if(s > best_score){
            best_score = s;
            chosen_op = candidates[i];
        }
    }

    // apply mutation. No lock — op_apply touches per-thread state/layout
    // and the per-thread rng, never the shared scheduler arrays.
    op_apply(rng, chosen_op, state, layout);

    return chosen_op;
}