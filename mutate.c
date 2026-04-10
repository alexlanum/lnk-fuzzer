// Scheduler state
// Scheduler functions
// Mutation operators
#include "mutate.h"
#include "model.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include "clsids.h"

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
        case MUTATE_PIDL_INJECT_CLSID:
        case MUTATE_PIDL_MISSING_TERMINAL:
        case MUTATE_PIDL_NONZERO_TERMINAL:
        case MUTATE_PIDL_DELEGATEITEMID:
            return layout->has_link_target_idlist && state->linktargetidlist.item_count > 0;

        case MUTATE_OFFSET_ZERO:
        case MUTATE_OFFSET_PAST_EOF:
        case MUTATE_OFFSET_OVERLAP:
        case MUTATE_OFFSET_WITHIN_HEADER:
        case MUTATE_OFFSET_CHAIN:
            return layout->has_linkinfo || layout->has_knownfolder_block; // at least one offset field must be present to target

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

// GROUP_SIZES mutation operators, multiple fields targeted
static void apply_sizes(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
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
    int t = targets[rand() % tcount]; // choose a random valid field to mutate

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
                    state->extradata.blocks[rand() % state->extradata.block_count].size = 0;
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
                    state->linkinfo.link_info_size = rand() % 4;
                    break;
                case T_VOLUMEID:
                    // VolumeIDSize < 0x10: fails VolumeID check
                    state->linkinfo.volume_id.volume_id_size = rand() % 0x10;
                    break;
                case T_CNRL:
                    // CNRL size must be >= 0x14    
                    state->linkinfo.common_network_relative_link.common_network_relative_link_size = rand() % 0x14;
                    break;
                case T_EXTRA:
                    // BlockSize must be >= 8
                    state->extradata.blocks[rand() % state->extradata.block_count].size = rand() % 8;
                    break;
                case T_IDLIST:
                    // minimum total_size is 2 (only terminator, two zero bytes): 0 and 1 both underflow
                    state->linktargetidlist.total_size = rand() % 2;
                    break;
                case T_PROPSTORE_STOR:
                    // storage_size < 24 (4 size + 4 version + 16 fmtid)
                    for(int i = 0; i < state->extradata.block_count; i++)
                        if(state->extradata.blocks[i].type == EXTRA_PROPERTY_STORE && state->extradata.blocks[i].data){
                            uint32_t undersized = rand() % 24;
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
                                uint32_t undersized = 1 + (rand() % 8);
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
            int delta = (rand() % 100) - 50;
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
                    state->extradata.blocks[rand() % state->extradata.block_count].size += delta;
                    break;
                default: break;
            }
            break;
        }

        case MUTATE_SIZE_BOUNDARY:{
            uint32_t val = boundaries[rand() % bcount];
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
                    state->extradata.blocks[rand() % state->extradata.block_count].size = val;
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
static void apply_pidl(MutationOperator op, LNKGeneratorState* state){
    // operators manipulate shell items in the items[] array
    LinkTargetIDList* pidl = &state->linktargetidlist;
    switch(op){
        case MUTATE_PIDL_REORDER_ITEM:{
            // swap two random items: parent/child relationship breaks
            if(pidl->item_count < 2) break;
            int i = rand() % pidl->item_count;
            int j;
            do{
                j = rand() % pidl->item_count;
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
            int pos = rand() % (pidl->item_count + 1); // pick a random pos in the list, insert there
            
            // shift existing items right to make a gap for the insertion at the pos we want
            for(int i = pidl->item_count; i > pos; i--)
                pidl->items[i] = pidl->items[i - 1];

            // now that the position is free, build a minimal item there (random class type)
            ItemID* item = &pidl->items[pos];
            memset(item, 0, sizeof(ItemID));
            item->size = 4;                   // cb = 4 (smallest valid: 2 cb + 1 class type + 1 byte)
            item->class_type = rand() & 0xFF; // rndm class type
            item->type = IDTYPE_UNKNOWN;
            item->payload_len = 1;            // 1 byte of payload after class type
            item->payload = malloc(1);
            item->payload[0] = 0;
            item->raw_len = 4;                // raw SHITEMID is 4 bytes total
            item->raw = malloc(4);
            uint16_t cb = 4;
            memcpy(item->raw, &cb, 2);        // bytes 0-1 is cb
            item->raw[2] = item->class_type;  // byte 2 is abID[0] (class type)
            item->raw[3] = rand() & 0xFF;     // byte 3 is payload, random here, doesn't rly matter can be 0 or wateva
            pidl->item_count++;               // +1 item in the list
            break;
        }

        case MUTATE_PIDL_REMOVE_ITEM:{
            // remove a random item in the list, namespace walk is shorter, children lose their parent
            if(pidl->item_count <= 1) break;
            int idx = rand() % pidl->item_count;
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
            int idx = rand() % pidl->item_count;
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
            int i = 1 + (rand() % (pidl->item_count - 1)); // 0 to item_count - 2, skips idx 0 (root item) to keep root valid

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
                new_type = types[rand() % (sizeof(types) / sizeof(types[0]))];
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
            int idx = rand() % pidl->item_count;
            ItemID* item = &pidl->items[idx];
            if(item->payload_len <= 1) break; // ned at least 2 bytes of payload to have a range of possible truncation lengths
            
            // pick a new shorter payload_len
            uint16_t new_len = rand() % item->payload_len;
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
            int r = rand() % 100;
            if(r < 40){
                // off-by-one: most likely to slip past validation
                pidl->total_size += (rand() % 2 == 0) ? 1 : -1;
            }else if(r < 70){
                // small drift: +/- 8 bytes
                pidl->total_size += (rand() % 16) - 8;
            }else if(r < 80){
                // large positive: big overallocation
                pidl->total_size += 500 + (rand() % 1000);
            }else if(r < 90){
                // boundary values
                uint16_t vals[] = {0, 1, 2, 0x7FFF, 0xFFFF};
                pidl->total_size = vals[rand() % 5];
            }else{
                // zero: allocation skipped or fails
                pidl->total_size = 0;
            }
            break;
        }
        
        case MUTATE_PIDL_CLASS_TYPE:{
            if(pidl->item_count < 1) break;
            int idx = rand() % pidl->item_count;
            ItemID* item = &pidl->items[idx];
            // 70% random byte to test undocumented handlers
            // 30% documented type to test known handlers with wrong payload
            if(rand() % 100 < 70)
                item->class_type = rand() & 0xFF;
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
                item->class_type = types[rand() % (sizeof(types) / sizeof(types[0]))];
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
            item->payload[0] = rand() & 0xFF;     // random sort order
            for(int i = 0; i < 16; i++)
                item->payload[1 + i] = rand() & 0xFF; // random GUID
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
            int r = rand() % 100;
            if(r < 50)
                pidl->terminal_value = 1 + (rand() % 10); // small
            else if(r < 80)
                pidl->terminal_value = rand() & 0xFFFF;   // random uint16_t
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
            // not by RegFolder. corrupting them is handled by apply_extra mutation operators
            // and AFL++ havoc on the serialized output. no dedicated fifth case needed here.
            if(pidl->item_count < 1) break;
            int idx = rand() % pidl->item_count;
            ItemID* item = &pidl->items[idx];

            int marker_offset = check_delegate(item->raw, item->raw_len);
            if(marker_offset >= 0){ // is DELEGATEITEMID
                int mode = rand() % 4;
                switch(mode){
                    case 0:{
                        // TARGET: DELEGATEITEMID outer data size field @0x04
                        // in BindToObject dispatch, RegFolder calculates the
                        // marker CLSID position as item + outer data size + 6.
                        // corrupting outer data size displaces that position.
                        // RegFolder will read 16 bytes from the wrong location
                        // and compare them against the marker.
                        uint16_t val;
                        int r = rand() % 100;
                        if(r < 40){
                            val = rand() % 10;     // small, read position is still inside the item buffer
                        } else if(r < 70){
                            val = rand() & 0xFFFF; // land anywhere, unpredictable misalignment
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
                        int byte_offset = marker_offset + (rand() % 16);
                        item->raw[byte_offset] ^= (1 + (rand() % 255)); // change a random byte in marker
                        break;
                    }

                    case 2:{
                        // TARGET: folder class identifier @0x02
                        // RegFolder reaads this to determine which parent folder
                        // type (ex. Control Panel) created this delegate. a wrong
                        // value means the item doesn't match any known parent.
                        // RegFolder may reject, dispatch to another handler, or
                        // process it with wrong assumptions about its outer data.
                        uint16_t val = rand() & 0xFFFF;
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
                        
                        int r = rand() % 100;
                        if(r < 30){
                            // 30% rndm: test error handling when CLSID doesn't exist
                            for(int i = 0; i < 16; i++)
                                item->raw[clsid_offset + i] = rand() & 0xFF;
                        } else{
                            // 70% known IShellFolder: test real handlers receiving
                            // DELEGATEITEMID outer data they weren't designed to parse
                            int ci = rand() % KNOWN_SHELL_CLSIDS_COUNT;
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

            int src = rand() % pidl->item_count;
            ItemID* dupe = &pidl->items[src];

            // fill remaining PIDL with copies
            int capacity = (MAX_PIDL_ITEMS - pidl->item_count);
            // but randomize how many, sometimes moderate depth, sometimes extreme
            int r = rand() % 100;
            if(r < 50){
                capacity = 10 + (rand() % 20); // moderate: 10-29 items
            } else if(r < 80){
                capacity = 30 + (rand() % 30); // deep: 30-59 items
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
static void apply_offsets(MutationOperator op, LNKGeneratorState* state){
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

    int idx = rand() % field_count;
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
            int r = rand() % 100;
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
                *target = 0x10000 + (rand() % 0x10000);
            else // 25%
                // take the current (valid) offset and add 0x400 (1KB) to 0xFC00 (65KB) to it.
                // the offset now points past the end of the section.
                // observes:
                //  . if the parser compares offset against section size before dereferencing
                *target = *target + 0x400 + (rand() % 0xFC00); // cur + large fwd jump
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
                idx2 = rand() % field_count;
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
            *target = header_positions[rand() % (sizeof(header_positions) / sizeof(header_positions[0]))];
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
            *target = chain_positions[rand() % (sizeof(chain_positions) / sizeof(chain_positions[0]))];
            break;
        }

        default: break;
    }
}

// GROUP_EXTRA_SEQ ExtraData block ordering/presence
static void apply_extra_seq(MutationOperator op, LNKGeneratorState* state){
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
            int a = rand() % extra->block_count;
            int b;
            do{
                b = rand() % extra->block_count;
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
            int idx = rand() % extra->block_count;
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
            int src = rand() % extra->block_count;
            ExtraDataBlock* s = &extra->blocks[src]; // random block
            ExtraDataBlock* d = &extra->blocks[extra->block_count]; // end
            d->size = s->size;
            d->type = s->type;
            int data_len = (s->size > 8) ? s->size - 8 : 0;
            if(s->data && data_len > 0){
                d->data = malloc(data_len);
                memcpy(d->data, s->data, data_len);
            } else{
                d->data = NULL;
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
            block->type = types[rand() % 11];

            int data_len = 8 + (rand() % 32); // 8 + 0-31 = 8-39 payload size after the header
            // 8 minimum ensures enough bytes for handlers to start parsing
            // 39 maximum keeps it small enough to pass SHReadDataBlockList validation (< 0xFFFF)
            block->data = calloc(1, data_len);
            for(int i = 0; i < data_len; i++)
                block->data[i] = rand() & 0xFF; // fill payload w random stuff
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
            int pos = rand() % extra->block_count; // insert before this block
            for(int i = extra->block_count; i > pos; i--)
                extra->blocks[i] = extra->blocks[i - 1];
            ExtraDataBlock* b = &extra->blocks[pos];
            memset(b, 0, sizeof(ExtraDataBlock));
            b->size = rand() % 8; // 0-7 size triggers loop termination
            b->type = EXTRA_TERMINATOR;
            b->data = NULL;
            extra->block_count++;
            break;
        }
        
        default: break;
    }
}

// GROUP_EXTRA_HDR ExtraData block header corruption
static void apply_extra_hdr(MutationOperator op, LNKGeneratorState* state){
    // MUTATE_BLOCK_SIZE_ZERO,
    // MUTATE_BLOCK_SIZE_UNDERFLOW,        // < 8, smaller than header
    // MUTATE_BLOCK_SIZE_OVERFLOW,         // extends into next block
    // MUTATE_BLOCK_SIGNATURE_UNKNOWN,     // unrecognized signature
    // MUTATE_BLOCK_SIGNATURE_WRONG,       // valid signature on wrong block type
    ExtraDataState* extra = &state->extradata;
    if(extra->block_count < 1) return;

    int idx = rand() % extra->block_count;
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
            block->size = 1 + (rand() % 7);
            break;
        }

        case MUTATE_BLOCK_SIZE_OVERFLOW:{
            // size > 0xFFFF causes SHReadDataBlockList to seek backward
            // in stream, silently terminates loop
            int r = rand() % 100;
            if(r < 40)
                block->size = 0x10000;                      // past 0xFFFF boundary
            else if(r < 70)
                block->size = 0x10000 + (rand() % 0xF0000); // 64KB-1MB
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
            int r = rand() % 100;
            if(r < 40)
                block->type = EXTRA_TERMINATOR; // maps to unknown signature in serializer
            else if(r < 70)
                block->type = rand() % 12;      // random type from the enum, might collide with real type
            else{
                block->type = EXTRA_TERMINATOR; // unknown signature
                block->size = 8;                // but valid size
            }
            break;
        }

        case MUTATE_BLOCK_SIGNATURE_WRONG:{
            // valid signature paired with wrong block type
            // 
            // example:
            //   swapping payload type to PropertyStore while having a 0xA0000003 BlockSignature
            //   causes SHFindDataBlock to find and return a PropertyStore payload to CTracker::Load.
            //   at this point. CTracker::Load reads fields under wrong assumptions.

            if(extra->block_count == 1){
                // only one ExtraData block.
                // can't swap with another, so change its type
                // to a different known type. the block's payload
                // stays the same, but the serializer writes a dif
                // signature. the handler for the new signature is
                // given the original block's payload.
                ExtraDataType types[] = {
                    EXTRA_ENVIRONMENT, EXTRA_CONSOLE, EXTRA_TRACKER,
                    EXTRA_CONSOLE_FE, EXTRA_SPECIAL_FOLDER, EXTRA_DARWIN,
                    EXTRA_ICON_ENVIRONMENT, EXTRA_PROPERTY_STORE,
                    EXTRA_KNOWN_FOLDER, EXTRA_VISTA_IDLIST, EXTRA_SHIM,
                };
                ExtraDataType new_type;
                do{
                    new_type = types[rand() % 11];
                } while(new_type == block->type); // ensure different type
                block->type = new_type;
            } else{
                // two or more ExtraData blocks.
                // swap types between two blocks.
                // both handlers get each other's payloads.
                int other;
                do{
                    other = rand() % extra->block_count;
                } while(other == idx); // ensure different block index
                ExtraDataType tmp = block->type;
                block->type = extra->blocks[other].type;
                extra->blocks[other].type = tmp;
            }
            break;
        }

        default:
            break;
    }
}

// Serialized Property Storage (property set within property store)
static void apply_propstore_set(MutationOperator op, LNKGeneratorState* state){
    SerializedPropertyStore* ps = &state->propstore;
    if(ps->storage_count < 1) return;

    // pick random storage, mutate storage-level fields
    int idx = rand() % ps->storage_count;
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
            storage->storage_size = 1 + (rand() % 23); // 1-23 (smaller than header)
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
            int r = rand() % 100;
            if(r < 50)
                storage->storage_size += (rand() % 16) - 8; // small drift +/- 8, lands nearby in the next storage's header
            else if(r < 80)
                storage->storage_size = 24 + (rand() % 32); // assign a size that is >= 24 but is likely shorter than the actual storage content
            else
                storage->storage_size = storage->storage_size / 2; // half the actual size
            break;
        }

        case MUTATE_PROPSTORE_STORAGE_SIZE_128MB:{
            // CMemPropStore::SetPropertyStorage rejects if computedSize > 0x08000000 (128MB)
            // one below the boundary passes the check, then CoTaskMemAlloc tries to alloc ~128MB
            // may fail and return NULL
            int r = rand() % 100;
            if(r < 60)
                storage->storage_size = 0x07FFFFFF; // 1 below boundary, passes check, massive alloc
            else
                storage->storage_size = 0x08000001; // 1 past boundary, fails check, tests rejection cleanup
            break;
        }

        case MUTATE_PROPSTORE_VERSION_WRONG:{
            // version must be 0x53505331 ("1SPS")
            // tests s_ValidateStorage rejection cleanup
            int r = rand() % 100;
            if(r < 30)
                storage->version = 0; // zero
            else if(r < 60)
                storage->version = 0x53505332; // "2SPS" off by one
            else if(r < 80)
                storage->version = rand(); // random
            else
                storage->version = 0x53505331 ^ (1 << (rand() % 32)); // single bit flip
            break;
        }

        case MUTATE_PROPSTORE_FORMAT_ID_RANDOM:{
            // unknown FormatID, no property schema registered for it
            // parser may fail to find handlers or fall through to default
            for(int i = 0; i < 16; i++)
                storage->fmtid[i] = rand() & 0xFF;
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
                other = rand() % ps->storage_count;
            } while(other == idx);
            memcpy(storage->fmtid, ps->storages[other].fmtid, 16);
            break;
        }

        case MUTATE_PROPSTORE_EARLY_TERMINATOR:{
            // set a middle storage's size to 0, terminates the walk early
            // storages after it are never processed
            if(ps->storage_count < 2) break;
            int middle = rand() % (ps->storage_count - 1); // not the last one
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
static void apply_propstore_val(MutationOperator op, LNKGeneratorState* state){
    SerializedPropertyStore* ps = &state->propstore;
    if(ps->storage_count < 1) return;

    // pick random storage, pick randome value, mutate value-level fields
    int idx = rand() % ps->storage_count;
    SerializedPropertyStorage* storage = &ps->storages[idx];
    int val_idx = rand() % storage->value_count;
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
                val->string_named.value_size = 1 + (rand() % 8); // 1-9 (not 0, other op handles that)
            else
                val->integer_named.value_size = 1 + (rand() % 8);
            break;
        }

        case MUTATE_PROPSTORE_VALUE_SIZE_DESYNC:{
            // ValueSize is the skip distance to the next value entry in the storage
            // wrong value makes GetValue land mid-field and read garbage as the next
            // value's PropertyID/NameSize/TypedPropertyValue
            int r = rand() % 100;
            if(r < 50){
                // small drift, -8 to +7 range
                if(val->name_scheme == PROPVAL_STRING_NAMED)
                    val->string_named.value_size += (rand() % 16) - 8;
                else
                    val->integer_named.value_size += (rand() % 16) - 8;
            } else if(r < 80){
                // passes < 9 check but wrong
                if(val->name_scheme == PROPVAL_STRING_NAMED)
                    val->string_named.value_size = 9 + (rand() % 32);
                else
                    val->integer_named.value_size = 9 + (rand() % 32);
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
            int a = rand() % storage->value_count;
            int b;
            do{
                b = rand() % storage->value_count;
            } while(b == a);
            storage->values[b].integer_named.property_id = storage->values[a].integer_named.property_id;
            break;
        }

        case MUTATE_PROPSTORE_RESERVED_NONZERO:{
            // reserved byte must be 0x00 according to spec
            // tests if any parser uses this byte as a flag, index, or size
            uint8_t reserved = 1 + (rand() % 255);
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
static void apply_propstore_tpv(MutationOperator op, LNKGeneratorState* state){
    SerializedPropertyStore* ps = &state->propstore;
    if(ps->storage_count < 1) return;

    // pick random storage, pick random value, corrupt TypedPropertyValue fields
    int idx = rand() % ps->storage_count;
    SerializedPropertyStorage* storage = &ps->storages[idx];
    int val_idx = rand() % storage->value_count;
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
            //   0x00-0x0E (VT_EMPTY through VT_DECIMAL)
            //   0x10-0x1F (VT_I1 through VT_LPWSTR)
            //   0x24-0x26 (VT_RECORD, VT_INT_PTR, VT_UINT_PTR)
            //   0x40-0x49 (VT_FILETIME through VT_VERSIONED_STREAM)
            // rejects: negative (bit 15), VT_VECTOR|VT_ARRAY together, everything else.
            // 
            // tests for rejection cleanup:
            //   rejection path in CheckVarType
            //   error handling in Worker
            uint16_t invalid_vartypes[] = {
                0x000F,                         // gap: VT_DECIMAL+1, only gap inside the low range
                0x0020, 0x0021, 0x0022, 0x0023, // gap: after VT_LPWSTR
                0x0027, 0x0028, 0x0030,         // gap: after VT_UINT_PTR
                0x004A, 0x004B, 0x00FF,         // gap: after VT_VERSIONED_STREAM
                0x0100, 0x0200, 0x0FFF,         // mid-range: no handler exists
            };
            tpv->vt = invalid_vartypes[rand() % (sizeof(invalid_vartypes) / sizeof(invalid_vartypes[0]))];
            break;
        }

        case MUTATE_PROPSTORE_VT_BYREF:{
            // attack vector
            // CheckVarType does not check for VT_BYREF:
            //   . a1 < 0 catches VT_RESERVED (0x8000) because int16 makes it negative
            //   . but 0x4000 as int16 is positive (16384), passes the sign check
            //   . base type (lower 12 bits) is whitelisted, passes the switch
            //   . CheckVarType returns 0 (success)
            // then in DeserializeHelper::Worker:
            //   bt di, 0Eh  <-- tests bit 14 (VT_BYREF flag)
            //   jb loc_...  <-- invokes BYREF handler
            // the BYREF handler interprets value bytes as pointer-sized data
            // this is the only modifier flag that passes CheckVarType and reaches
            // a dedicated handler, VT_RESERVED, VT_VECTOR|VT_ARRAY etc. get caught,
            // but VT_BYREF alone slips through.
            uint16_t base_vartypes[] = {
                VT_I2, VT_I4, VT_R4, VT_R8, VT_BSTR, VT_ERROR,
                VT_BOOL, VT_I1, VT_UI1, VT_UI2, VT_UI4,
                VT_I8, VT_UI8, VT_INT, VT_UINT,
                VT_LPSTR, VT_LPWSTR,
            };
            tpv->vt = VT_BYREF | base_vartypes[rand() % (sizeof(base_vartypes) / sizeof(base_vartypes[0]))];
            break;
        }

        case MUTATE_PROPSTORE_VT_VECTOR:{
            // VT_VECTOR (0x1000) triggers count-prefixed array parsing in DeserializeHelper::Worker.
            // CheckVarType allows it: 0x1000 | base_type is positive, and the VT_VECTOR|VT_ARRAY check
            // only rejects when both bits are set. VT_VECTOR alone passes.
            // Worker reads a count from value bytes, allocates count * element_size,
            // then loops reading elements of the vector.
            // corrupted count with small buffer = OOB read
            // corrupted element_size with large count = int overflow in allocation
            uint16_t base_types[] = {
                VT_I2, VT_I4, VT_R4, VT_R8, VT_BSTR,
                VT_BOOL, VT_UI1, VT_UI4, VT_I8, VT_UI8,
                VT_LPSTR, VT_LPWSTR, VT_FILETIME, VT_CLSID,
                VT_VARIANT, // VT_VECTOR | VT_VARIANT = array of nested variants
            };
            tpv->vt = VT_VECTOR | base_types[rand() % (sizeof(base_types) / sizeof(base_types[0]))];
            break;
        }

        case MUTATE_PROPSTORE_VT_STREAM:{
            // VT_STREAM (0x42), VT_STORAGE (0x43), VT_STREAMED_OBJECT (0x44),
            // VT_STORED_OBJECT (0x45) all pass CheckVarType (cases 66-69).
            // StgDeserializePropVariant pre-checks 0x43-0x46 before Worker:
            //   lea eax, [rcx-43h]
            //   test eax, 0FFFFFFF9h
            //   jz loc_...  ← separate handler for storage types
            // these types trigger COM IStream/IStorage creation from value bytes.
            // the separate handler may create COM objects from attacker-controlled data.
            uint16_t stream_types[] = {
                VT_STREAM, VT_STORAGE, VT_STREAMED_OBJECT, VT_STORED_OBJECT,
            };
            tpv->vt = stream_types[rand() % 4];
            break;
        }

        case MUTATE_PROPSTORE_VT_VARIANT:{
            // VT_VARIANT (0x0C) passes CheckVarType (case 12).
            // in Worker's first jump table (byte_18000C6B0), vt 0x0C maps to
            // handler group 6 (default). but in the second jump table
            // (byte_18000C734 / jpt_18000BF21), it maps to handler group 5
            // which calls Worker recursively for nested PROPVARIANT parsing.
            // crafted nesting depth could overflow the stack.
            // crafted inner vt could reach handlers the outer CheckVarType
            // wouldn't normally allow.
            tpv->vt = VT_VARIANT;
            break;
        }

        case MUTATE_PROPSTORE_VT_RESERVED:{
            // VT_RESERVED (0x8000) — bit 15 set.
            // CheckVarType catches it: a1 < 0 (int16 sign check).
            // 0x8000 as int16 = -32768, rejected immediately.
            // this only tests rejection cleanup, not parsing.
            // kept because VT_RESERVED | base_type combinations might
            // behave differently than pure 0x8000 in the error path.
            uint16_t base_types[] = {
                VT_I4, VT_BSTR, VT_BOOL, VT_LPWSTR, VT_FILETIME, VT_CLSID,
            };
            tpv->vt = VT_RESERVED | base_types[rand() % 6];
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
            tpv->padding = 1 + (rand() % 0xFFFE); // 1-0xFFFF, guaranteed non-zero
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
                    val->string_named.value_size += 1 + (rand() % 7);
            } else{
                if((val->integer_named.value_size & 7) == 0)
                    val->integer_named.value_size += 1 + (rand() % 7);
            }
            break;
        }

        default:
            break;
    }
}

// do mutation
static void op_apply(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    switch(op_to_group[op]){
        case GROUP_FLAGS:         apply_flags(op, state);         break;
        case GROUP_SIZES:         apply_sizes(op, state, layout); break;
        case GROUP_PIDL:          apply_pidl(op, state);          break;
        case GROUP_OFFSETS:       apply_offsets(op, state);       break;
        case GROUP_EXTRA_SEQ:     apply_extra_seq(op, state);     break;
        case GROUP_EXTRA_HDR:     apply_extra_hdr(op, state);     break;
        case GROUP_PROPSTORE_SET: apply_propstore_set(op, state); break;
        case GROUP_PROPSTORE_VAL: apply_propstore_val(op, state); break;
        case GROUP_PROPSTORE_TPV: apply_propstore_tpv(op, state); break;
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