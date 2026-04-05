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
    //   volume_id_offset
    //   local_base_path_offset
    //   common_network_relative_link_offset
    //   common_path_suffix_offset
    //   local_base_path_offset_unicode
    //   common_path_suffix_offset_unicode

    // CommonNetworkRelativeLink (inside LinkInfo):
    //   net_name_offset
    //   device_name_offset

    // SpecialFolderDataBlock:
    //   offset (PIDL index — CVE-2017-8464 attack surface)

    // KnownFolderDataBlock:
    //   offset (PIDL index — CVE-2017-8464 attack surface)

    uint32_t* offset_fields[12];
    int count = 0;

    if(state->core.has_linkinfo){
        // offset field slots are always in the 0x1C header regardless of LinkInfoFlags
        // parser only follows them when the corresponding flags are set
        offset_fields[count++] = &state->linkinfo.volume_id_offset;
        offset_fields[count++] = &state->linkinfo.local_base_path_offset;
        offset_fields[count++] = &state->linkinfo.common_network_relative_link_offset;
        offset_fields[count++] = &state->linkinfo.common_path_suffix_offset;

        // unicode offsets only present when LinkInfoHeaderSize >= 0x24
        if(state->linkinfo.link_info_header_size >= 0x24){
            offset_fields[count++] = &state->linkinfo.local_base_path_offset_unicode;
            offset_fields[count++] = &state->linkinfo.common_path_suffix_offset_unicode;
        }

        // CNRL has its own pair of offsets for the two name strings
        if(state->linkinfo.has_common_network_relative_link){
            offset_fields[count++] = &state->linkinfo.common_network_relative_link.net_name_offset;
            offset_fields[count++] = &state->linkinfo.common_network_relative_link.device_name_offset;
        }
    }

    // SpecialFolderDataBlock and KnownFolderDataBlock offsets
    // these are PIDL indices, not byte offsets into LinkInfo
    // but the mutation strategies still apply
    for(int i = 0; i < state->extradata.block_count; i++){
        ExtraDataBlock* blk = &state->extradata.blocks[i];
        if(blk->type == EXTRA_SPECIAL_FOLDER && blk->data){
            // payload layout: [SpecialFolderID:4][Offset:4]
            offset_fields[count++] = (uint32_t*)(blk->data + 4);
        } else if(blk->type == EXTRA_KNOWN_FOLDER && blk->data){
            // payload layout: [KnownFolderID:16][Offset:4]
            offset_fields[count++] = (uint32_t*)(blk->data + 16);
        }
    }

    if(count == 0) return;

    int idx = rand() % count;
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
            // parser dereferences beyond valid data, reaching adjacent sections or unmapped memory
            int r = rand() % 3;
            if(r == 0)
                *target = 0xFFFFFFFF;                           // max: guaranteed OOB
            else if(r == 1)
                *target = 0x10000 + (rand() % 0x10000);         // 64KB–128KB: past any real LinkInfo
            else
                *target = *target + 0x400 + (rand() % 0xFC00);  // current + large forward delta
            break;
        }

        case MUTATE_OFFSET_OVERLAP:{
            // set this offset to the value of another field: two parsers read the same bytes
            // with different type assumptions (e.g. VolumeID parser and CNRL parser both
            // start at the same location, interpreting the same bytes as different structures)
            if(count < 2){
                // only one field: nudge it to create partial overlap with adjacent bytes
                uint32_t delta = 1 + (rand() % 4);
                *target = (*target >= delta) ? (*target - delta) : (*target + delta);
            } else {
                int other = idx;
                while(other == idx) other = rand() % count;
                *target = *offset_fields[other];
            }
            break;
        }

        case MUTATE_OFFSET_WITHIN_HEADER:{
            // offset lands inside the structure's own fixed-size header:
            // parser expects a string or substructure but reads size/flags/offset bytes instead.
            // LinkInfo header occupies 0x00–0x1B (standard) or 0x00–0x23 (with unicode offsets).
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

// do mutation
static void op_apply(MutationOperator op, LNKGeneratorState* state, LNKLayout* layout){
    switch(op_to_group[op]){
        case GROUP_FLAGS:   apply_flags(op, state);         break;
        case GROUP_SIZES:   apply_sizes(op, state, layout); break;
        case GROUP_PIDL:    apply_pidl(op, state);          break;
        case GROUP_OFFSETS: apply_offsets(op, state);       break;
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