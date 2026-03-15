/**
 * Mutation enums, scheduler structs, function signatures.
 */

#ifndef MUTATE_H
#define MUTATE_H

#include "model.h"

/**
 * Mutation stategies
 */
typedef enum {
    GROUP_STRUCTURE,                    // add/remove sections
    GROUP_FLAGS,                        // bit flips, reserved bits, IsUnicode
    GROUP_OFFSETS,                      // zero, past-EOF, overlap, chain
    GROUP_SIZES,                        // zero, underflow, boundary
    GROUP_PIDL,                         // ItemID manipulation
    GROUP_EXTRA_SEQ,                    // ExtraData block ordering/presence
    GROUP_EXTRA_HDR,                    // ExtraData block header corruption
    GROUP_PROPSTORE_SET,                // Serialized Property Storage
    GROUP_PROPSTORE_VAL,                // Serialized Property Value
    GROUP_PROPSTORE_TPV,                // TypedPropertyValue VARTYPE/padding
    GROUP_DARWIN,                       // DarwinDataBlock payload
    GROUP_TRACKER,                      // TrackerDataBlock payload
    GROUP_KNOWNFOLDER,                  // KnownFolderDataBlock
    GROUP_FILE,                         // whole-file mutations
    GROUP_COUNT
} MutationOperatorGroup;

typedef enum {
    // Structure presence
    MUTATE_STRUCTURE_ADD,
    MUTATE_STRUCTURE_REMOVE,
    MUTATE_STRUCTURE_DESYNC_FLAG,       // flag says present but section absent, or vice versa

    // Flags
    MUTATE_FLAG_SINGLE_BIT,             // flip one bit
    MUTATE_FLAG_ALL_SET,
    MUTATE_FLAG_ALL_CLEAR,
    MUTATE_FLAG_RESERVED_BITS,          // set bits spec says must be zero
    MUTATE_FLAG_DESYNC_ISUNICODE,       // flip IsUnicode — misinterprets all StringData counts

    // Offsets
    MUTATE_OFFSET_ZERO,
    MUTATE_OFFSET_PAST_EOF,
    MUTATE_OFFSET_OVERLAP,              // two offsets point to same region
    MUTATE_OFFSET_WITHIN_HEADER,        // offset lands inside the header itself
    MUTATE_OFFSET_CHAIN,                // offset points into another structure's middle

    // Sizes
    MUTATE_SIZE_ZERO,
    MUTATE_SIZE_UNDERFLOW,              // smaller than minimum valid
    MUTATE_SIZE_DESYNC,                 // size field inconsistent with actual content
    MUTATE_SIZE_BOUNDARY,               // interesting boundary values: MAX, MAX-1, MAX+1

    // PIDL / IDList
    MUTATE_PIDL_REORDER_ITEM,
    MUTATE_PIDL_INSERT_ITEM,
    MUTATE_PIDL_REMOVE_ITEM,
    MUTATE_PIDL_DUPLICATE_ITEM,
    MUTATE_PIDL_PARENT_CHILD_MISMATCH,
    MUTATE_PIDL_CHAIN_TRUNCATION,
    MUTATE_PIDL_TOTAL_SIZE_DESYNC,      // IDListSize field inconsistent with actual items
    MUTATE_PIDL_CLASS_TYPE,             // change abID[0] dispatch byte
    MUTATE_PIDL_DELEGATE_CLSID,         // inject delegate item with random CLSID
    MUTATE_PIDL_MISSING_TERMINAL,       // remove terminal ItemID
    MUTATE_PIDL_NONZERO_TERMINAL,       // terminal item with non-zero size
    MUTATE_PIDL_INNER_CB,               // corrupt inner_cb in delegate item — shifts CLSID read
    MUTATE_PIDL_DEPTH,                  // add many items — stack depth attack

    // ExtraData block sequence
    MUTATE_EXTRA_INSERT_BLOCK,
    MUTATE_EXTRA_REMOVE_BLOCK,
    MUTATE_EXTRA_DUPLICATE_BLOCK,
    MUTATE_EXTRA_REORDER_BLOCKS,
    MUTATE_EXTRA_MISSING_TERMINATOR,
    MUTATE_EXTRA_EARLY_TERMINATOR,
    MUTATE_EXTRA_DOUBLE_TERMINATOR,

    // ExtraData block header
    MUTATE_BLOCK_SIZE_ZERO,
    MUTATE_BLOCK_SIZE_UNDERFLOW,        // < 8, smaller than header
    MUTATE_BLOCK_SIZE_OVERFLOW,         // extends into next block
    MUTATE_BLOCK_SIGNATURE_UNKNOWN,     // unrecognized signature
    MUTATE_BLOCK_SIGNATURE_WRONG,       // valid signature on wrong block type

    // PropertyStore — storage level
    MUTATE_PROPSTORE_STORAGE_SIZE_ZERO,         // treated as terminator — early exit
    MUTATE_PROPSTORE_STORAGE_SIZE_UNDERFLOW,    // < 24, smaller than header
    MUTATE_PROPSTORE_STORAGE_SIZE_DESYNC,       // inconsistent with actual content
    MUTATE_PROPSTORE_STORAGE_SIZE_128MB,        // pushes total over 128MB limit
    MUTATE_PROPSTORE_VERSION_WRONG,             // != 0x53505331
    MUTATE_PROPSTORE_FORMAT_ID_RANDOM,          // unknown GUID
    MUTATE_PROPSTORE_FORMAT_ID_STRING_NAMED,    // force string-named FMTID
    MUTATE_PROPSTORE_NAMING_MISMATCH,           // string FMTID but integer values, or vice versa
    MUTATE_PROPSTORE_DUPLICATE_FORMAT_ID,       // two storages with same FMTID
    MUTATE_PROPSTORE_MISSING_TERMINATOR,        // no 0x00000000 at end of store
    MUTATE_PROPSTORE_EARLY_TERMINATOR,          // terminator before last storage

    // PropertyStore — value level
    MUTATE_PROPSTORE_VALUE_SIZE_ZERO,           // infinite loop in GetValue walker
    MUTATE_PROPSTORE_VALUE_SIZE_UNDERFLOW,      // < 9, smaller than header
    MUTATE_PROPSTORE_VALUE_SIZE_DESYNC,         // inconsistent with actual content
    MUTATE_PROPSTORE_DUPLICATE_PID,             // duplicate property ID in same storage
    MUTATE_PROPSTORE_RESERVED_NONZERO,          // reserved byte != 0x00
    MUTATE_PROPSTORE_MISSING_VALUE_TERMINATOR,  // no 0x00000000 at end of storage

    // PropertyStore — TypedPropertyValue
    MUTATE_PROPSTORE_VT_INVALID,                // undefined/gap VT value
    MUTATE_PROPSTORE_VT_BYREF,                  // VT_BYREF | base_type
    MUTATE_PROPSTORE_VT_VECTOR,                 // VT_VECTOR | base_type
    MUTATE_PROPSTORE_VT_STREAM,                 // VT_STREAM — IStream creation
    MUTATE_PROPSTORE_VT_VARIANT,                // VT_VARIANT — recursive parsing
    MUTATE_PROPSTORE_VT_RESERVED,               // VT_RESERVED — must not appear
    MUTATE_PROPSTORE_PADDING_NONZERO,           // TypedPropertyValue padding != 0
    MUTATE_PROPSTORE_FORCE_MISALIGN,            // craft sizes so valuePtr & 7 != 0

    // Darwin
    MUTATE_DARWIN_FORMAT_STRING,                // inject %s%n into product code
    MUTATE_DARWIN_OVERLONG,                     // product code > 260 chars
    MUTATE_DARWIN_INVALID_GUID,                 // malformed GUID format
    MUTATE_DARWIN_NULL_BYTES,                   // embed null bytes in product code
    MUTATE_DARWIN_RANDOM,                       // fully random bytes

    // Tracker
    MUTATE_TRACKER_LENGTH_WRONG,                // != 0x58
    MUTATE_TRACKER_VERSION_NONZERO,             // must be 0
    MUTATE_TRACKER_DROID_CORRUPT,               // corrupt GUID fields
    MUTATE_TRACKER_MACHINE_ID_CORRUPT,

    // KnownFolder
    MUTATE_KNOWNFOLDER_GUID_UNKNOWN,            // unrecognized GUID
    MUTATE_KNOWNFOLDER_GUID_ZERO,               // all-zero GUID
    MUTATE_KNOWNFOLDER_OFFSET_OOB,              // offset past end of IDList

    // File
    MUTATE_FILE_HEADER_SIZE_WRONG,              // != 0x4C
    MUTATE_FILE_CLSID_CORRUPT,                  // corrupt shell link CLSID
    MUTATE_FILE_TRUNCATE,
    MUTATE_FILE_APPEND_GARBAGE,
    MUTATE_FILE_SECTION_OVERLAP,                // sections overlap in byte layout

    MUTATE_COUNT // must be last
} MutationOperator;

/**
 * Extract layout from a deserialized state
 */
LNKLayout mutate_extract_layout(LNKGeneratorState* state);

/**
 * Initialize scheduler (call once @ startup)
 */
void mutate_scheduler_init(void);

/**
 * Choose a mutation operator, apply it, ret which was used
 */
MutationOperator mutate_apply(LNKGeneratorState* state, LNKLayout* layout);

/**
 * Report coverage result back to scheduler
 */
void mutate_report(MutationOperator op, int new_cov);

#endif