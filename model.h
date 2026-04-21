#ifndef MODEL_H
#define MODEL_H

#include <stdint.h>
#include <wchar.h>

static const uint8_t LNK_CLSID[16] = {
    0x01, 0x14, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46
};

/**
 * ShellLinkHeader non-constant fields
 */
typedef struct {
    uint32_t link_flags;
    uint32_t file_attributes;

    uint64_t creation_time;
    uint64_t access_time;
    uint64_t write_time;

    uint32_t file_size;
    int32_t  icon_index;

    uint32_t show_command;
    uint16_t hot_key;

    uint16_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} ShellLinkHeader;

/**
 * LinkTargetIDList
 */
#define MAX_PIDL_ITEMS 64

typedef enum {
    IDTYPE_CLSID_ITEM,
    IDTYPE_VOLUME_ITEM,
    IDTYPE_FILESYSTEM_DIR,
    IDTYPE_FILESYSTEM_FILE,
    IDTYPE_NETWORK_RESOURCE,
    IDTYPE_NETWORK_SERVER,
    IDTYPE_NETWORK_SHARE,
    IDTYPE_DELEGATE_ITEM,
    IDTYPE_EXTENSION_ITEM,
    IDTYPE_UNKNOWN
} ItemIDType;

typedef struct {
    /**
     * Dissected SHITEMID representation used by the Shell namespace.
     *
     * Real structure:
     *   uint16_t cb
     *   uint8_t  abID[]
     *
     * The first byte of abID is a class/type indicator that identifies
     * the class/type (if the shell item is type indicator-based) that
     * determines which parser will interpret the remaining payload
     */
    uint16_t size;          // cb
    uint8_t  class_type;    // abID[0]

    /**
     * Remaining bytes of the shell item payload.
     * Interpretation depends on the namespace handler
     * (filesystem, network, CLSID, extension, etc.).
     */
    uint8_t* payload;       // abID[1..]
    uint16_t payload_len;   // size - 3

    /**
     * Raw byte copy of the SHITEMID as it appeared in the input PIDL.
     * This enables the fuzzer to mutate structures it doesn't understand,
     * while still keeping the item valid enough to reach deeper parser code.
     * This situation occurs when the PIDL contains items of unknown structure.
    */
    uint8_t* raw;
    uint16_t raw_len;

    /**
     * Derived classification used internally by the fuzzer to guide
     * mutation strategies. This value is not stored in the actual
     * SHITEMID structure and is inferred from the type indicator byte
     * (`class_type`) and, in many cases, additional payload inspection.
     *
     * This effectively groups shell items into categories (filesystem,
     * network, CLSID, delegate, etc.) so the mutator can apply
     * structure-aware mutations to the payload
     */
    ItemIDType type;
} ItemID;

typedef struct {
    uint16_t total_size;
    ItemID   items[MAX_PIDL_ITEMS]; // the order of items[] defines the namespace traversal
    int      item_count;
    int      has_terminal;
    uint16_t terminal_value; // 0 = normal, non-zero = malformed
} LinkTargetIDList;

/**
 * LinkInfo
 * This appears right after LinkTargetIDList if HasLinkInfo (0x02) is set in the LinkFlags.
 */
typedef enum {
    DRIVE_UNKNOWN       = 0x00000000,
    DRIVE_NO_ROOT_DIR   = 0x00000001,
    DRIVE_REMOVABLE     = 0x00000002,
    DRIVE_FIXED         = 0x00000003,
    DRIVE_REMOTE        = 0x00000004,
    DRIVE_CDROM         = 0x00000005,
    DRIVE_RAMDISK       = 0x00000006,
    // anything beyond 0x06 is undefined by spec
} DriveType;

typedef struct {
    /**
     * Dissected VolumeID
     * Specifies the volume the link target lived on at creation time.
     * Used during resolution to locate the correct volume by serial number.
     */
    uint32_t  volume_id_size;       // must be > 0x10, all offsets within must be < this, all strings within must fit in this.
    DriveType drive_type;           // only valid values are 0x0-0x06
    uint32_t  drive_serial_number;
    uint32_t  volume_label_offset;  // if == 0x14: this field is ignored and VolumeLabelOffsetUnicode is used instead.
    
    // Present only when volume_label_offset == 0x14
    uint32_t  volume_label_offset_unicode;
    int       has_label_unicode;
    
    // Variable data (volume label of the drive as a string).
    char      data_ansi[260];
    wchar_t   data_unicode[260];
} VolumeID;

typedef enum {
    // SDK values (wnnc.h / winnetwk.h) not listed in MS-SHLLINK spec
    WNNC_NET_MSNET       = 0x00010000,
    WNNC_NET_SMB         = 0x00020000, // aka WNNC_NET_LANMAN
    WNNC_NET_NETWARE     = 0x00030000,
    WNNC_NET_VINES       = 0x00040000,
    WNNC_NET_10NET       = 0x00050000,
    WNNC_NET_LOCUS       = 0x00060000,
    WNNC_NET_SUN_PC_NFS  = 0x00070000,
    WNNC_NET_LANSTEP     = 0x00080000,
    WNNC_NET_9TILES      = 0x00090000,
    WNNC_NET_LANTASTIC   = 0x000A0000,
    WNNC_NET_AS400       = 0x000B0000,
    WNNC_NET_FTP_NFS     = 0x000C0000,
    WNNC_NET_PATHWORKS   = 0x000D0000,
    WNNC_NET_LIFENET     = 0x000E0000,
    WNNC_NET_POWERLAN    = 0x000F0000,
    WNNC_NET_BWNFS       = 0x00100000,
    WNNC_NET_COGENT      = 0x00110000,
    WNNC_NET_FARALLON    = 0x00120000,
    WNNC_NET_APPLETALK   = 0x00130000,
    WNNC_NET_INTERGRAPH  = 0x00140000,
    WNNC_NET_SYMFONET    = 0x00150000,
    WNNC_NET_CLEARCASE   = 0x00160000,
    WNNC_NET_FRONTIER    = 0x00170000,
    WNNC_NET_BMC         = 0x00180000,
    WNNC_NET_DCE         = 0x00190000,

    // MS-SHLLINK spec valid values (0x001A0000 – 0x00430000)
    WNNC_NET_AVID        = 0x001A0000,
    WNNC_NET_DOCUSPACE   = 0x001B0000,
    WNNC_NET_MANGOSOFT   = 0x001C0000,
    WNNC_NET_SERNET      = 0x001D0000,
    WNNC_NET_RIVERFRONT1 = 0x001E0000,
    WNNC_NET_RIVERFRONT2 = 0x001F0000,
    WNNC_NET_DECORB      = 0x00200000,
    WNNC_NET_PROTSTOR    = 0x00210000,
    WNNC_NET_FJ_REDIR    = 0x00220000,
    WNNC_NET_DISTINCT    = 0x00230000,
    WNNC_NET_TWINS       = 0x00240000,
    WNNC_NET_RDR2SAMPLE  = 0x00250000,
    WNNC_NET_CSC         = 0x00260000,
    WNNC_NET_3IN1        = 0x00270000,
    WNNC_NET_EXTENDNET   = 0x00290000,
    WNNC_NET_STAC        = 0x002A0000,
    WNNC_NET_FOXBAT      = 0x002B0000,
    WNNC_NET_YAHOO       = 0x002C0000,
    WNNC_NET_EXIFS       = 0x002D0000,
    WNNC_NET_DAV         = 0x002E0000,
    WNNC_NET_KNOWARE     = 0x002F0000,
    WNNC_NET_OBJECT_DIRE = 0x00300000,
    WNNC_NET_MASFAX      = 0x00310000,
    WNNC_NET_HOB_NFS     = 0x00320000,
    WNNC_NET_SHIVA       = 0x00330000,
    WNNC_NET_IBMAL       = 0x00340000,
    WNNC_NET_LOCK        = 0x00350000,
    WNNC_NET_TERMSRV     = 0x00360000,
    WNNC_NET_SRT         = 0x00370000,
    WNNC_NET_QUINCY      = 0x00380000,
    WNNC_NET_OPENAFS     = 0x00390000,
    WNNC_NET_AVID1       = 0x003A0000,
    WNNC_NET_DFS         = 0x003B0000,
    WNNC_NET_KWNP        = 0x003C0000,
    WNNC_NET_ZENWORKS    = 0x003D0000,
    WNNC_NET_DRIVEONWEB  = 0x003E0000,
    WNNC_NET_VMWARE      = 0x003F0000,
    WNNC_NET_RSFX        = 0x00400000,
    WNNC_NET_MFILES      = 0x00410000,
    WNNC_NET_MS_NFS      = 0x00420000,
    WNNC_NET_GOOGLE      = 0x00430000,
    // beyond this: undefined
} NetworkProviderType;

typedef struct {
    /**
     * Dissected CommonNetworkRelativeLink
     * Mutually exclusive with VolumeID.
     * Spec allows both flags to be set simultaneously.
     */
    uint32_t common_network_relative_link_size;  // must be >= 0x14, all offsets within must be < this
    uint32_t common_network_relative_link_flags; // bit0=ValidDevice, bit1=ValidNetType, bits2-31 reserved
    uint32_t net_name_offset;                    // always present
    uint32_t device_name_offset;                 // must be 0 if ValidDevice not set
    NetworkProviderType network_provider_type;   // must be 0 if ValidNetType not set

    uint32_t net_name_offset_unicode;            // present if net_name_offset > 0x14
    uint32_t device_name_offset_unicode;         // present if device_name_offset > 0x14
    int has_unicode_fields;

    // Variable data
    char net_name[4096];               // always present
    char device_name[4096];            // present if ValidDevice set, absent otherwise
    wchar_t net_name_unicode[4096];    // present if net_name_offset > 0x14, absent otherwise
    wchar_t device_name_unicode[4096]; // present if device_name_offset > 0x14, absent otherwise
    
    int has_device_name;
    int has_net_name_unicode;
    int has_device_name_unicode;
} CommonNetworkRelativeLink;

typedef struct {
    uint32_t link_info_size;        // all offsets must be < this, all strings must fit within this
    uint32_t link_info_header_size; // 0x1C = no unicode offsets, >= 0x24 = unicode offsets present
    uint32_t link_info_flags;       // bit0=VolumeIDAndLocalBasePath, bit1=CommonNetworkRelativeLinkAndPathSuffix

    // Offset fields – all relative to the start of LinkInfo
    uint32_t volume_id_offset;
    uint32_t local_base_path_offset;
    uint32_t common_network_relative_link_offset;
    uint32_t common_path_suffix_offset;
    // These two only exist when link_info_header_size >= 0x00000024
    uint32_t local_base_path_offset_unicode;
    uint32_t common_path_suffix_offset_unicode;

    // Presence flags
    int has_volume_id;
    int has_local_base_path;
    int has_common_network_relative_link;
    int has_local_base_path_unicode;      // VolumeIDAndLocalBasePath set AND LinkInfoHeaderSize >= 0x24
    int has_common_path_suffix_unicode;   // LinkInfoHeaderSize >= 0x24

    // Variable data
    VolumeID volume_id;
    CommonNetworkRelativeLink common_network_relative_link;
    char local_base_path[4096];
    char common_path_suffix[4096];            // always present
    wchar_t local_base_path_unicode[4096];    // present only if VolumeIDAndLocalBasePath is set AND LinkInfoHeaderSize >= 0x24
    wchar_t common_path_suffix_unicode[4096]; // present only if LinkInfoHeaderSize >= 0x24
} LinkInfoState;

/**
 * StringData
 * Order is fixed by ShellLinkHeader->LinkFlags, lengths are to be fuzzed.
 * Present if ANY of these flags are set.
 */
typedef struct {
    int has_name;            char* name;            uint16_t name_len;
    int has_relative_path;   char* relative_path;   uint16_t rel_len;
    int has_working_dir;     char* working_dir;     uint16_t work_len;
    int has_arguments;       char* arguments;       uint16_t arg_len;
    int has_icon_location;   char* icon_location;   uint16_t icon_len;
} StringDataState;

/**
 * ExtraData blocks
 * [BlockSize][BlockSignature][payload]
 */
#define MAX_EXTRA_DATA_BLOCKS 32

typedef enum {
    EXTRA_ENVIRONMENT,
    EXTRA_CONSOLE,
    EXTRA_CONSOLE_FE,
    EXTRA_DARWIN,
    EXTRA_ICON_ENVIRONMENT,
    EXTRA_KNOWN_FOLDER,
    EXTRA_PROPERTY_STORE,
    EXTRA_SHIM,
    EXTRA_SPECIAL_FOLDER,
    EXTRA_TRACKER,
    EXTRA_VISTA_IDLIST,
    EXTRA_TERMINATOR
} ExtraDataType;

typedef struct {
    uint32_t      size;
    ExtraDataType type;
    uint8_t*      data; // raw bytes after signature
    /**
     * BYTE 0  – [storage_size]  . 4  bytes: size of this whole storage
     * BYTE 4  – [version]       . 4  bytes: must be "1SPS"
     * BYTE 8  – [fmtid]         . 16 bytes: property set
     * BYTE 24 – [value_size]    . 4  bytes: size of this value entry
     * BYTE 28 – [property_id]   . 4  bytes: property
     * BYTE 32 – [reserved]      . 1  byte
     * BYTE 33 – [typed_value]   . variable: actual property data (ended by terminator) 
     */
} ExtraDataBlock;

typedef struct {
    ExtraDataBlock blocks[MAX_EXTRA_DATA_BLOCKS];
    int block_count;
    int has_terminator;
} ExtraDataState;

/**
 * ExtraData PropertyStoreDataBlock
 */
typedef enum {
    // https://github.com/libyal/libfole/blob/main/documentation/OLE%20definitions.asciidoc
    // Base types
    VT_EMPTY            = 0x0000,
    VT_NULL             = 0x0001,
    VT_I2               = 0x0002,  // 2-byte signed int
    VT_I4               = 0x0003,  // 4-byte signed int
    VT_R4               = 0x0004,  // 4-byte real
    VT_R8               = 0x0005,  // 8-byte real
    VT_CY               = 0x0006,  // currency
    VT_DATE             = 0x0007,
    VT_BSTR             = 0x0008,  // binary string
    VT_DISPATCH         = 0x0009,  // IDispatch pointer [COM]
    VT_ERROR            = 0x000A,  // SCODE / HRESULT
    VT_BOOL             = 0x000B,
    VT_VARIANT          = 0x000C,  // nested PROPVARIANT — recursive parsing [LOOP]
    VT_UNKNOWN          = 0x000D,  // IUnknown pointer [COM]
    VT_DECIMAL          = 0x000E,
    // 0x000F — unassigned gap (fuzz target)
    VT_I1               = 0x0010,
    VT_UI1              = 0x0011,
    VT_UI2              = 0x0012,
    VT_UI4              = 0x0013,
    VT_I8               = 0x0014,
    VT_UI8              = 0x0015,
    VT_INT              = 0x0016,
    VT_UINT             = 0x0017,
    VT_VOID             = 0x0018,
    VT_HRESULT          = 0x0019,
    VT_PTR              = 0x001A,  // pointer type [OOB]
    VT_SAFEARRAY        = 0x001B,  // SAFEARRAY allocation [MEM]
    VT_CARRAY           = 0x001C,  // C-style array
    VT_USERDEFINED      = 0x001D,
    VT_LPSTR            = 0x001E,  // null-terminated ANSI string
    VT_LPWSTR           = 0x001F,  // null-terminated Unicode string
    // 0x0020-0x0023 — unassigned gap (fuzz targets)
    VT_RECORD           = 0x0024,
    VT_INT_PTR          = 0x0025,
    VT_UINT_PTR         = 0x0026,
    // 0x0027-0x003F — unassigned gap (fuzz targets)
    VT_FILETIME         = 0x0040,
    VT_BLOB             = 0x0041,  // size-prefixed blob [MEM]
    VT_STREAM           = 0x0042,  // IStream creation [COM]
    VT_STORAGE          = 0x0043,  // IStorage creation [COM]
    VT_STREAMED_OBJECT  = 0x0044,  // [COM]
    VT_STORED_OBJECT    = 0x0045,  // [COM]
    VT_BLOB_OBJECT      = 0x0046,
    VT_CF               = 0x0047,  // clipboard format
    VT_CLSID            = 0x0048,  // CLSID [COM]
    VT_VERSIONED_STREAM = 0x0049,  // versioned IStream [COM]
    // 0x004A-0x0FFE — unassigned gap

    // Modifier flags — combined with base types via bitwise OR, not standalone values
    VT_VECTOR           = 0x1000,  // VT_VECTOR | base_type — count-prefixed array [LOOP][MEM]
    VT_ARRAY            = 0x2000,  // VT_ARRAY  | base_type — SAFEARRAY [MEM]
    VT_BYREF            = 0x4000,  // VT_BYREF  | base_type — pointer to value [OOB]
    VT_RESERVED         = 0x8000,  // reserved, MUST NOT appear — fuzz target

    // Masks and sentinels — not type values, used for extracting/checking type fields
    VT_TYPEMASK         = 0x0FFF,  // mask to extract base type: vt & VT_TYPEMASK
    VT_ILLEGAL          = 0xFFFF,  // sentinel: invalid/illegal type value
} PropVarType;

static const uint8_t FMTID_STRING_NAMED[16] = {
    /**
     * FMTID {D5CDD505-2E9C-101B-9397-08002B2CF9AE} switches
     * property value format to String Named (user defined properties).
     * If FormatID == this, all values in the store must be String Named.
     * If FormatID != this, all values must be Integer Named.
     */
    0x05, 0xD5, 0xCD, 0xD5, 0x9C, 0x2E, 0x1B, 0x10, 0x93, 0x97, 0x08, 0x00, 0x2B, 0x2C, 0xF9, 0xAE
};

typedef struct {
    /**
     * [vt:2][padding:2][value:var][unknown:variable]
     * Padding is sometimes considered part of the vt.
     * Padding is always 0x0000 in valid data.
     * 
     * During materialization, CMemPropStore::GetValue checks (value & 7) != 0
     * and branches to a LocalAlloc copy path if so. This means misaligned values
     * take a different path than aligned ones.
     * Both paths call propsys.dll!StgDeserializePropVariant, but the misaligned
     * one does so from a temp buffer, while the aligned one calls it directly on
     * the original blob pointer.
     */
    PropVarType vt;
    uint16_t padding;     // must be 0x0000
    uint8_t value[65536]; // variable, interpretation depends on vt

    uint32_t value_len; // how many bytes of value[] are meaningful
} TypedPropertyValue;

typedef struct {
    /**
     * Storage's FormatID != FMTID_STRING_NAMED.
     * Property is identified by an unsigned integer PID.
     * [ValueSize:4][PropertyID:4][Reserved:1][TypedPropertyValue:var]
     * 
     * CMemPropStore::GetValue walks: prop += entry->ValueSize.
     * So ValueSize is the distance to the next value in the store.
     */
    uint32_t value_size;  // includes 4 bytes of itself, this is the skip distance
    uint32_t property_id; // numeric PID, must be unique in storage
    uint8_t reserved;     // must be 0x00
    TypedPropertyValue typed_value;
} SerializedPropertyValueInteger;

typedef struct {
    /**
     * Storage's FormatID == FMTID_STRING_NAMED.
     * Property is identified by a Unicode string name.
     * [ValueSize:4][NameSize:4][Reserved:1][NameString:NameSize][TypedPropertyValue:var]
     */
    uint32_t value_size; // includes 4 bytes of itself
    uint32_t name_size;  // byte count of name string incl. null
    uint8_t reserved;    // must be 0x00
    wchar_t name[4096];  // null terminated Unicode property name
    TypedPropertyValue typed_value;
} SerializedPropertyValueString;

typedef enum {
    PROPVAL_INTEGER_NAMED = 0,  // FormatID != FMTID_STRING_NAMED
    PROPVAL_STRING_NAMED  = 1,  // FormatID == FMTID_STRING_NAMED
} PropValNameScheme;

typedef struct {
    PropValNameScheme name_scheme;
    union {
        SerializedPropertyValueInteger integer_named;
        SerializedPropertyValueString string_named;
    };
} SerializedPropertyValue;

typedef struct {
    /**
     * SerializedPropertyStorage (one property set = one FMTID group)
     * [StorageSize:4][Version:4][FormatID:16][Values:var][Terminator:4 = 0x00000000]
     * 
     * CMemPropStore::SetPropertyStorage does:
     *   chunkSize = *(ULONG*)pStorage;
     *   while(chunkSize != 0) { pStorage += chunkSize; computedSize += chunkSize; }
     * So StorageSize is the distance to the next storage.
     */
    uint32_t storage_size; // includes 4 bytes of itself, this is the skip distance
                           // 0 = early termination
    uint32_t version;      // must be 0x53505331 "1SPS"
    uint8_t  fmtid[16];    // determines name scheme
    
    // Name scheme derived from fmtid – controls which union is active
    PropValNameScheme       name_scheme;
    SerializedPropertyValue values[256];
    int value_count;
    int has_terminator; // whether 0x00000000 is written
} SerializedPropertyStorage;

typedef struct {
    /**
     * SerializedPropertyStore (the full MS-PROPSTORE payload)
     * This is what lives in PropertyStoreDataBlock [payload] after the ExtraData header.
     * [Storage_0:var][Storage_1:var]...[Terminator:4 = 0x00000000]
     * 
     * The MS-PROPSTORE format does not prefix the store with its own size field
     * in this context. The enclosing PropertyStoreDataBlock's BlockSize field
     * already covers the entire payload. The store is terminated by a
     * StorageSize of 0x00000000, not by a prefixed size.
     * 
     * CMemPropStore::SetPropertyStorage walks:
     *   chunkSize = *(ULONG*)pStorage;
     *   while(chunkSize != 0){ pStorage += chunkSize; }
     * 128MB limit check happens after the walk:
     *   if(computedSize > 0x08000000) return E_INVALIDARG;
     */
    SerializedPropertyStorage storages[32];
    int storage_count;
    int has_terminator;
} SerializedPropertyStore;

/**
 * ExtraData TrackerDataBlock (UUID/volume parsing)
 */
typedef struct {
    uint32_t length;         // must be 0x58
    uint32_t version;        // must be 0
    uint32_t machine_id[4];  // NetBIOS name, 16 bytes
    uint8_t  droid[32];      // two GUIDs - birth volume + birth object
    uint8_t  droid_birth[32];
} TrackerDataBlockPayload;

/**
 * ExtraData KnownFolderDataBlock (KNOWNFOLDERID)
 */
typedef struct {
    uint8_t  known_folder_id[16]; // GUID
    uint32_t offset;              // offset into IDList
} KnownFolderDataBlockPayload;

/**
 * LNK file layout model
 * This struct controls which Major optional sections are present in the LNK file.
 */
typedef struct {
    int has_link_target_idlist; // presence controlled by ShellLinkHeader->LinkFlags.
    int has_linkinfo;           // presence controlled by ShellLinkHeader->LinkFlags.
    int has_stringdata;         // presence depends on several LinkFlags (HasName, HasArguments, etc.).
    int has_extradata;          // not controlled by LinkFlags. Parsed until terminating block (BlockSize == 0).

    // ExtraData block presence
    int has_propstore_block;
    int has_darwin_block;
    int has_tracker_block;
    int has_knownfolder_block;
    int has_specialfolder_block;
} LNKLayout;

/**
 * Post-serialization mutation operator. Most mutations operate on the parsed LNKGeneratorState,
 * but GROUP_FILE operates on raw bytes and so it must be applied after serialize() produces the
 * byte buffer (.lnk file). The mutation operator dispatcher (op_apply()) sets these fields; the
 * harness reads them after serialization and applies the corresponding byute-level mutation before
 * submitting the mutated byte buffer to AFL++.
 *
 * postserialize_op == POSTSERIALIZE_NONE means no post-serialize mutation requested.
 */
typedef enum {
    POSTSERIALIZE_NONE = 0,        // deserialize_lnk memset default
    POSTSERIALIZE_TRUNCATE,        // cut off final N bytes. N stored in postserialize_arg
    POSTSERIALIZE_APPEND_GARBAGE,  // append N random bytes. N stored in postserialize_arg
    POSTSERIALIZE_SECTION_OVERLAP, // shrink a section size field so the next section overlaps
} PostSerializeOp;

/**
 * Structured model used to generate and serialize an LNK file.
 * This represents the configuration for all major LNK structures that
 * shall exist when constructing a single input. Each corpus entry
 * corresponds to one LNKGeneratorState instance.
 */
typedef struct {
    LNKLayout        core;
    ShellLinkHeader  header;
    LinkTargetIDList linktargetidlist;
    LinkInfoState    linkinfo;
    StringDataState  stringdata;
    ExtraDataState   extradata;

    // parsed ExtraData block payloads
    SerializedPropertyStore     propstore;
    TrackerDataBlockPayload     tracker;
    KnownFolderDataBlockPayload knownfolder;

    // post-serialization mutation request (set by GROUP_FILE ops)
    int postserialize_op;  // PostSerializeOp value, or POSTSERIALIZE_NONE
    int postserialize_arg; // operator-specific argument (len, offset, etc.)
} LNKGeneratorState;

#endif