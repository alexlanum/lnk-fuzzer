/**
 * parses raw LNK bytes into an LNKGeneratorState
  */
#include "model.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define TRY(expr) do { if ((expr) < 0) return -1; } while (0)

/**
 * helper functions for safe reads
 */
 static inline int safe_read(const uint8_t* buf, size_t buf_len, size_t offset, void* out, size_t n){
    if(offset + n > buf_len) return -1;
    memcpy(out, buf + offset, n);
    return 0;
 }
  
static inline int read_u8(const uint8_t* buf, size_t len, size_t* off, uint8_t* out){
    if(safe_read(buf, len, *off, out, 1) < 0) return -1;
    *off += 1;
    return 0;
}
 
static inline int read_u16(const uint8_t* buf, size_t len, size_t* off, uint16_t* out){
    if(safe_read(buf, len, *off, out, 2) < 0) return -1;
    *off += 2;
    return 0;
}
 
static inline int read_u32(const uint8_t* buf, size_t len, size_t* off, uint32_t* out){
    if(safe_read(buf, len, *off, out, 4) < 0) return -1;
    *off += 4;
    return 0;
}
 
static inline int read_u64(const uint8_t* buf, size_t len, size_t* off, uint64_t* out){
    if(safe_read(buf, len, *off, out, 8) < 0) return -1;
    *off += 8;
    return 0;
}
 
static inline int read_i32(const uint8_t* buf, size_t len, size_t* off, int32_t* out){
    if(safe_read(buf, len, *off, out, 4) < 0) return -1;
    *off += 4;
    return 0;
}
 
static inline int read_bytes(const uint8_t* buf, size_t len, size_t* off, void* out, size_t n){
    if (safe_read(buf, len, *off, out, n) < 0) return -1;
    *off += n;
    return 0;
}

/**
 * constants
 */
static const uint8_t LNK_CLSID[16] = {0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};
#define HEADER_SIZE               0x4C
#define LF_HAS_LINK_TARGET_IDLIST 0x00000001
#define LF_HAS_LINK_INFO          0x00000002
#define LF_HAS_NAME               0x00000004
#define LF_HAS_RELATIVE_PATH      0x00000008
#define LF_HAS_WORKING_DIR        0x00000010
#define LF_HAS_ARGUMENTS          0x00000020
#define LF_HAS_ICON_LOCATION      0x00000040
#define LF_IS_UNICODE             0x00000080

/**
 * ShellLinkHeader deserialization
 */
static int deserialize_header(const uint8_t* buf, size_t len, size_t* off, ShellLinkHeader* hdr, LNKLayout* layout){
    uint32_t header_size;
    TRY(read_u32(buf, len, off, &header_size));
    if(header_size != HEADER_SIZE) return -1;

    uint8_t clsid[16];
    TRY(read_bytes(buf, len, off, clsid, 16));
    if(memcmp(clsid, LNK_CLSID, 16) != 0) return -1;

    TRY(read_u32(buf, len, off, &hdr->link_flags));
    TRY(read_u32(buf, len, off, &hdr->file_attributes));
    TRY(read_u64(buf, len, off, &hdr->creation_time));
    TRY(read_u64(buf, len, off, &hdr->access_time));
    TRY(read_u64(buf, len, off, &hdr->write_time));
    TRY(read_u32(buf, len, off, &hdr->file_size));
    TRY(read_i32(buf, len, off, &hdr->icon_index));
    TRY(read_u32(buf, len, off, &hdr->show_command));
    TRY(read_u16(buf, len, off, &hdr->hot_key));
    TRY(read_u16(buf, len, off, &hdr->reserved1));
    TRY(read_u32(buf, len, off, &hdr->reserved2));
    TRY(read_u32(buf, len, off, &hdr->reserved3));

    // derive layout from LinkFlags
    layout->has_link_target_idlist = (hdr->link_flags & LF_HAS_LINK_TARGET_IDLIST) != 0;
    layout->has_linkinfo           = (hdr->link_flags & LF_HAS_LINK_INFO) != 0;
    layout->has_stringdata         = (hdr->link_flags & (LF_HAS_NAME | LF_HAS_RELATIVE_PATH | LF_HAS_WORKING_DIR | LF_HAS_ARGUMENTS | LF_HAS_ICON_LOCATION)) != 0;
    layout->has_extradata          = 0;

    return 0;
}

/**
 * LinkTargetIDList deserialization
 */
static int deserialize_idlist(const uint8_t* buf, size_t len, size_t* off, LinkTargetIDList* pidl){
    uint16_t idlist_size;
    TRY(read_u16(buf, len, off, &idlist_size));
    pidl->total_size = idlist_size;
    
    size_t end = *off + idlist_size;
    pidl->item_count = 0;

    while(*off + 2 <= end){
        uint16_t cb;
        TRY(read_u16(buf, len, off, &cb));

        if(cb == 0){
            pidl->has_terminal = 1;
            break;
        }

        if(cb < 2) return -1;

        uint16_t payload_len = cb - 2; // cb includes itself so - 2

        if(pidl->item_count >= MAX_PIDL_ITEMS) return -1;
        ItemID* item = &pidl->items[pidl->item_count];
        item->size = cb;
        item->payload_len = (payload_len > 0) ? payload_len - 1 : 0;

        // raw copy of the entire SHITEMID (fallback mutation for unknown class types)
        item->raw_len = cb;
        item->raw = malloc(cb);
        if(!item->raw) return -1;
        // go back 2 bytes to capture cb of raw
        if(*off - 2 + cb > len) return -1;
        memcpy(item->raw, buf + *off - 2, cb);

        // class type is first byte of payload (abID[0])
        if(payload_len > 0){
            TRY(read_u8(buf, len, off, &item->class_type));

            // remaining payload (follows format defined by class_type)
            if(item->payload_len > 0){
                item->payload = malloc(item->payload_len);
                if(!item->payload) return -1;
                TRY(read_bytes(buf, len, off, item->payload, item->payload_len));
            }
        }

        // class type logics
        switch(item->class_type){
            case 0x1F: item->type = IDTYPE_CLSID_ITEM;       break;
            case 0x2F: item->type = IDTYPE_VOLUME_ITEM;      break;
            case 0x31: item->type = IDTYPE_FILESYSTEM_DIR;   break;
            case 0x32: item->type = IDTYPE_FILESYSTEM_FILE;  break;
            case 0x41: item->type = IDTYPE_NETWORK_RESOURCE; break;
            case 0x42: item->type = IDTYPE_NETWORK_SERVER;   break;
            case 0x46: item->type = IDTYPE_NETWORK_SHARE;    break;
            default: item->type = IDTYPE_UNKNOWN; break;
            // There also exist two signature-based class types:
            //  . delegate items
            //  . extension items
            // These cannot be classified from abID[0] alone.
            // TODO: optionally implement later
        }

        pidl->item_count++;
    }

    return 0;
}

/**
 * LinkInfo deserialization
 */
static int deserialize_linkinfo(const uint8_t* buf, size_t len, size_t* off, LinkInfoState* info){
    TRY(read_u32(buf, len, off, &info->link_info_size));
    TRY(read_u32(buf, len, off, &info->link_info_header_size));

    // LinkInfoFlags:
    //  . bit0 VolumeIDAndLocalBasePath
    //  . bit1 CommonNetworkRelativeLinkAndPathSuffix
    TRY(read_u32(buf, len, off, &info->link_info_flags));
    if(info->link_info_flags & 0x01){
        info->has_volume_id = 1;
        info->has_local_base_path = 1;
    }
    if(info->link_info_flags & 0x02){
        info->has_common_network_relative_link = 1;
    }

    // offsets
    TRY(read_u32(buf, len, off, &info->volume_id_offset));
    TRY(read_u32(buf, len, off, &info->local_base_path_offset));
    TRY(read_u32(buf, len, off, &info->common_network_relative_link_offset));
    TRY(read_u32(buf, len, off, &info->common_path_suffix_offset));

    // unicode fields only present if LinkInfoHeaderSize >= 0x24
    if(info->link_info_header_size >= 0x24){
        TRY(read_u32(buf, len, off, &info->local_base_path_offset_unicode));
        TRY(read_u32(buf, len, off, &info->common_path_suffix_offset_unicode));
    }

}

/**
 * StringData deserialization
 */
static int deserialize_stringdata(const uint8_t* buf, size_t len, size_t* off, StringDataState* stringdata, uint32_t link_flags){
    // ill do this
}

/**
 * ExtraData deserialization
 */
static int deserialize_extradata(const uint8_t* buf, size_t len, size_t* off, ExtraDataState* extradata, LNKLayout* layout){
    // ill do this
}

/**
 * Core deserialization
 */
int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state){
    memset(state, 0, sizeof(*state));
    size_t off = 0;
    deserialize_header(buf, len, &off, &state->header, &state->core); // always
    
    // LinkTargetIDList (if HasLinkTargetIDList)
    if(state->core.has_link_target_idlist)
        TRY(deserialize_idlist(buf, len, &off, &state->linktargetidlist));

    // LinkInfo (if HasLinkInfo)
    if(state->core.has_linkinfo)
        TRY(deserialize_linkinfo(buf, len, &off, &state->linkinfo));

    // StringData (if any string flags set)
    if(state->core.has_stringdata)
        TRY(deserialize_stringdata(buf, len, &off, &state->stringdata, state->header.link_flags));

    // ExtraData (not flag controlled, read until null-term)
    if(off < len)
        TRY(deserialize_extradata(buf, len, &off, &state->extradata, &state->core));

    return 0;
}