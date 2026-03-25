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
#define HEADER_SIZE               0x4C
#define LF_HAS_LINK_TARGET_IDLIST 0x00000001
#define LF_HAS_LINK_INFO          0x00000002
#define LF_HAS_NAME               0x00000004
#define LF_HAS_RELATIVE_PATH      0x00000008
#define LF_HAS_WORKING_DIR        0x00000010
#define LF_HAS_ARGUMENTS          0x00000020
#define LF_HAS_ICON_LOCATION      0x00000040

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
    // IDListSize describes how many bytes the entire IDList payload
    // occupies. This is used to know where the IDList ends.
    uint16_t idlist_size;
    TRY(read_u16(buf, len, off, &idlist_size));
    pidl->total_size = idlist_size;
    
    // Walk boundary
    // end is the position in buf where the IDList stops.
    // Everything between *off and end is SHITEMID entries.
    size_t end = *off + idlist_size;
    pidl->item_count = 0;

    // SHITEMID read loop
    while(*off + 2 <= end){ // make sure theres room to read 2 bytes
        uint16_t cb; // SHITEMID.cb: total size of the item including cb itself
        TRY(read_u16(buf, len, off, &cb)); // read cb

        if(cb == 0){ // cb of 0 means end of list (terminator)
            pidl->has_terminal = 1;
            break; // never increment item_count, terminator is not an item
        }

        if(cb < 2) return -1;
        uint16_t payload_len = cb - 2; // cb includes itself so - 2

        // get a pointer to the current item in the array
        if(pidl->item_count >= MAX_PIDL_ITEMS) return -1;
        ItemID* item = &pidl->items[pidl->item_count];
        item->size = cb;
        if(payload_len > 0){
            // payload_len is everything after cb
            // payload_len - 1 is everything after the class type byte
            item->payload_len = payload_len - 1; // - 1 because one byte of payload is the class type byte, which gets stored separately.
        }

        // copy the entire SHITEMID as it appeared in the input
        // This raw copy serves two purposes: the serializer can write
        // it back directly, and the mutator can mutate items it doesn't
        // fully understand (IDTYPE_UNKNOWN) by operating on raw bytes.
        item->raw_len = cb;
        item->raw = malloc(cb);
        if(!item->raw) return -1;
        // go back 2 bytes to where cb was, because u already read those
        if(*off - 2 + cb > len) return -1;
        memcpy(item->raw, buf + *off - 2, cb);

        // read the class type (first byte of payload)
        if(payload_len > 0){
            TRY(read_u8(buf, len, off, &item->class_type)); // abID[0]

            // read remaining payload (class_type specific format)
            if(item->payload_len > 0){
                item->payload = malloc(item->payload_len);
                if(!item->payload) return -1;
                TRY(read_bytes(buf, len, off, item->payload, item->payload_len));
            }
        }

        // class type classification
        // This maps the class type byte to the enum so the mutator knows
        // which mutation strategies to apply to this item.
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

        pidl->item_count++; // move to next item, repeats until terminator or end of IDList
    }

    return 0;
}

/**
 * LinkInfo deserialization
 */
static int deserialize_linkinfo(const uint8_t* buf, size_t len, size_t* off, LinkInfoState* info){
    size_t linkinfo_start = *off;

    TRY(read_u32(buf, len, off, &info->link_info_size));
    if(info->link_info_size < 0x1C) return -1; // LinkInfoSize must be minimum 28 bytes
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

    // variable
    if(info->has_volume_id){
        if(info->volume_id_offset & 3) return -1; // VolumeIDOffset must be 4-byte aligned
        size_t volume_id_offset = linkinfo_start + info->volume_id_offset;
        size_t volume_id_start = volume_id_offset;

        TRY(read_u32(buf, len, &volume_id_offset, &info->volume_id.volume_id_size));        // VolumeIDSize
        size_t remaining = (linkinfo_start + info->link_info_size) - volume_id_start;
        if(info->volume_id.volume_id_size > remaining || info->volume_id.volume_id_size < 0x10) return -1;

        TRY(read_u32(buf, len, &volume_id_offset, (uint32_t*)&info->volume_id.drive_type)); // DriveType

        TRY(read_u32(buf, len, &volume_id_offset, &info->volume_id.drive_serial_number));   // SerialNumber

        TRY(read_u32(buf, len, &volume_id_offset, &info->volume_id.volume_label_offset));   // VolumeLabelOffset
        if(info->volume_id.volume_label_offset == 0x14){
            info->volume_id.has_label_unicode = 1;
            if(info->volume_id.volume_id_size < 0x14) return -1;
            TRY(read_u32(buf, len, &volume_id_offset, &info->volume_id.volume_label_offset_unicode));
            if(info->volume_id.volume_label_offset_unicode & 1) return -1; // Unicode offsets must be 2-byte aligned
        }
        
        // read volume label string
        if(info->volume_id.has_label_unicode){
            // unicode
            size_t label_offset = volume_id_start + info->volume_id.volume_label_offset_unicode;
            if(label_offset >= volume_id_start + info->volume_id.volume_id_size) return -1;
            size_t max_bytes = volume_id_start + info->volume_id.volume_id_size - label_offset;
            if(max_bytes > sizeof(info->volume_id.data_unicode)){
                max_bytes = sizeof(info->volume_id.data_unicode);
            }
            memcpy(info->volume_id.data_unicode, buf + label_offset, max_bytes);
        } else{
            // ansi
            size_t label_offset = volume_id_start + info->volume_id.volume_label_offset;
            if(label_offset >= volume_id_start + info->volume_id.volume_id_size) return -1;
            size_t max_bytes = volume_id_start + info->volume_id.volume_id_size - label_offset;
            if(max_bytes > sizeof(info->volume_id.data_ansi)){
                max_bytes = sizeof(info->volume_id.data_ansi);
            }
            memcpy(info->volume_id.data_ansi, buf + label_offset, max_bytes);
        }
    }

    if(info->has_local_base_path){
        size_t lbp_offset = linkinfo_start + info->local_base_path_offset;
        size_t max_bytes = linkinfo_start + info->link_info_size - lbp_offset;
        if(max_bytes > sizeof(info->local_base_path)){
            max_bytes = sizeof(info->local_base_path);
        }
        
        // LocalBasePath string must be null-terminated within bounds
        void* nullpos = memchr(buf + lbp_offset, '\0', max_bytes);
        if(!nullpos) return -1;

        // read null-terminated ANSI string at lbp_offset
        memcpy(info->local_base_path, buf + lbp_offset, max_bytes);
    }

    // CommonPathSuffix (ANSI, always present)
    size_t cps_offset = linkinfo_start + info->common_path_suffix_offset;
    size_t max_bytes = linkinfo_start + info->link_info_size - cps_offset;
    if(max_bytes > sizeof(info->common_path_suffix))
        max_bytes = sizeof(info->common_path_suffix);
    if(info->common_path_suffix_offset >= info->link_info_size) return -1;
    if(!memchr(buf + cps_offset, '\0', max_bytes)) return -1;
    memcpy(info->common_path_suffix, buf + cps_offset, max_bytes);

    // If extended header (>= 0x24) and VolumeIDAndLocalBasePath:
    //  . LocalBasePathUnicode present
    //  . CommonPathSuffixUnicode present
    if(info->link_info_header_size >= 0x24 && info->has_volume_id){
        // both must be < LinkInfoSize
        if(info->local_base_path_offset_unicode >= info->link_info_size) return -1;
        if(info->common_path_suffix_offset_unicode >= info->link_info_size) return -1;

        // both must be 2-byte aligned
        if(info->local_base_path_offset_unicode & 1) return -1;
        if(info->common_path_suffix_offset_unicode & 1) return -1;

        // read both unicode strings (both must pass StringCbLengthW)
        size_t max_bytes;
        // LocalBasePathUnicode
        size_t lbp_uni_offset = linkinfo_start + info->local_base_path_offset_unicode;
        max_bytes = linkinfo_start + info->link_info_size - lbp_uni_offset;

        if(max_bytes > sizeof(info->local_base_path_unicode))
            max_bytes = sizeof(info->local_base_path_unicode);

        if(!memchr(buf + lbp_uni_offset, '\0', max_bytes)) return -1;
        memcpy(info->local_base_path_unicode, buf + lbp_uni_offset, max_bytes);

        info->has_local_base_path_unicode = 1; // set flag after successful read

        // CommonPathSuffixUnicode
        size_t cps_uni_offset = linkinfo_start + info->common_path_suffix_offset_unicode;
        max_bytes = linkinfo_start + info->link_info_size - cps_uni_offset;

        if(max_bytes > sizeof(info->common_path_suffix_unicode))
            max_bytes = sizeof(info->common_path_suffix_unicode);
        
        if(!memchr(buf + cps_uni_offset, '\0', max_bytes)) return -1;
        memcpy(info->common_path_suffix_unicode, buf + cps_uni_offset, max_bytes);
        
        info->has_common_path_suffix_unicode = 1; // set flag after successful read
    }

    // If extended header (>= 0x24) and CommonNetworkRelativeLink:
    //  . CommonPathSuffixUnicode present
    if(info->link_info_header_size >= 0x24 && info->has_common_network_relative_link){
        // must be < LinkInfoSize, 2-byte aligned, string must pass StringCbLengthW
        if(info->common_path_suffix_offset_unicode >= info->link_info_size) return -1;
        if(info->common_path_suffix_offset_unicode & 1) return -1;
        
        size_t cps_uni_offset = linkinfo_start + info->common_path_suffix_offset_unicode;
        size_t max_bytes = linkinfo_start + info->link_info_size - cps_uni_offset;

        if(max_bytes > sizeof(info->common_path_suffix_unicode))
            max_bytes = sizeof(info->common_path_suffix_unicode);
        
        if(!memchr(buf + cps_uni_offset, '\0', max_bytes)) return -1;
        memcpy(info->common_path_suffix_unicode, buf + cps_uni_offset, max_bytes);
        
        info->has_common_path_suffix_unicode = 1; // set flag after successful read
    }
    
    if(info->has_common_network_relative_link){
        if(info->common_network_relative_link_offset & 3) return -1; // CommonNetworkRelativeLinkOffset must be 4-byte aligned
        size_t cnrl_offset = linkinfo_start + info->common_network_relative_link_offset;
        size_t cnrl_start = cnrl_offset;
        CommonNetworkRelativeLink* cnrl = &info->common_network_relative_link;

        TRY(read_u32(buf, len, &cnrl_offset, &cnrl->common_network_relative_link_size));  // CommonNetworkRelativeLinkSize
        if(cnrl->common_network_relative_link_size < 0x14) return -1;

        TRY(read_u32(buf, len, &cnrl_offset, &cnrl->common_network_relative_link_flags)); // CommonNetworkRelativeLinkFlags
        if(cnrl->common_network_relative_link_flags & 0x01){
            cnrl->has_device_name = 1; // bit0 set: HasDeviceName
        }
        
        if(cnrl->common_network_relative_link_flags & 0x02){
            // bit1 set: ValidNetType
            // so network_provider_type is meaningful
            // no extra field to read, just means the value you already read is valid
        }
        
        // offsets
        TRY(read_u32(buf, len, &cnrl_offset, &cnrl->net_name_offset));                    // NetNameOffset (always present)
        TRY(read_u32(buf, len, &cnrl_offset, &cnrl->device_name_offset));                 // DeviceNameOffset
        // DeviceNameOffset must be 0 if ValidDevice not set
        if(!cnrl->has_device_name && cnrl->device_name_offset != 0) return -1;

        TRY(read_u32(buf, len, &cnrl_offset, (uint32_t*)&cnrl->network_provider_type));   // NetworkProviderType
        // NetworkProviderType must be 0 if ValidNetType not set
        if(!(cnrl->common_network_relative_link_flags & 0x02) && cnrl->network_provider_type != 0) return -1;

        if(cnrl->net_name_offset > 0x14){
            cnrl->has_unicode_fields = 1;
            TRY(read_u32(buf, len, &cnrl_offset, &cnrl->net_name_offset_unicode));        // NetNameOffsetUnicode
            TRY(read_u32(buf, len, &cnrl_offset, &cnrl->device_name_offset_unicode));     // DeviceNameOffsetUnicode
        }

        // variable strings
        if(cnrl->has_unicode_fields){
            // NetNameUnicode
            size_t nn_uni_off = cnrl_start + cnrl->net_name_offset_unicode;
            size_t max_bytes = cnrl_start + cnrl->common_network_relative_link_size - nn_uni_off;
            if(max_bytes > sizeof(cnrl->net_name_unicode)) max_bytes = sizeof(cnrl->net_name_unicode);
            if(!memchr(buf + nn_uni_off, '\0', max_bytes)) return -1;
            memcpy(cnrl->net_name_unicode, buf + nn_uni_off, max_bytes);
            cnrl->has_net_name_unicode = 1;

            // DeviceNameUnicode
            if(cnrl->has_device_name){
                size_t dn_uni_off = cnrl_start + cnrl->device_name_offset_unicode;
                max_bytes = cnrl_start + cnrl->common_network_relative_link_size - dn_uni_off;
                if(max_bytes > sizeof(cnrl->device_name_unicode)) max_bytes = sizeof(cnrl->device_name_unicode);
                if(!memchr(buf + dn_uni_off, '\0', max_bytes)) return -1;
                memcpy(cnrl->device_name_unicode, buf + dn_uni_off, max_bytes);
                cnrl->has_device_name_unicode = 1;
            }
        } else{
            // NetName (ANSI, always present)
            size_t nn_off = cnrl_start + cnrl->net_name_offset;
            size_t max_bytes = cnrl_start + cnrl->common_network_relative_link_size - nn_off;
            if(max_bytes > sizeof(cnrl->net_name)) max_bytes = sizeof(cnrl->net_name);
            if(!memchr(buf + nn_off, '\0', max_bytes)) return -1;
            memcpy(cnrl->net_name, buf + nn_off, max_bytes);

            // DeviceName (ANSI, only if ValidDevice)
            if(cnrl->has_device_name){
                size_t dn_off = cnrl_start + cnrl->device_name_offset;
                max_bytes = cnrl_start + cnrl->common_network_relative_link_size - dn_off;
                if(max_bytes > sizeof(cnrl->device_name)) max_bytes = sizeof(cnrl->device_name);
                if(!memchr(buf + dn_off, '\0', max_bytes)) return -1;
                memcpy(cnrl->device_name, buf + dn_off, max_bytes);
            }
        }

    }
    *off = linkinfo_start + info->link_info_size;
    return 0;
}

/**
 * StringData deserialization
 */
static int read_string_field(const uint8_t* buf, size_t len, size_t* off, char** out, uint16_t* out_len, int is_unicode){
    // StringData strings must not be null-terminated
    uint16_t count;
    TRY(read_u16(buf, len, off, &count));

    size_t byte_len;
    if(is_unicode)
        byte_len = (size_t)count * 2;
    else
        byte_len = (size_t)count;

    char* str = malloc(byte_len + 1);
    if(!str) return -1;

    TRY(read_bytes(buf, len, off, str, byte_len));

    str[byte_len] = '\0';

    *out = str;
    *out_len = count;

    return 0;
}

static int deserialize_stringdata(const uint8_t* buf, size_t len, size_t* off, StringDataState* stringdata, uint32_t link_flags){
    // IsUnicode (bit 7) selects between W and A read paths. No validation.
    // Arguments field has no max length cap (a3 = 0). Overlong mutations go here.
    // Other fields capped at 260 by the target.
    // Order is always: Name, RelativePath, WorkingDir, Arguments, IconLocation.
    int is_unicode = 0;
    if(link_flags & 0x80) is_unicode = 1;
    
    if(link_flags & LF_HAS_NAME){
        stringdata->has_name = 1;
        TRY(read_string_field(buf, len, off, &stringdata->name, &stringdata->name_len, is_unicode));
    }
    if(link_flags & LF_HAS_RELATIVE_PATH){
        stringdata->has_relative_path = 1;
        TRY(read_string_field(buf, len, off, &stringdata->relative_path, &stringdata->rel_len, is_unicode));
    }
    if(link_flags & LF_HAS_WORKING_DIR){
        stringdata->has_working_dir = 1;
        TRY(read_string_field(buf, len, off, &stringdata->working_dir, &stringdata->work_len, is_unicode));
    }
    if(link_flags & LF_HAS_ARGUMENTS){
        stringdata->has_arguments = 1;
        TRY(read_string_field(buf, len, off, &stringdata->arguments, &stringdata->arg_len, is_unicode));
    }
    if(link_flags & LF_HAS_ICON_LOCATION){
        stringdata->has_icon_location = 1;
        TRY(read_string_field(buf, len, off, &stringdata->icon_location, &stringdata->icon_len, is_unicode));
    }

    return 0;
}

/**
 * ExtraData deserialization
 * ExtraData block header:
 *  . DWORD BlockSize;
 *  . DWORD BlockSignature;
 *  . BYTE Payload[BlockSize - 8]
 */
static int deserialize_extradata(const uint8_t* buf, size_t len, size_t* off, ExtraDataState* extradata, LNKLayout* layout){
    // Blocks are passed to SHReadDataBlockList, which selectively handles all block signatures and size parsing.
    while(*off + 4 <= len){ // prevent reading past EOF
        // DWORD BlockSize
        uint32_t block_size;
        TRY(read_u32(buf, len, off, &block_size));
        if(block_size < 8) break; // terminator or invalid
        if(extradata->block_count > MAX_EXTRA_DATA_BLOCKS) return -1; // invalid range

        // DWORD BlockSignature
        uint32_t block_signature;
        TRY(read_u32(buf, len, off, &block_signature));

        // BYTE Payload[BlockSize - 8]
        uint32_t payload_len = block_size - 8; // minus size and signature
        ExtraDataBlock* block = &extradata->blocks[extradata->block_count];
        block->size = block_size;

        // BlockSignature type classification
        switch(block_signature){
            case 0xA0000001: block->type = EXTRA_ENVIRONMENT;      break;
            case 0xA0000002: block->type = EXTRA_CONSOLE;          break;
            case 0xA0000004: block->type = EXTRA_CONSOLE_FE;       break;
            case 0xA0000006: block->type = EXTRA_DARWIN;           break;
            case 0xA0000007: block->type = EXTRA_ICON_ENVIRONMENT; break;
            case 0xA000000B: block->type = EXTRA_KNOWN_FOLDER;     break;
            case 0xA0000009: block->type = EXTRA_PROPERTY_STORE;   break;
            case 0xA0000008: block->type = EXTRA_SHIM;             break;
            case 0xA0000005: block->type = EXTRA_SPECIAL_FOLDER;   break;
            case 0xA0000003: block->type = EXTRA_TRACKER;          break;
            case 0xA000000C: block->type = EXTRA_VISTA_IDLIST;     break;
            default:         block->type = EXTRA_TERMINATOR;       break;
        }

        // Store the raw payload which comes after BlockSignature
        if(payload_len > 0){
            block->data = malloc(payload_len);
            if(!block->data) return -1;
            TRY(read_bytes(buf, len, off, block->data, payload_len));
        }

        extradata->block_count++;
    }

    // Set the specific layout flags for whatever the BlockSignature matched
    // Only TrackerDataBlock, DarwinDataBlock, and VistaAndAboveIDListDataBlock
    // are actively interpreted during _LoadFromStream.
    // PropertyStoreDataBlock is lazily parsed upon first property access.
    // All other blocks are stored but not interpreted during load (deserialization).
    for(int i = 0; i < extradata->block_count; i++){
        switch(extradata->blocks[i].type){
            case EXTRA_PROPERTY_STORE: layout->has_propstore_block   = 1; break;
            case EXTRA_DARWIN:         layout->has_darwin_block      = 1; break;
            case EXTRA_TRACKER:        layout->has_tracker_block     = 1; break;
            case EXTRA_KNOWN_FOLDER:   layout->has_knownfolder_block = 1; break;
            default: break;
        }
    }

    if((extradata->block_count > 0))
        layout->has_extradata = 1;

    return 0;
}

/**
 * Core deserialization
 */
int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state){
    memset(state, 0, sizeof(*state));
    size_t off = 0;
    TRY(deserialize_header(buf, len, &off, &state->header, &state->core));
    
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
