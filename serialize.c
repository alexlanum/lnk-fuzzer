// Takes a populated LNKGeneratorState struct and writes it out
// as a raw LNK byte stream that the target parser will consume.
#include "model.h"
#include <string.h>
#include <stdlib.h>
#include <wchar.h>
#include <stdio.h>

#define TRY(expr) do { if ((expr) < 0) return -1; } while (0)

/**
 * helper functions for safe writes
 */
static inline int write_u8(uint8_t* buf, size_t cap, size_t* off, uint8_t val){
    if(*off + 1 > cap) return -1;
    buf[*off] = val;
    *off += 1;
    return 0;
}

static inline int write_u16(uint8_t* buf, size_t cap, size_t* off, uint16_t val){
    if(*off + 2 > cap) return -1;
    memcpy(buf + *off, &val, 2);
    *off += 2;
    return 0;
}

static inline int write_u32(uint8_t* buf, size_t cap, size_t* off, uint32_t val){
    if(*off + 4 > cap) return -1;
    memcpy(buf + *off, &val, 4);
    *off += 4;
    return 0;
}

static inline int write_i32(uint8_t* buf, size_t cap, size_t* off, int32_t val){
    if(*off + 4 > cap) return -1;
    memcpy(buf + *off, &val, 4);
    *off += 4;
    return 0;
}

static inline int write_u64(uint8_t* buf, size_t cap, size_t* off, uint64_t val){
    if(*off + 8 > cap) return -1;
    memcpy(buf + *off, &val, 8);
    *off += 8;
    return 0;
}

static inline int write_bytes(uint8_t* buf, size_t cap, size_t* off, const void* data, size_t n){
    if(*off + n > cap) return -1;
    memcpy(buf + *off, data, n);
    *off += n;
    return 0;
}

static size_t utf16le_bytelen(const void* data, size_t max_bytes){
    const uint8_t* p = (const uint8_t*)data;
    size_t i = 0;
    while(i + 1 < max_bytes){
        if(p[i] == 0 && p[i+1] == 0) break;
        i += 2;
    }
    return i + 2;
}

/**
 * ShellLinkHeader serialization
 */
static int serialize_header(uint8_t* buf, size_t cap, size_t* off, const ShellLinkHeader* header){
    TRY(write_u32(buf, cap, off, 0x4C));                // HeaderSize
    TRY(write_bytes(buf, cap, off, LNK_CLSID, 16));     // LinkCLSID
    TRY(write_u32(buf, cap, off, header->link_flags));
    TRY(write_u32(buf, cap, off, header->file_attributes));
    TRY(write_u64(buf, cap, off, header->creation_time));
    TRY(write_u64(buf, cap, off, header->access_time));
    TRY(write_u64(buf, cap, off, header->write_time));
    TRY(write_u32(buf, cap, off, header->file_size));
    TRY(write_i32(buf, cap, off, header->icon_index));
    TRY(write_u32(buf, cap, off, header->show_command));
    TRY(write_u16(buf, cap, off, header->hot_key));
    TRY(write_u16(buf, cap, off, header->reserved1));
    TRY(write_u32(buf, cap, off, header->reserved2));
    TRY(write_u32(buf, cap, off, header->reserved3));
    return 0;
}

/**
 * LinkTargetIDList serialization
 */
static int serialize_idlist(uint8_t* buf, size_t cap, size_t* off, const LinkTargetIDList* pidl){
    // IDList starts with a 2-byte total size field specifying the size of
    // all SHITEMIDs in the IDList + the terminator. This final size is unknown
    // until after you've written all items, so write a placeholder at the start,
    // write the items, then go back and write to it for this functionality.
    size_t size_off = *off;
    TRY(write_u16(buf, cap, off, 0));

    // write each item's raw bytes to the LNK file (buf)
    for(int i=0; i < pidl->item_count; i++){
        TRY(write_bytes(buf, cap, off, pidl->items[i].raw, pidl->items[i].raw_len));
    }

    // write terminator
    TRY(write_u16(buf, cap, off, 0));

    // write total_size now that you know how many bytes were written
    // *off is current location
    // size_off is where total_size lives in buf at the start
    // - 2 because total_size defines how many bytes of IDList data follow after total_size itself. It doesn't count its own 2 bytes, so subtract your placeholder.
    uint16_t total_size = (uint16_t)(*off - size_off - 2);
    memcpy(buf + size_off, &total_size, 2);

    return 0;
}

/**
 * LinkInfo serialization
 * @param buf       Output byte buffer to write serialized data into (raw bytes that become the LNK file)
 * @param cap       Capacity of buf in bytes, writes beyond this are rejected
 * @param off       Current write position, advanced by the safe write functions as bytes are written
 * @param linkinfo  Source struct to serialize, not modified
 */
static int serialize_linkinfo(uint8_t* buf, size_t cap, size_t* off, const LinkInfoState* linkinfo){
    size_t linkinfo_start = *off; // where LinkInfo begins in the LNK file (buf)

    // header
    TRY(write_u32(buf, cap, off, linkinfo->link_info_size));
    TRY(write_u32(buf, cap, off, linkinfo->link_info_header_size));
    TRY(write_u32(buf, cap, off, linkinfo->link_info_flags));
    TRY(write_u32(buf, cap, off, linkinfo->volume_id_offset));
    TRY(write_u32(buf, cap, off, linkinfo->local_base_path_offset));
    TRY(write_u32(buf, cap, off, linkinfo->common_network_relative_link_offset));
    TRY(write_u32(buf, cap, off, linkinfo->common_path_suffix_offset));

    if(linkinfo->link_info_header_size >= 0x24){
        TRY(write_u32(buf, cap, off, linkinfo->local_base_path_offset_unicode));
        TRY(write_u32(buf, cap, off, linkinfo->common_path_suffix_offset_unicode));
    }

    // variable data (written at offset positions relative to linkinfo_start)
    // var   VolumeID                        . (if flag A set)
    // var   LocalBasePath                   . (if flag A set, null-terminated ANSI)
    // var   CommonNetworkRelativeLink       . (if flag B set)
    // var   CommonPathSuffix                . (always present, null-terminated ANSI)
    // var   LocalBasePathUnicode            . (if flag A set AND header >= 0x24)
    // var   CommonPathSuffixUnicode         . (if header >= 0x24)

    // VolumeID
    if(linkinfo->has_volume_id){
        size_t volumeid_offset = linkinfo_start + linkinfo->volume_id_offset;
        TRY(write_u32(buf, cap, &volumeid_offset, linkinfo->volume_id.volume_id_size));
        TRY(write_u32(buf, cap, &volumeid_offset, (uint32_t)linkinfo->volume_id.drive_type));
        TRY(write_u32(buf, cap, &volumeid_offset, linkinfo->volume_id.drive_serial_number));
        TRY(write_u32(buf, cap, &volumeid_offset, linkinfo->volume_id.volume_label_offset));
    
        if(linkinfo->volume_id.has_label_unicode){
            TRY(write_u32(buf, cap, &volumeid_offset, linkinfo->volume_id.volume_label_offset_unicode));
            size_t data_offset = linkinfo_start + linkinfo->volume_id_offset + linkinfo->volume_id.volume_label_offset_unicode;
            size_t data_len = utf16le_bytelen(linkinfo->volume_id.data_unicode, sizeof(linkinfo->volume_id.data_unicode));
            TRY(write_bytes(buf, cap, &data_offset, linkinfo->volume_id.data_unicode, data_len));
        } else{
            size_t data_offset = linkinfo_start + linkinfo->volume_id_offset + linkinfo->volume_id.volume_label_offset;
            size_t data_len = strlen(linkinfo->volume_id.data_ansi) + 1;
            TRY(write_bytes(buf, cap, &data_offset, linkinfo->volume_id.data_ansi, data_len));
        }
    }

    // LocalBasePath
    if(linkinfo->has_local_base_path){
        size_t lbp_offset = linkinfo_start + linkinfo->local_base_path_offset;
        size_t lbp_len = strlen(linkinfo->local_base_path) + 1;
        TRY(write_bytes(buf, cap, &lbp_offset, linkinfo->local_base_path, lbp_len));
    }

    // CommonNetworkRelativeLink
    if(linkinfo->has_common_network_relative_link){
        size_t cnrl_offset = linkinfo_start + linkinfo->common_network_relative_link_offset;
        CommonNetworkRelativeLink const* cnrl = &linkinfo->common_network_relative_link;

        // constant header fields
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->common_network_relative_link_size));
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->common_network_relative_link_flags));
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->net_name_offset));
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->device_name_offset));
        TRY(write_u32(buf, cap, &cnrl_offset, (uint32_t)cnrl->network_provider_type));
        if(cnrl->has_unicode_fields){
            TRY(write_u32(buf, cap, &cnrl_offset, cnrl->net_name_offset_unicode));
            TRY(write_u32(buf, cap, &cnrl_offset, cnrl->device_name_offset_unicode));
        }

        // variable strings (ANSI and unicode are mutually exclusive)
        size_t cnrl_start = linkinfo_start + linkinfo->common_network_relative_link_offset;
        if(cnrl->has_unicode_fields){
            // NetNameUnicode (always present)
            size_t netname_offset = cnrl_start + cnrl->net_name_offset_unicode;
            TRY(write_bytes(buf, cap, &netname_offset, cnrl->net_name_unicode, utf16le_bytelen(cnrl->net_name_unicode, sizeof(cnrl->net_name_unicode))));
            if(cnrl->has_device_name_unicode){
                size_t devicename_offset = cnrl_start + cnrl->device_name_offset_unicode;
                TRY(write_bytes(buf, cap, &devicename_offset, cnrl->device_name_unicode, utf16le_bytelen(cnrl->device_name_unicode, sizeof(cnrl->device_name_unicode))));
            }
        } else{
            // NetName (always present)
            size_t netname_offset = cnrl_start + cnrl->net_name_offset;
            TRY(write_bytes(buf, cap, &netname_offset, cnrl->net_name, strlen(cnrl->net_name) + 1));
            // DeviceName
            if(cnrl->has_device_name){
                size_t devicename_offset = cnrl_start + cnrl->device_name_offset;
                TRY(write_bytes(buf, cap, &devicename_offset, cnrl->device_name, strlen(cnrl->device_name) + 1));
            }
        }
    }

    // CommonPathSuffix (always present, ANSI string)
    size_t cps_offset = linkinfo_start + linkinfo->common_path_suffix_offset;
    TRY(write_bytes(buf, cap, &cps_offset, linkinfo->common_path_suffix, strlen(linkinfo->common_path_suffix) + 1));

    // Unicode strings
    if(linkinfo->has_local_base_path_unicode){
        size_t lbp_uni = linkinfo_start + linkinfo->local_base_path_offset_unicode;
        TRY(write_bytes(buf, cap, &lbp_uni, linkinfo->local_base_path_unicode, utf16le_bytelen(linkinfo->local_base_path_unicode, sizeof(linkinfo->local_base_path_unicode))));
    }

    if(linkinfo->has_common_path_suffix_unicode){
        size_t cps_uni = linkinfo_start + linkinfo->common_path_suffix_offset_unicode;
        TRY(write_bytes(buf, cap, &cps_uni, linkinfo->common_path_suffix_unicode, utf16le_bytelen(linkinfo->common_path_suffix_unicode, sizeof(linkinfo->common_path_suffix_unicode))));
    }

    // advance offset past entire LinkInfo so the next section (StringData or ExtraData) starts at the right pos
    *off = linkinfo_start + linkinfo->link_info_size;

    return 0;
}

/**
 * StringData serialization
 */
static int write_string_field(uint8_t* buf, size_t cap, size_t* off, const char* str, uint16_t count, int is_unicode){
    // StringData strings must not be null-terminated
    TRY(write_u16(buf, cap, off, count));

    size_t byte_len;
    if(is_unicode)
        byte_len = (size_t)count * 2;
    else
        byte_len = (size_t)count;
    
    TRY(write_bytes(buf, cap, off, str, byte_len));

    return 0;
}

static int serialize_stringdata(uint8_t* buf, size_t cap, size_t* off, const StringDataState* stringdata, int is_unicode){
    if(stringdata->has_name)
        TRY(write_string_field(buf, cap, off, stringdata->name, stringdata->name_len, is_unicode));
    if(stringdata->has_relative_path)
        TRY(write_string_field(buf, cap, off, stringdata->relative_path, stringdata->rel_len, is_unicode));
    if(stringdata->has_working_dir)
        TRY(write_string_field(buf, cap, off, stringdata->working_dir, stringdata->work_len, is_unicode));
    if(stringdata->has_arguments)
        TRY(write_string_field(buf, cap, off, stringdata->arguments, stringdata->arg_len, is_unicode));
    if(stringdata->has_icon_location)
        TRY(write_string_field(buf, cap, off, stringdata->icon_location, stringdata->icon_len, is_unicode));
    
    return 0;
}

/**
 * ExtraData serialization
 */
static int serialize_extradata(uint8_t* buf, size_t cap, size_t* off, const ExtraDataState* extradata){
    for(int i=0; i < extradata->block_count; i++){
        ExtraDataBlock const* block = &extradata->blocks[i];

        // BlockSize
        TRY(write_u32(buf, cap, off, block->size));

        // BlockSignature.
        // Prefer the raw signature deserialize captured (preserves unknown sigs across
        // a roundtrip). Fall back to the type→sig table only when `signature` is zero —
        // that path covers blocks the mutator constructs from scratch without populating
        // the field.
        uint32_t sig = block->signature;
        if(sig == 0){
            switch(block->type){
                case EXTRA_ENVIRONMENT:      sig = 0xA0000001; break;
                case EXTRA_CONSOLE:          sig = 0xA0000002; break;
                case EXTRA_TRACKER:          sig = 0xA0000003; break;
                case EXTRA_CONSOLE_FE:       sig = 0xA0000004; break;
                case EXTRA_SPECIAL_FOLDER:   sig = 0xA0000005; break;
                case EXTRA_DARWIN:           sig = 0xA0000006; break;
                case EXTRA_ICON_ENVIRONMENT: sig = 0xA0000007; break;
                case EXTRA_SHIM:             sig = 0xA0000008; break;
                case EXTRA_PROPERTY_STORE:   sig = 0xA0000009; break;
                case EXTRA_KNOWN_FOLDER:     sig = 0xA000000B; break;
                case EXTRA_VISTA_IDLIST:     sig = 0xA000000C; break;
                case EXTRA_UNKNOWN:          sig = 0xA00000FF; break; // placeholder unrecognized sig
                case EXTRA_TERMINATOR:       sig = 0x00000000; break; // shouldn't reach here for size>=8 blocks
                default:                     sig = 0x00000000; break;
            }
        }
        TRY(write_u32(buf, cap, off, sig));

        // Payload[BlockSize - 8]
        if(((block->size - 8) > 0) && block->data){
            TRY(write_bytes(buf, cap, off, block->data, block->size - 8));
        }
    }

    // terminator ExtraDataBlock
    TRY(write_u32(buf, cap, off, 0)); // when parser reads the next block and sees BlockSize < 8 it stops

    return 0;
}

/**
 * Core serialization
 */
int serialize_lnk(uint8_t* buf, size_t cap, size_t* out_len, const LNKGeneratorState* state){
    size_t offset = 0;

    TRY(serialize_header(buf, cap, &offset, &state->header));

    if(state->core.has_link_target_idlist)
        TRY(serialize_idlist(buf, cap, &offset, &state->linktargetidlist));

    if(state->core.has_linkinfo)
        TRY(serialize_linkinfo(buf, cap, &offset, &state->linkinfo));

    int is_unicode = (state->header.link_flags & 0x80) != 0;
    if(state->core.has_stringdata)
        TRY(serialize_stringdata(buf, cap, &offset, &state->stringdata, is_unicode));

    if(state->core.has_extradata)
        TRY(serialize_extradata(buf, cap, &offset, &state->extradata));

    *out_len = offset;

    return 0;
}