// Takes a populated LNKGeneratorState struct and writes it out
// as a raw LNK byte stream that the target parser will consume.
#include "model.h"
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

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
            size_t data_len = wcslen(linkinfo->volume_id.data_unicode) * 2 + 2;
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
        write_bytes(buf, cap, &lbp_offset, linkinfo->local_base_path, lbp_len);
    }

    // CommonNetworkRelativeLink
    if(linkinfo->has_common_network_relative_link){
        size_t cnrl_offset = linkinfo_start + linkinfo->common_network_relative_link_offset;
        CommonNetworkRelativeLink* cnrl = (CommonNetworkRelativeLink*)&linkinfo->common_network_relative_link;
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->common_network_relative_link_size));
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->common_network_relative_link_flags));
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->net_name_offset));
        TRY(write_u32(buf, cap, &cnrl_offset, cnrl->device_name_offset));
        TRY(write_u32(buf, cap, &cnrl_offset, (uint32_t)cnrl->network_provider_type));

        if(cnrl->has_unicode_fields){
            TRY(write_u32(buf, cap, &cnrl_offset, cnrl->net_name_offset_unicode));
            TRY(write_u32(buf, cap, &cnrl_offset, cnrl->device_name_offset_unicode));
        }

        // variable
        // ANSI strings
        size_t netname_offset = linkinfo_start + linkinfo->common_network_relative_link_offset + cnrl->net_name_offset;
        TRY(write_bytes(buf, cap, &netname_offset, cnrl->net_name, strlen(cnrl->net_name) + 1));

        if(cnrl->has_device_name){
            size_t devicename_offset = linkinfo_start + linkinfo->common_network_relative_link_offset + cnrl->device_name_offset;
            TRY(write_bytes(buf, cap, &devicename_offset, cnrl->device_name, strlen(cnrl->device_name) + 1));
        }

        // Unicode strings
        if(cnrl->has_unicode_fields){
            size_t netname_uni = linkinfo_start + linkinfo->common_network_relative_link_offset + cnrl->net_name_offset_unicode;
            TRY(write_bytes(buf, cap, &netname_uni, cnrl->net_name_unicode, wcslen(cnrl->net_name_unicode) * 2 + 2));

            if(cnrl->has_device_name_unicode){
                size_t devicename_uni = linkinfo_start + linkinfo->common_network_relative_link_offset + cnrl->device_name_offset_unicode;
                write_bytes(buf, cap, &devicename_uni, cnrl->device_name_unicode, wcslen(cnrl->device_name_unicode) * 2 + 2);
            }
        }
    }

    // CommonPathSuffix (always present)

    return 0;
}