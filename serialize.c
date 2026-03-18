// Takes a populated LNKGeneratorState struct and writes it out
// as a raw LNK byte stream that the target parser will consume.
#include "model.h"
#include <string.h>
#include <stdlib.h>

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