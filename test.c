#include "model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);
int serialize_lnk(uint8_t* buf, size_t cap, size_t* out_len, const LNKGeneratorState* state);
void create_cpanel_lnk(void) {
    LNKGeneratorState state;
    memset(&state, 0, sizeof(state));

    state.header.link_flags = 0x01;
    state.header.show_command = 1;
    state.core.has_link_target_idlist = 1;

    LinkTargetIDList* pidl = &state.linktargetidlist;
    pidl->item_count = 1;
    pidl->has_terminal = 1;

    // Control Panel CLSID: {21EC2020-3AEA-1069-A2DD-08002B30309D}
    // Root folder SHITEMID layout:
    //   [cb:2] [type:1] [sort_order:1] [GUID:16]
    //   cb = 20, type = 0x1F, sort_order = 0x50
    uint8_t raw_item[] = {
        0x14, 0x00,             // cb = 20
        0x1F,                   // class type
        0x50,                   // sort order (0x50 = My Computer)
        0x20, 0x20, 0xEC, 0x21, // GUID start
        0xEA, 0x3A,
        0x69, 0x10,
        0xA2, 0xDD,
        0x08, 0x00, 0x2B, 0x30, 0x30, 0x9D  // GUID end
    };

    ItemID* item = &pidl->items[0];
    item->size = 20;
    item->class_type = 0x1F;
    item->type = IDTYPE_CLSID_ITEM;
    item->payload_len = 17; // sort_order + GUID
    item->payload = malloc(17);
    memcpy(item->payload, raw_item + 2, 17);
    item->raw_len = 20;
    item->raw = malloc(20);
    memcpy(item->raw, raw_item, 20);

    uint8_t out[4096];
    size_t out_len;
    if (serialize_lnk(out, sizeof(out), &out_len, &state) < 0) {
        printf("serialize failed\n");
        return;
    }

    FILE* f = fopen("cpanel_test.lnk", "wb");
    fwrite(out, 1, out_len, f);
    fclose(f);
    printf("wrote cpanel_test.lnk (%zu bytes)\n", out_len);

    free(item->raw);
    free(item->payload);
}

int main(void){
    create_cpanel_lnk();
    return 0;
}