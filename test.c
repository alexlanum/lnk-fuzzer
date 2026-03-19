#include "model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);
int serialize_lnk(uint8_t* buf, size_t cap, size_t* out_len, const LNKGeneratorState* state);

int main(void){
    printf("starting\n");
    fflush(stdout);
    FILE* file = fopen("test.lnk", "rb");
    if(!file){
        printf("cant open file\n");
        return 1;
    }
    
    fseek(file, 0, SEEK_END);
    size_t len = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* buf = malloc(len);
    fread(buf, 1, len, file);
    fclose(file);

    LNKGeneratorState state;
    int result = deserialize_lnk(buf, len, &state);
    if(result < 0)
        printf("deserialize failed\n");
    else
        printf("deserialize ok\n");

    // // print parsed fields
    // if(result == 0){
    //     printf("ok\n");
    //     printf(">_ Header \n");
    //     printf(" . link_flags:       0x%08X\n", state.header.link_flags);
    //     printf(" . file_attributes:  0x%08X\n", state.header.file_attributes);
    //     printf(" . file_size:        %u\n", state.header.file_size);
    //     printf(" . show_command:     0x%08X\n", state.header.show_command);

    //     printf("\n>_ Layout \n");
    //     printf(" . has_idlist:       %d\n", state.core.has_link_target_idlist);
    //     printf(" . has_linkinfo:     %d\n", state.core.has_linkinfo);
    //     printf(" . has_stringdata:   %d\n", state.core.has_stringdata);
    //     printf(" . has_extradata:    %d\n", state.core.has_extradata);

    //     if(state.core.has_link_target_idlist){
    //         printf("\n>_ IDList \n");
    //         printf(" . total_size:       %u\n", state.linktargetidlist.total_size);
    //         printf(" . item_count:       %d\n", state.linktargetidlist.item_count);
    //         for (int i = 0; i < state.linktargetidlist.item_count; i++) {
    //             printf("  item[%d]: cb=%u class=0x%02X type=%d\n",
    //                 i, state.linktargetidlist.items[i].size,
    //                 state.linktargetidlist.items[i].class_type,
    //                 state.linktargetidlist.items[i].type);
    //         }
    //     }

    //     if(state.core.has_linkinfo){
    //         printf("\n>_ LinkInfo \n");
    //         printf(" . link_info_size:   %u\n", state.linkinfo.link_info_size);
    //         printf(" . header_size:      0x%X\n", state.linkinfo.link_info_header_size);
    //         printf(" . flags:            0x%X\n", state.linkinfo.link_info_flags);
    //         printf(" . has_volume_id:    %d\n", state.linkinfo.has_volume_id);
    //         printf(" . has_cnrl:         %d\n", state.linkinfo.has_common_network_relative_link);
    //         if(state.linkinfo.has_local_base_path)
    //             printf(" . local_base_path:  %s\n", state.linkinfo.local_base_path);
    //     }

    //     if(state.core.has_extradata){
    //         printf("\n>_ ExtraData \n");
    //         printf(" . block_count:      %d\n", state.extradata.block_count);
    //         for(int i = 0; i < state.extradata.block_count; i++){
    //             printf("  block[%d]: size=%u type=%d\n",
    //                 i, state.extradata.blocks[i].size,
    //                 state.extradata.blocks[i].type);
    //         }
    //     }
    // }

    uint8_t out[65536];
    size_t out_len;
    int ser_result = serialize_lnk(out, sizeof(out), &out_len, &state);
    if(ser_result < 0)
        printf("serialize failed\n");

    if(out_len == len && memcmp(buf, out, len) == 0)
        printf("deserialize to serialize perfect match\n");
    else
        printf("deserialize to serialize mismatch (in=%zu out=%zu)\n", len, out_len);
    
    
    free(buf);
    return 0;
}