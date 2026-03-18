#include "model.h"
#include <stdio.h>
#include <stdlib.h>

int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);

int main(void) {
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
    if (result < 0) {
        printf("failed\n");
        printf("link_flags: 0x%08X\n", state.header.link_flags);
        printf("has_idlist: %d\n", state.core.has_link_target_idlist);
        printf("has_linkinfo: %d\n", state.core.has_linkinfo);
        printf("has_stringdata: %d\n", state.core.has_stringdata);
    } else {
        printf("ok\n");
    }

    free(buf);
    return 0;
}