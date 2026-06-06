/* Offline seed-corpus classifier (Linux, see Makefile's cc path).
 *
 * Runs the project's own deserialize_lnk over each seed and prints the structural axes the
 * scheduler's precondition filter gates on (LNKLayout + the enum varieties in model.h). The
 * union of TAGS across the corpus is exactly the set of operator groups that have live
 * candidates somewhere; missing tags are the gaps a richer corpus must fill.
 *
 * build:  cc -I. tools/classify.c deserialize.c serialize.c mutate.c gen.c lnk_prng.c -lm -lpthread -o /tmp/classify
 * run:    /tmp/classify seeds/*.lnk
 */
#include "model.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int deserialize_lnk(const uint8_t* buf, size_t len, LNKGeneratorState* state);

static const char* iditype(ItemIDType t){
    switch(t){
        case IDTYPE_CLSID_ITEM:       return "clsid";
        case IDTYPE_VOLUME_ITEM:      return "volume";
        case IDTYPE_FILESYSTEM_DIR:   return "fsdir";
        case IDTYPE_FILESYSTEM_FILE:  return "fsfile";
        case IDTYPE_NETWORK_RESOURCE: return "netresource";
        case IDTYPE_NETWORK_SERVER:   return "netserver";
        case IDTYPE_NETWORK_SHARE:    return "netshare";
        case IDTYPE_DELEGATE_ITEM:    return "delegate";
        case IDTYPE_EXTENSION_ITEM:   return "extension";
        default:                      return "unknown";
    }
}

static const char* extype(ExtraDataType t){
    switch(t){
        case EXTRA_ENVIRONMENT:      return "environment";
        case EXTRA_CONSOLE:          return "console";
        case EXTRA_CONSOLE_FE:       return "console_fe";
        case EXTRA_DARWIN:           return "darwin";
        case EXTRA_ICON_ENVIRONMENT: return "icon_environment";
        case EXTRA_KNOWN_FOLDER:     return "known_folder";
        case EXTRA_PROPERTY_STORE:   return "property_store";
        case EXTRA_SHIM:             return "shim";
        case EXTRA_SPECIAL_FOLDER:   return "special_folder";
        case EXTRA_TRACKER:          return "tracker";
        case EXTRA_VISTA_IDLIST:     return "vista_idlist";
        case EXTRA_UNKNOWN:          return "unknown_sig";
        default:                     return "terminator";
    }
}

int main(int argc, char** argv){
    for(int a = 1; a < argc; a++){
        FILE* f = fopen(argv[a], "rb");
        if(!f){ fprintf(stderr, "open %s\n", argv[a]); continue; }
        fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
        uint8_t* buf = malloc(n > 0 ? n : 1);
        if(fread(buf, 1, n, f) != (size_t)n){ fclose(f); free(buf); continue; }
        fclose(f);

        const char* base = strrchr(argv[a], '/'); base = base ? base+1 : argv[a];

        // LNKGeneratorState embeds the full propstore model (~0.5 GB); heap-allocate it like the
        // real mutator does (calloc, so only touched pages are paged in) — never on the stack.
        LNKGeneratorState* sp = calloc(1, sizeof(LNKGeneratorState));
        #define st (*sp)
        if(!sp){ free(buf); continue; }
        if(deserialize_lnk(buf, n, sp) < 0){
            printf("%-64s PARSE_FAIL\n", base);
            free(buf); free(sp); continue;
        }
        LNKLayout* c = &st.core;

        // TAGS line: flat tokens for trivial union across the corpus.
        printf("%-64s TAGS", base);
        if(c->has_link_target_idlist) printf(" idlist");
        if(c->has_linkinfo)           printf(" linkinfo");
        if(st.linkinfo.has_volume_id) printf(" linkinfo:local");
        if(st.linkinfo.has_common_network_relative_link) printf(" linkinfo:unc");
        if(c->has_stringdata)         printf(" stringdata");
        if(st.header.link_flags & 0x80) printf(" unicode"); else if(c->has_stringdata) printf(" ansi");
        if(c->has_extradata)          printf(" extradata");

        for(int i = 0; i < st.linktargetidlist.item_count; i++)
            printf(" pidl:%s", iditype(st.linktargetidlist.items[i].type));

        for(int i = 0; i < st.extradata.block_count; i++)
            printf(" block:%s", extype(st.extradata.blocks[i].type));

        // propstore depth
        if(c->has_propstore_block){
            int max_vals = 0, has_str = 0, has_int = 0;
            for(int s = 0; s < st.propstore.storage_count; s++){
                SerializedPropertyStorage* S = &st.propstore.storages[s];
                if(S->value_count > max_vals) max_vals = S->value_count;
                if(S->name_scheme == PROPVAL_STRING_NAMED) has_str = 1; else has_int = 1;
                for(int v = 0; v < S->value_count; v++){
                    uint16_t vt = (S->name_scheme == PROPVAL_STRING_NAMED)
                        ? (uint16_t)S->values[v].string_named.typed_value.vt
                        : (uint16_t)S->values[v].integer_named.typed_value.vt;
                    printf(" vt:%04x", vt);
                }
            }
            printf(" ps:storages%d", st.propstore.storage_count);
            if(max_vals >= 2) printf(" ps:vals2+");
            if(has_int) printf(" ps:int");
            if(has_str) printf(" ps:strnamed");
        }
        printf("\n");
        free(buf);
        free(sp);
        #undef st
    }
    return 0;
}
