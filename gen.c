/**
 * Populates a LNKGeneratorState with valid data and returns it.
 * Each gen_x function populates on section of the format.
 * The generate_x functions compose them into complete configs.
 *
 * Each field's validation is reverse engineered to guide
 * how much mutation effort to spend on it.
 */
#include "model.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

// ShellLinkHeader LinkFlags bits
#define LF_HAS_LINK_TARGET_IDLIST     0x00000001
#define LF_HAS_LINK_INFO              0x00000002
#define LF_HAS_NAME                   0x00000004
#define LF_HAS_RELATIVE_PATH          0x00000008
#define LF_HAS_WORKING_DIR            0x00000010
#define LF_HAS_ARGUMENTS              0x00000020
#define LF_HAS_ICON_LOCATION          0x00000040
#define LF_IS_UNICODE                 0x00000080
#define LF_FORCE_NO_LINK_INFO         0x00000100
#define LF_HAS_EXP_STRING             0x00000200
#define LF_RUN_IN_SEPARATE_PROCESS    0x00000400
#define LF_HAS_DARWIN_ID              0x00001000
#define LF_RUN_AS_USER                0x00002000
#define LF_HAS_EXP_ICON               0x00004000
#define LF_NO_PIDL_ALIAS              0x00008000
#define LF_RUN_WITH_SHIM_LAYER        0x00020000
#define LF_FORCE_NO_LINK_TRACK        0x00040000
#define LF_ENABLE_TARGET_METADATA     0x00080000
#define LF_DISABLE_LINK_PATH_TRACKING 0x00100000
#define LF_DISABLE_KNOWN_FOLDER_TRACK 0x00200000
#define LF_DISABLE_KNOWN_FOLDER_ALIAS 0x00400000
#define LF_ALLOW_LINK_TO_LINK         0x00800000
#define LF_UNALIAS_ON_SAVE            0x01000000
#define LF_PREFER_ENVIRONMENT_PATH    0x02000000
#define LF_KEEP_LOCAL_IDLIST_FOR_UNC  0x04000000

// ShellLinkHeader FileAttributes bits
#define FA_READONLY                   0x00000001
#define FA_HIDDEN                     0x00000002
#define FA_SYSTEM                     0x00000004
#define FA_RESERVED1                  0x00000008  // must be 0
#define FA_DIRECTORY                  0x00000010
#define FA_ARCHIVE                    0x00000020
#define FA_RESERVED2                  0x00000040  // must be 0
#define FA_NORMAL                     0x00000080
#define FA_TEMPORARY                  0x00000100
#define FA_SPARSE_FILE                0x00000200
#define FA_REPARSE_POINT              0x00000400
#define FA_COMPRESSED                 0x00000800
#define FA_OFFLINE                    0x00001000
#define FA_NOT_CONTENT_INDEXED        0x00002000
#define FA_ENCRYPTED                  0x00004000

// ShellLinkHeader ShowCommand values
// "any other value MUST be treated as SW_SHOWNORMAL"
#define SW_SHOWNORMAL                 0x00000001
#define SW_SHOWMAXIMIZED              0x00000003
#define SW_SHOWMINNOACTIVE            0x00000007