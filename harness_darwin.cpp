/**
 * MSI / Darwin LNK fuzzing harness for Jackalope + TinyInst.
 *
 * Instrumentation target is msi.dll (advertised-shortcut / Darwin descriptor decoder), not shell32.dll.
 * Run this harness with a Darwin-biased seed corpus and a higher weight on GROUP_DARWIN in the scheduler;
 * run harness.cpp with the general corpus.
 *
 * Fuzz surface
 * ––––––––––––
 * fuzz() reads a mutated .lnk byte stream from Jackalope's SHM region (SHMSampleDelivery, format:
 * [uint32 len][bytes]), writes it to a fixed temp path, and drives msi.dll's Darwin entry points:
 *
 *   MsiGetShortcutTargetW         – opens the .lnk, locates the DarwinDataBlock (signature 0xA0000006),
 *                                   validates the descriptor, and decodes ProductCode / FeatureId /
 *                                   ComponentCode GUIDs.
 *   CommandLineFromMsiDescriptor – takes a Darwin descriptor string and parses it independently of
 *                                   any .lnk wrapper. Reachable in the LNK flow when the shortcut
 *                                   contains a non-empty descriptor; reachable here directly so the
 *                                   parser sees the mutator's mangled descriptors even when
 *                                   MsiGetShortcutTargetW rejects the whole file early.
 *
 * Targeted operator group: GROUP_DARWIN. GROUP_EXTRA_SEQ, GROUP_EXTRA_HDR also feed this harness
 * because msi.dll has to walk past every preceding ExtraData block to find 0xA0000006, and any kind
 * of structural mutation upstream can change what msi sees.
 *
 * Persistent mode
 * –––––––––––––––
 * fuzz() is the persistent target, same pattern as harness.cpp. The temp .lnk path is fixed per
 * process so the file system cache stays active. CreateFile/Write/Close is done per iteration with
 * FILE_ATTRIBUTE_TEMPORARY hinting the cache manager to keep pages resident. msi opens the path
 * itself; we can't keep our handle open while it does, but the pages don't actually leave RAM.
 *
 * cl.exe /EHsc /O2 harness_darwin.cpp /link msi.lib ole32.lib shell32.lib
 * point Jackalope at it with -instrument_module msi.dll and a Darwin based seed corpus
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <objbase.h>
#include <ShlObj.h>
#include <msi.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#pragma comment(lib, "msi.lib")

extern "C" UINT WINAPI CommandLineFromMsiDescriptor(WCHAR* Descriptor, WCHAR* CommandLine, DWORD* CommandLineLength);

// SHM layout — must match harness.cpp and lnk_mutator.cc / Jackalope's Sample::max_size.
#define MAX_SAMPLE_SIZE (1 << 20)
#define SHM_HEADER_SIZE 4
#define SHM_SIZE (SHM_HEADER_SIZE + MAX_SAMPLE_SIZE)

#define MSI_GUID_BUF_CHARS    39  // 32 hex + 4 dashes + braces + null is 39 wchars at most
#define MSI_FEATURE_BUF_CHARS 39

static unsigned char* g_shm_data  = nullptr;
static WCHAR g_temp_path[MAX_PATH] = {0};

/**
 * SHM setup
 * same pattern as harness.cpp
 */
static int setup_shmem(const char* name){
    HANDLE map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
    if(!map){
        fprintf(stderr, "OpenFileMapping(%s) failed: %lu\n", name, GetLastError());
        return 0;
    }
    g_shm_data = (unsigned char*)MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
    if(!g_shm_data){
        fprintf(stderr, "MapViewOfFile failed: %lu\n", GetLastError());
        return 0;
    }
    return 1;
}

/**
 * Build a fixed temp path under %TEMP% keyed by PID. Per-process so multiple fuzz workers don't
 * stomp each other; fixed across iterations so the FS cache keeps the pages hot.
 */
static int setup_temp_path(void){
    WCHAR dir[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, dir);
    if(n == 0 || n >= MAX_PATH) return 0;
    int written = _snwprintf_s(g_temp_path, MAX_PATH, _TRUNCATE, L"%sjackalope_lnk_%lu.lnk", dir, GetCurrentProcessId());
    return (written > 0);
}

/**
 * Locate the unicode portion of a DarwinDataBlock inside the SHM payload.
 *
 * DarwinDataBlock layout (788 bytes total):
 *   0x000  4    BlockSize         = 0x00000314
 *   0x004  4    BlockSignature    = 0xA0000006
 *   0x008  260  DarwinDataAnsi
 *   0x10C  520  DarwinDataUnicode
 *
 * LNK parsers find this by walking ExtraData blocks from the post-StringData offset. We can't
 * trust the LNK structure to be valid, the whole point is to fuzz it, so we just signature-scan.
 * False positives don't matter: handing a random 520-byte slice to CommandLineFromMsiDescriptor is
 * still legitimate fuzzing input for that parser.
 */
static const BYTE* find_darwin_unicode(const BYTE* data, ULONG size){
    if(size < 12 + 520) return nullptr;
    // signature 0xA0000006 little-endian = 06 00 00 A0
    for(ULONG i = 0; i + 4 + 8 + 520 <= size; i++){
        if(data[i+0] == 0x06 && data[i+1] == 0x00 && data[i+2] == 0x00 && data[i+3] == 0xA0){
            // i points at signature. unicode descriptor starts at signature + 4 (rest of header) + 260 (ansi).
            return data + i + 4 + 260;
        }
    }
    return nullptr;
}

/**
 * The persistent target. TinyInst rewrites the RET so each call loops back to the entry; the
 * extern "C" / dllexport / noinline triple is the same trick harness.cpp uses to keep the symbol
 * findable and prevent inlining into main().
 */
extern "C" __declspec(dllexport) __declspec(noinline)
void fuzz(char* /*shm_name*/){
    uint32_t sample_size = *(uint32_t*)g_shm_data;
    if(sample_size == 0 || sample_size > MAX_SAMPLE_SIZE) return;
    const BYTE* sample_bytes = (const BYTE*)(g_shm_data + SHM_HEADER_SIZE);

    // Overwrite the temp .lnk with this iteration's payload.
    // CREATE_ALWAYS truncates+rewrites; FILE_ATTRIBUTE_TEMPORARY hints the cache manager to keep
    // pages in memory and avoid lazy writeback to disk.
    HANDLE h = CreateFileW(g_temp_path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
    if(h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    BOOL ok = WriteFile(h, sample_bytes, sample_size, &written, nullptr);
    CloseHandle(h);
    if(!ok || written != sample_size) return;

    // Path 1: full Darwin pipeline through MsiGetShortcutTargetW.
    // msi.dll opens the .lnk, walks ExtraData looking for 0xA0000006, validates the descriptor,
    // and emits the three GUID strings. Any mutation in GROUP_DARWIN — and most of GROUP_EXTRA_*
    // and GROUP_FILE — feeds this entry point.
    WCHAR product[MSI_GUID_BUF_CHARS]    = {0};
    WCHAR feature[MSI_FEATURE_BUF_CHARS] = {0};
    WCHAR component[MSI_GUID_BUF_CHARS]  = {0};
    MsiGetShortcutTargetW(g_temp_path, product, feature, component);

    // Path 2: descriptor parser in isolation, via CommandLineFromMsiDescriptor.
    // Even if MsiGetShortcutTargetW bailed before reaching the descriptor parser (e.g. structural
    // header rejection), feeding the raw mutated unicode bytes directly here guarantees that the
    // parser sees them. We bound to 259 wchars + nul to match the documented 520-byte slot.
    const BYTE* darwin_unicode = find_darwin_unicode(sample_bytes, sample_size);
    if(darwin_unicode){
        WCHAR descriptor[260] = {0};
        const WCHAR* src = (const WCHAR*)darwin_unicode;
        // copy at most 259 wchars; force-null the last slot so the parser can't run off the end
        // even if the mutator stripped the in-block null terminator (MUTATE_DARWIN_NULL_BYTES /
        // MUTATE_DARWIN_OVERLONG).
        for(size_t i = 0; i < 259; i++){
            descriptor[i] = src[i];
            if(src[i] == 0) break;
        }
        descriptor[259] = 0;

        WCHAR commandline[INFOTIPSIZE] = {0};
        DWORD cmdline_chars = INFOTIPSIZE;
        CommandLineFromMsiDescriptor(descriptor, commandline, &cmdline_chars);
    }
}

int main(int argc, char** argv){
    if(argc != 3 || strcmp(argv[1], "-m") != 0){
        fprintf(stderr, "Usage: %s -m <shm_name>\n", argv[0]);
        return 1;
    }
    if(!setup_shmem(argv[2])){
        fprintf(stderr, "shared memory setup failed\n");
        return 1;
    }
    if(!setup_temp_path()){
        fprintf(stderr, "temp path setup failed\n");
        return 1;
    }

    // COM init for the lifetime of the process. msi.dll's internal callbacks into shell may
    // require apartment state; per-iteration init/uninit would dominate timing without changing
    // which code paths the parser hits.
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if(FAILED(hr)){
        fprintf(stderr, "CoInitializeEx failed: 0x%08lx\n", hr);
        return 1;
    }

    fuzz(argv[2]);

    CoUninitialize();
    DeleteFileW(g_temp_path);
    return 0;
}