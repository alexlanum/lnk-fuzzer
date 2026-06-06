/**
 * Behavioral (sink) oracle for the LNK fuzzing harnesses.
 *
 * Why this exists
 * –––––––––––––––
 * The crash oracle Jackalope/TinyInst gives us for free only fires when the parser corrupts
 * itself (access violation, /GS fastfail, heap guard) or hangs (-t timeout). It is structurally
 * blind to the bug class this fuzzer's operators are actually built around — CVE-2010-2568
 * (Stuxnet), CVE-2015-0096, CVE-2017-8464 — because those are *logic* bugs: shell32 is steered
 * into loading attacker-controlled code and the load SUCCEEDS. A successful LoadLibrary does not
 * fault, so nothing the engine watches ever trips.
 *
 * This header installs the missing judge. It intercepts the code-execution sinks reachable from
 * shell32's LNK / namespace handlers and asks one question per call: "is shell32 about to execute
 * a module that did not come from a trusted system location?" If yes, it reports the hit through
 * the only channel the engine listens on — a deliberate, self-identifying access violation — so
 * TinyInst captures the exact input into findings/ exactly as it would a memory bug.
 *
 * Detection model
 * –––––––––––––––
 *   sink reached   : LoadLibrary{,Ex}W / CreateProcessW / WinExec / ShellExecuteExW called from a
 *                    target module's import table (the CPL load in CControlPanelFolder is the
 *                    historic one — CPL_LoadCPLModule -> LoadLibraryW).
 *   policy         : a load is benign iff the module is a bare name (loader resolves from the
 *                    system search path) or lives under %SystemRoot% / System32. Anything with a
 *                    path component outside those — a temp path, a UNC path, a \\.\STORAGE device
 *                    path (the literal Stuxnet payload) — is a finding.
 *   taint tag      : if the offending path's UTF-16 image also occurs in the current sample bytes,
 *                    the load was provably steered by the mutator, not by machine state. Tagged in
 *                    the report so triage can separate attacker-driven hits from environmental ones
 *                    without symbolizing.
 *   report         : write to 0xDEAD0NNN (NN = sink id, bit 0x100 = tainted). The faulting address
 *                    self-documents the finding class in the crash dump; distinct from a genuine
 *                    shell32 AV, which faults on a shell32-derived address.
 *
 * Mechanism
 * –––––––––
 * Import Address Table patching, no third-party dependency. For each target module we walk its
 * import descriptors, match the sink by symbolic name (robust across the apiset forwarding that
 * makes address-comparison unreliable on modern Windows), and swap the IAT slot to our trampoline.
 * The trampoline judges, then tail-calls the real export resolved via GetProcAddress.
 *
 * Scope / limits
 * ––––––––––––––
 *  - IAT hooking catches cross-module imports only. A sink shell32 calls *intra-module* (e.g. its
 *    own exported ShellExecuteExW) or resolves via GetProcAddress is not seen; that needs an inline
 *    hook (Detours/MinHook). The historic sink — LoadLibrary{,Ex}W, imported from kernel32 — IS an
 *    import, so the primary class is covered.
 *  - Only modules loaded at install time are patched. We force-load the target set first so their
 *    IATs are present; delegate DLLs loaded later are not re-patched.
 *  - Single-threaded persistent-target assumption: one harness process drives one fuzz() loop, so
 *    the sample pointer is a plain global. Do not share an LNKGeneratorState across threads here.
 *
 * VALIDATE BEFORE TRUSTING: an oracle you have not watched fire is worthless. Run a positive control
 * (a seed whose PIDL points a control-panel item at a non-System32 module — it MUST produce a
 * 0xDEAD0xxx finding) and a negative control (a clean .lnk — it must stay silent through shell32's
 * legitimate system-DLL loads). Only then start a campaign.
 */

#ifndef LNK_ORACLE_H
#define LNK_ORACLE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>   // ShellExecuteExW / SHELLEXECUTEINFOW
#include <tlhelp32.h>   // module snapshot (no psapi link needed)
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

// Sink identifiers. Encoded into the faulting address (low byte) so a crash triage can read the
// sink off the dump without symbols. Keep < 0x100.
enum {
    ORACLE_SINK_LOADLIBRARY = 0x01,
    ORACLE_SINK_CREATEPROC  = 0x02,
    ORACLE_SINK_WINEXEC     = 0x03,
    ORACLE_SINK_SHELLEXEC   = 0x04,
};

// –––––– current sample, for input-taint tagging ––––––
// Set once per iteration by the harness; read only inside the hooks. Pointer into the SHM region,
// not owned here.
static const unsigned char* g_oracle_sample      = nullptr;
static unsigned long        g_oracle_sample_size = 0;

static inline void oracle_set_sample(const unsigned char* data, unsigned long size) {
    g_oracle_sample      = data;
    g_oracle_sample_size = size;
}

// –––––– policy ––––––

// Benign iff: empty (nothing executes), a bare module name (loader resolves via the system search
// order), or rooted under %SystemRoot% / System32. Prefix heuristic — good enough for a fuzzing
// oracle; a path that escapes System32 via "..\.." is itself suspicious and still flagged.
static inline bool oracle_is_trusted_path(const WCHAR* path) {
    if (!path || !path[0]) return true;

    bool has_sep = false;
    for (const WCHAR* q = path; *q; ++q) {
        if (*q == L'\\' || *q == L'/') { has_sep = true; break; }
    }
    if (!has_sep) return true;  // bare name -> system search path

    WCHAR sysdir[MAX_PATH];
    WCHAR windir[MAX_PATH];
    UINT  ns = GetSystemDirectoryW (sysdir, MAX_PATH);   // ...\System32
    UINT  nw = GetWindowsDirectoryW(windir, MAX_PATH);   // ...\Windows
    if (ns && ns < MAX_PATH && _wcsnicmp(path, sysdir, ns) == 0) return true;
    if (nw && nw < MAX_PATH && _wcsnicmp(path, windir, nw) == 0) return true;
    return false;
}

// Does the UTF-16LE image of `path` (sans terminator) occur verbatim in the current sample? A match
// proves the mutator's bytes produced this path. A miss is inconclusive (the path may be
// env-expanded), so taint only TAGS the finding — it never suppresses one.
static inline bool oracle_path_tainted(const WCHAR* path) {
    if (!g_oracle_sample || !g_oracle_sample_size || !path || !path[0]) return false;
    size_t cb = wcslen(path) * sizeof(WCHAR);
    if (cb == 0 || cb > g_oracle_sample_size) return false;
    for (unsigned long i = 0; i + cb <= g_oracle_sample_size; ++i) {
        if (memcmp(g_oracle_sample + i, path, cb) == 0) return true;
    }
    return false;
}

// –––––– report ––––––
// stderr line (lands in run.log) + a deliberate AV at a self-identifying address. EXCEPTION_
// NONCONTINUABLE is not used: a plain write fault is what TinyInst's crash path is guaranteed to
// catch and dedup, and the address carries the metadata.
static inline void oracle_fire(unsigned sink_id, const WCHAR* what, bool tainted) {
    fprintf(stderr, "[ORACLE] sink=%u tainted=%d path=%ls\n",
            sink_id, (int)tainted, what ? what : L"(null)");
    fflush(stderr);
    volatile char* trap =
        (volatile char*)(uintptr_t)(0xDEAD0000u | (tainted ? 0x100u : 0u) | (sink_id & 0xFFu));
    *trap = 0;  // -> EXCEPTION_ACCESS_VIOLATION, captured by TinyInst with the input that caused it
}

static inline void oracle_check(unsigned sink_id, const WCHAR* path) {
    if (!oracle_is_trusted_path(path)) {
        oracle_fire(sink_id, path, oracle_path_tainted(path));
    }
}

// –––––– trampolines ––––––
typedef HMODULE (WINAPI* LoadLibraryW_t)   (LPCWSTR);
typedef HMODULE (WINAPI* LoadLibraryExW_t) (LPCWSTR, HANDLE, DWORD);
typedef BOOL    (WINAPI* CreateProcessW_t) (LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                            BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef UINT    (WINAPI* WinExec_t)        (LPCSTR, UINT);
typedef BOOL    (WINAPI* ShellExecuteExW_t)(SHELLEXECUTEINFOW*);

static LoadLibraryW_t    g_real_LoadLibraryW    = nullptr;
static LoadLibraryExW_t  g_real_LoadLibraryExW  = nullptr;
static CreateProcessW_t  g_real_CreateProcessW  = nullptr;
static WinExec_t         g_real_WinExec         = nullptr;
static ShellExecuteExW_t g_real_ShellExecuteExW = nullptr;

static HMODULE WINAPI Hook_LoadLibraryW(LPCWSTR name) {
    oracle_check(ORACLE_SINK_LOADLIBRARY, name);
    return g_real_LoadLibraryW(name);
}

static HMODULE WINAPI Hook_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) {
    // Resource-only loads (icons, message tables) never run DllMain, so they are not a code-exec
    // sink — skip them to keep the oracle's signal clean. The CPL load uses a plain image load.
    const DWORD data_only = LOAD_LIBRARY_AS_DATAFILE
                          | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE
                          | LOAD_LIBRARY_AS_IMAGE_RESOURCE;
    if (!(flags & data_only)) oracle_check(ORACLE_SINK_LOADLIBRARY, name);
    return g_real_LoadLibraryExW(name, file, flags);
}

static BOOL WINAPI Hook_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                       LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                       LPVOID env, LPCWSTR cwd, LPSTARTUPINFOW si,
                                       LPPROCESS_INFORMATION pi) {
    oracle_check(ORACLE_SINK_CREATEPROC, app ? app : cmd);
    return g_real_CreateProcessW(app, cmd, pa, ta, inherit, flags, env, cwd, si, pi);
}

static UINT WINAPI Hook_WinExec(LPCSTR cmd, UINT show) {
    // ANSI sink: widen the leading path for the policy check; no taint tagging (sample is matched
    // as UTF-16).
    WCHAR w[MAX_PATH] = {0};
    if (cmd) MultiByteToWideChar(CP_ACP, 0, cmd, -1, w, MAX_PATH);
    if (cmd && !oracle_is_trusted_path(w)) oracle_fire(ORACLE_SINK_WINEXEC, w, false);
    return g_real_WinExec(cmd, show);
}

static BOOL WINAPI Hook_ShellExecuteExW(SHELLEXECUTEINFOW* info) {
    if (info && info->lpFile) oracle_check(ORACLE_SINK_SHELLEXEC, info->lpFile);
    return g_real_ShellExecuteExW(info);
}

// –––––– IAT patching ––––––

// Swap every IAT slot in `mod` whose imported symbol name == `import_name` to `hook`. Matching is
// by name via the Import Name Table (OriginalFirstThunk), so apiset forwarding (shell32 importing
// LoadLibraryW through api-ms-win-core-libraryloader-*) is handled transparently.
static bool oracle_iat_patch(HMODULE mod, const char* import_name, void* hook) {
    if (!mod) return false;
    BYTE* base = (BYTE*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return false;

    bool patched = false;
    for (IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
         imp->Name; ++imp) {
        // INT (names) runs parallel to the IAT (resolved pointers). Bound imports may zero the
        // OriginalFirstThunk, in which case fall back to FirstThunk for names.
        IMAGE_THUNK_DATA* names = (IMAGE_THUNK_DATA*)(base + (imp->OriginalFirstThunk
                                                              ? imp->OriginalFirstThunk
                                                              : imp->FirstThunk));
        IMAGE_THUNK_DATA* slots = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        for (; names->u1.AddressOfData; ++names, ++slots) {
            if (names->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;  // imported by ordinal, no name
            IMAGE_IMPORT_BY_NAME* by_name =
                (IMAGE_IMPORT_BY_NAME*)(base + names->u1.AddressOfData);
            if (strcmp((const char*)by_name->Name, import_name) != 0) continue;

            void** target = (void**)&slots->u1.Function;
            DWORD  prot   = 0;
            if (VirtualProtect(target, sizeof(void*), PAGE_READWRITE, &prot)) {
                *target = hook;
                VirtualProtect(target, sizeof(void*), prot, &prot);
                patched = true;
            }
        }
    }
    return patched;
}

// Resolve the real exports, force-load the target modules, then patch each one's IAT for every sink
// whose export resolved. Call once, after CoInitialize, before the fuzz loop.
static inline void oracle_install(const wchar_t* const* modules, size_t module_count) {
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    g_real_LoadLibraryW    = (LoadLibraryW_t)   GetProcAddress(k32, "LoadLibraryW");
    g_real_LoadLibraryExW  = (LoadLibraryExW_t) GetProcAddress(k32, "LoadLibraryExW");
    g_real_CreateProcessW  = (CreateProcessW_t) GetProcAddress(k32, "CreateProcessW");
    g_real_WinExec         = (WinExec_t)        GetProcAddress(k32, "WinExec");
    g_real_ShellExecuteExW = (ShellExecuteExW_t)GetProcAddress(
                                 LoadLibraryW(L"shell32.dll"), "ShellExecuteExW");

    for (size_t i = 0; i < module_count; ++i) {
        HMODULE mod = LoadLibraryW(modules[i]);  // ensure loaded so its IAT exists; refs held
        if (!mod) continue;
        if (g_real_LoadLibraryW)    oracle_iat_patch(mod, "LoadLibraryW",    (void*)Hook_LoadLibraryW);
        if (g_real_LoadLibraryExW)  oracle_iat_patch(mod, "LoadLibraryExW",  (void*)Hook_LoadLibraryExW);
        if (g_real_CreateProcessW)  oracle_iat_patch(mod, "CreateProcessW",  (void*)Hook_CreateProcessW);
        if (g_real_WinExec)         oracle_iat_patch(mod, "WinExec",         (void*)Hook_WinExec);
        if (g_real_ShellExecuteExW) oracle_iat_patch(mod, "ShellExecuteExW", (void*)Hook_ShellExecuteExW);
    }
}

#endif  // LNK_ORACLE_H
