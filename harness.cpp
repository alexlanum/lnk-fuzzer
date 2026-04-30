// harness.cpp
//
// LNK fuzzing harness for Jackalope + TinyInst.
//
// What gets fuzzed
// ----------------
// `fuzz()` reads a mutated .lnk byte stream from shared memory (Jackalope's
// SHMSampleDelivery, format: [uint32_t length][bytes]) and feeds it through
// the Windows shell-link parsing path that historically holds the bugs:
//
//   IPersistStream::Load    — top-level structural parse from the byte stream
//   IShellLinkW::Resolve    — full target resolution (LinkInfo path build,
//                             working directory normalize, icon load)
//   IShellLinkW::GetIDList  — forces the LinkTargetIDList through full PIDL
//                             traversal: SHITEMID dispatch by class type byte,
//                             which is the path Stuxnet (CVE-2010-2568) and
//                             CVE-2017-8464 walked through CControlPanelFolder.
//   IShellLinkW::GetPath    — exercises CommonNetworkRelativeLink path
//                             construction (CVE-2015-0096 territory).
//   IShellLink::GetIconLocation — exercises icon-from-CPL resolution paths.
//
// All of the above eventually call into shell32.dll (and the namespace-
// extension DLLs it dispatches to). TinyInst is told to instrument
// shell32.dll so coverage feedback comes from the parser itself, not from
// our harness scaffolding.
//
// Persistent mode
// ---------------
// `fuzz()` is the persistent target. TinyInst rewrites its return so each
// call loops back to the top instead of exiting the process. Per-iteration
// COM object lifetimes are tightly bounded (CoCreateInstance -> use ->
// Release) so heap state doesn't accumulate across iterations beyond what
// shell32 itself caches. The -iterations flag bounds how many loops happen
// before the harness process is recycled, which limits unbounded growth.
//
// What we deliberately don't do
// -----------------------------
// - We do NOT call CoInitialize per-iteration; it runs once at startup.
//   Per-iteration init/uninit dominates the timing budget and isn't where
//   bugs live.
// - We do NOT touch IShellLink* methods that Resolve() already drives
//   transitively (GetWorkingDirectory, GetArguments, etc.). Calling them
//   adds runtime without adding coverage.
// - We do NOT write the sample to disk and reload via IPersistFile. The
//   IPersistStream path reaches the same parser through a shorter call
//   stack and is faster per iteration.

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Layout of Jackalope's SHM sample delivery: [uint32_t size][bytes...]
// The 1 MiB cap matches LNK_MAX_BYTES in lnk_mutator.cc.
#define MAX_SAMPLE_SIZE  (1 << 20)
#define SHM_HEADER_SIZE  4
#define SHM_SIZE         (SHM_HEADER_SIZE + MAX_SAMPLE_SIZE)

static unsigned char* g_shm_data = nullptr;

// --------------------------------------------------------------------------
// IStream wrapper around a fixed memory buffer.
//
// IPersistStream::Load needs an IStream. SHCreateMemStream exists but isn't
// available on every Windows SDK target without extra link gymnastics, and
// it copies the buffer internally. A 60-line minimal IStream over the SHM
// region avoids the copy and the link dependency. Only Read/Seek/Stat are
// reachable from the LNK parser — the rest stub out with E_NOTIMPL.
// --------------------------------------------------------------------------
class MemStream : public IStream {
public:
    MemStream(const BYTE* data, ULONG size)
        : data_(data), size_(size), pos_(0), refs_(1) {}

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_ISequentialStream || riid == IID_IStream) {
            *ppv = static_cast<IStream*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef()  override { return ++refs_; }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG r = --refs_;
        if (r == 0) delete this;
        return r;
    }

    // ISequentialStream
    HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) override {
        if (!pv) return STG_E_INVALIDPOINTER;
        ULONG remaining = (pos_ < size_) ? (size_ - pos_) : 0;
        ULONG to_copy   = (cb < remaining) ? cb : remaining;
        if (to_copy) memcpy(pv, data_ + pos_, to_copy);
        pos_ += to_copy;
        if (pcbRead) *pcbRead = to_copy;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Write(const void*, ULONG, ULONG*) override {
        return STG_E_ACCESSDENIED;  // read-only stream
    }

    // IStream — only Seek and Stat are actually needed by the LNK parser.
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER off, DWORD origin,
                                   ULARGE_INTEGER* new_pos) override {
        LONGLONG target;
        switch (origin) {
            case STREAM_SEEK_SET: target = off.QuadPart; break;
            case STREAM_SEEK_CUR: target = (LONGLONG)pos_ + off.QuadPart; break;
            case STREAM_SEEK_END: target = (LONGLONG)size_ + off.QuadPart; break;
            default: return STG_E_INVALIDFUNCTION;
        }
        if (target < 0) return STG_E_INVALIDFUNCTION;
        // The parser is allowed to seek past EOF; Read clamps gracefully.
        pos_ = (ULONG)((target > (LONGLONG)size_) ? size_ : target);
        if (new_pos) new_pos->QuadPart = pos_;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* pstatstg, DWORD grfStatFlag) override {
        if (!pstatstg) return STG_E_INVALIDPOINTER;
        memset(pstatstg, 0, sizeof(*pstatstg));
        pstatstg->type = STGTY_STREAM;
        pstatstg->cbSize.QuadPart = size_;
        if (grfStatFlag != STATFLAG_NONAME) {
            // Parser doesn't read the name; allocate empty to be safe.
            pstatstg->pwcsName = (LPOLESTR)CoTaskMemAlloc(sizeof(WCHAR));
            if (pstatstg->pwcsName) pstatstg->pwcsName[0] = L'\0';
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER)              override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CopyTo(IStream*, ULARGE_INTEGER,
                                     ULARGE_INTEGER*, ULARGE_INTEGER*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Commit(DWORD)                        override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Revert()                             override { return S_OK; }
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER,
                                         ULARGE_INTEGER, DWORD)    override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER,
                                           ULARGE_INTEGER, DWORD)  override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Clone(IStream**)                     override { return E_NOTIMPL; }

private:
    const BYTE* data_;
    ULONG       size_;
    ULONG       pos_;
    ULONG       refs_;
};

// --------------------------------------------------------------------------
// SHM setup. Identical to Jackalope's test.cpp pattern.
// --------------------------------------------------------------------------
static int setup_shmem(const char* name) {
    HANDLE map = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name);
    if (!map) {
        fprintf(stderr, "OpenFileMapping(%s) failed: %lu\n", name, GetLastError());
        return 0;
    }
    g_shm_data = (unsigned char*)MapViewOfFile(map, FILE_MAP_ALL_ACCESS, 0, 0, SHM_SIZE);
    if (!g_shm_data) {
        fprintf(stderr, "MapViewOfFile failed: %lu\n", GetLastError());
        return 0;
    }
    return 1;
}

// --------------------------------------------------------------------------
// The persistent target. TinyInst rewrites the return so this loops.
//
// Exported so TinyInst's -target_method finds it by symbol. Marked noinline
// so the compiler can't fold it into main and break the entry-point hook.
// --------------------------------------------------------------------------
extern "C" __declspec(dllexport) __declspec(noinline)
void fuzz(char* /*shm_name*/) {
    // 1. Pull the sample out of shared memory.
    uint32_t sample_size = *(uint32_t*)g_shm_data;
    if (sample_size == 0 || sample_size > MAX_SAMPLE_SIZE) return;

    const BYTE* sample_bytes = (const BYTE*)(g_shm_data + SHM_HEADER_SIZE);

    // 2. Wrap the bytes in an IStream the shell-link parser can consume.
    //    Heap-allocated because IPersistStream::Load may keep references
    //    transiently; refcounting handles the lifetime correctly.
    MemStream* stream = new MemStream(sample_bytes, sample_size);

    // 3. Spin up a fresh IShellLinkW for this iteration. Keeping creation
    //    inside fuzz() means each iteration starts from a known COM state
    //    and any per-instance state from the previous sample doesn't bleed
    //    forward into the next one.
    IShellLinkW* link = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IShellLinkW, (void**)&link);
    if (FAILED(hr) || !link) {
        stream->Release();
        return;
    }

    // 4. Get the IPersistStream interface — this is the structural parser
    //    entry point. CShellLink::Load walks ShellLinkHeader, LinkTargetIDList,
    //    LinkInfo, StringData, and ExtraData blocks here. This is the call
    //    that hits the byte-level format-parsing surface.
    IPersistStream* persist = nullptr;
    hr = link->QueryInterface(IID_IPersistStream, (void**)&persist);
    if (SUCCEEDED(hr) && persist) {
        // The actual parse. Crashes here are structural-parser bugs:
        // size-confusions, integer overflows in offset arithmetic, OOB
        // reads inside ExtraData block enumeration, etc.
        persist->Load(stream);
        persist->Release();

        // 5. Resolve() — the deeper attack surface. Walks the PIDL through
        //    the shell namespace, dispatches each SHITEMID by class type
        //    byte, builds the full target path including any
        //    CommonNetworkRelativeLink computation, runs tracker fixup,
        //    loads icons from the icon-location string. This is where
        //    Stuxnet's CControlPanelFolder dispatch lived and where
        //    CVE-2017-8464's SpecialFolderDataBlock + KnownFolderDataBlock
        //    namespace-redirect was triggered.
        //
        //    SLR_NO_UI       : suppress dialog popups (we're headless)
        //    SLR_NOSEARCH    : don't try to locate moved targets
        //    SLR_NOTRACK     : skip distributed link tracking
        //    SLR_NOLINKINFO  : we still want LinkInfo parsed; this flag
        //                      controls fallback path resolution, not
        //                      whether the LinkInfo block is decoded —
        //                      so leave it OFF to keep that path live.
        link->Resolve(nullptr,
                      SLR_NO_UI | SLR_NOSEARCH | SLR_NOTRACK);

        // 6. GetIDList — forces full PIDL serialization back out, which
        //    re-walks every SHITEMID and exercises the CCFSFolder /
        //    CControlPanelFolder / CRegFolder dispatch paths.
        ITEMIDLIST* idl = nullptr;
        if (SUCCEEDED(link->GetIDList(&idl)) && idl) {
            CoTaskMemFree(idl);
        }

        // 7. GetPath — exercises the path-construction logic that
        //    CVE-2015-0096 lived in (LinkInfo path concat with embedded
        //    spaces, fallback-to-LinkTargetIDList path).
        WCHAR path_buf[MAX_PATH] = {0};
        WIN32_FIND_DATAW fd = {0};
        link->GetPath(path_buf, MAX_PATH, &fd, SLGP_RAWPATH);

        // 8. GetIconLocation — the original Stuxnet trigger. Even with
        //    MS10-046 patched, the resolution path is still parsed; we
        //    want coverage of that code regardless of whether the
        //    whitelist accepts the result.
        WCHAR icon_buf[MAX_PATH] = {0};
        int icon_index = 0;
        link->GetIconLocation(icon_buf, MAX_PATH, &icon_index);
    }

    link->Release();
    stream->Release();
}

// --------------------------------------------------------------------------
// main: wire up SHM, init COM once, jump into the persistent loop.
// --------------------------------------------------------------------------
int main(int argc, char** argv) {
    if (argc != 3 || strcmp(argv[1], "-m") != 0) {
        fprintf(stderr, "Usage: %s -m <shm_name>\n", argv[0]);
        return 1;
    }

    if (!setup_shmem(argv[2])) {
        fprintf(stderr, "shared memory setup failed\n");
        return 1;
    }

    // COM init once for the lifetime of the process. Per-iteration init
    // would dominate timings and isn't where bugs are — they're in the
    // parser, which doesn't care about apartment state being torn down
    // and rebuilt.
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        fprintf(stderr, "CoInitializeEx failed: 0x%08lx\n", hr);
        return 1;
    }

    // The persistent target. TinyInst rewrites the RET so each call loops
    // back to fuzz()'s entry; -iterations on the fuzzer command line
    // bounds how many loops before the process is recycled to bound heap
    // accumulation in shell32's internal caches.
    fuzz(argv[2]);

    CoUninitialize();
    return 0;
}
