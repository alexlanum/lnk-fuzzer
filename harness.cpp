/**
 * LNK fuzzing harness for Jackalope + TinyInst.
 * 
 * Fuzz surface
 * ––––––––––––
 * fuzz() reads a mutated .lnk byte stream from Jackalope's SHM region
 * (SHMSampleDelivery, format: [uint32 len][bytes]) and feeds it to the
 * Windows Shell Link parsing path.
 * 
 * IPersistStream::Load                    – top level structure parse from the byte stream
 * IShellLinkW::Resolve                    – target resolution (LinkInfo path building, working directory normalization, icon load)
 * IShellLinkW::GetIDList                  – force LinkTargetIDList through full PIDL traversal: SHITEMID dispatch by class type byte (CVE-2010-2568, CVE-2017-8464 CControlPanelFolder attack surface)
 * IShellLinkW::GetPath                    – CommonNetworkRelativeLink path construction (CVE-2015-0096 attack surface)
 * IShellLink::GetIconLocation             – paths that resolve icon from CPL
 * IPropertyStore::GetCount/GetAt/GetValue – decode SerializedPropertyStorage (PropertyStoreDataBlock)
 * IShellLinkDataList::CopyDataBlock       – per-block re-marshal of every ExtraData signature, exercising the
 *                                           inverse path that mirrors CShellLink::Load (struct repack, length recompute).
 *
 * All of these COM methods eventually call into shell32.dll (and the namespace extension DLLs it dispatches to).
 * TinyInst is configured to instrument shell32.dll specifically. Not harness.exe. So coverage feedback comes from
 * the LNK parser itself, not from this file's configuration stuff (SHM setup, COM init, IStream wrapper, persistent
 * loop). Those run identically every iteration and carry zero scheduler signal.
 *
 * The MSI/Darwin path (MsiGetShortcutTargetW + CommandLineFromMsiDescriptorW in msi.dll) lives in a sibling
 * harness, harness_darwin.cpp. Splitting it lets that harness instrument msi.dll alone without muxing the two
 * coverage signals into one corpus.
 *
 * Persistent mode
 * –––––––––––––––
 * fuzz() is the persistent target. TinyInst rewrites its return so each call loops back to the top instead of
 * exiting the process. Per-iteration COM object lifetimes are tightly bounded (CoCreateInstance -> use -> Release)
 * so heap state doesn't accumulate across iterations beyond what shell32 itself caches. The `-iterations` flag bounds
 * how many loops happen before the harness process is recycled, which limits unbounded growth.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <objbase.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <propsys.h>
#include <propvarutil.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "oracle.h"  // behavioral (sink) oracle: turns an attacker-steered module load into a crash

// Jackalope's SHM sample delivery layout: [uint32 size][bytes...]
// All three constants must agree with LNK_MAX_BYTES in lnk_mutator.cc and
// Jackalope's Sample::max_size — if any one is smaller, large samples get
// truncated or rejected silently and the scheduler learns the wrong lesson.
#define MAX_SAMPLE_SIZE (1 << 20)                    // 2^20 = 1 MiB. Cap per sample. ~10x headroom over realistic .lnk sizes.
#define SHM_HEADER_SIZE 4                            // sizeof(uint32_t). First 4 bytes of the mapping = sample length prefix.
#define SHM_SIZE (SHM_HEADER_SIZE + MAX_SAMPLE_SIZE) // total mapping size (header + payload). Passed to MapViewOfFile.

static unsigned char* g_shm_data = nullptr;

/**
 * MemStream is a fixed memory buffer exposed as an IStream.
 * IPersistStream::Load takes an IStream as input. SHCreateMemStream exists but isn't available on every Windows
 * SDK target without extra shit, and it copies the buffer internally. This minimal IStream over the SHM region
 * avoids the copy and the link dependency. Only ::Read/::Seek/::Stat are reachable from the LNK parser; the
 * remaining IStream methods (::SetSize, ::CopyTo, ::LockRegion, etc.) return E_NOTIMPL.
 */
class MemStream : public IStream {
public:
    MemStream(const BYTE* data, ULONG size)
        : data_(data),
        size_(size),
        pos_ (0),
        refs_(1)
    {}

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if(!ppv) return E_POINTER;
        if(riid == IID_IUnknown || riid == IID_ISequentialStream || riid == IID_IStream){
            *ppv = static_cast<IStream*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }
    // refcount is interlocked. shell32 in our STA doesn't actually share these across threads, but
    // making the COM-mandated contract correct removes a foot-gun if a future code path hands the
    // stream to a worker (some LoadFromStream paths in shell32 internally pass IStream around).
    ULONG STDMETHODCALLTYPE AddRef()  override { return (ULONG)InterlockedIncrement(&refs_); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&refs_);
        if(r == 0) delete this;
        return (ULONG)r;
    }

    // ISequentialStream
    // Returns S_FALSE on a short read (fewer bytes than requested), per MSDN. Some parsers branch
    // on this vs. an S_OK with pcbRead<cb — returning the spec-compliant value is more interesting
    // for fuzzing because it actually enters those branches.
    HRESULT STDMETHODCALLTYPE Read(void* pv, ULONG cb, ULONG* pcbRead) override {
        if(!pv) return STG_E_INVALIDPOINTER;
        ULONG remaining = (pos_ < size_) ? (size_ - pos_) : 0;
        ULONG to_copy = (cb < remaining) ? cb : remaining;
        if(to_copy) memcpy(pv, data_ + pos_, to_copy);
        pos_ += to_copy;
        if(pcbRead) *pcbRead = to_copy;
        return (to_copy < cb) ? S_FALSE : S_OK;
    }
    HRESULT STDMETHODCALLTYPE Write(const void*, ULONG, ULONG*) override {
        return STG_E_ACCESSDENIED;  // read-only stream
    }

    // IStream (only Seek and Stat are actually needed by the LNK parser)
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER off, DWORD origin, ULARGE_INTEGER* new_pos) override {
        LONGLONG target;
        switch(origin){
            case STREAM_SEEK_SET: target = off.QuadPart; break;
            case STREAM_SEEK_CUR: target = (LONGLONG)pos_ + off.QuadPart; break;
            case STREAM_SEEK_END: target = (LONGLONG)size_ + off.QuadPart; break;
            default: return STG_E_INVALIDFUNCTION;
        }
        if(target < 0) return STG_E_INVALIDFUNCTION;
        // The parser is allowed to seek past EOF; Read returns 0 bytes in that case.
        pos_ = (ULONG)((target > (LONGLONG)size_) ? size_ : target);
        if(new_pos) new_pos->QuadPart = pos_;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* pstatstg, DWORD /*grfStatFlag*/) override {
        if(!pstatstg) return STG_E_INVALIDPOINTER;
        memset(pstatstg, 0, sizeof(*pstatstg));
        pstatstg->type = STGTY_STREAM;
        pstatstg->cbSize.QuadPart = size_;
        // pwcsName left null. LNK parser doesn't read it; no need to allocate.
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER)                                            override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE CopyTo(IStream*, ULARGE_INTEGER, ULARGE_INTEGER*, ULARGE_INTEGER*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Commit(DWORD)                                                      override { return S_OK; }
    HRESULT STDMETHODCALLTYPE Revert()                                                           override { return S_OK; }
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD)                  override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD)                override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Clone(IStream**)                                                   override { return E_NOTIMPL; }

private:
    const BYTE*  data_;
    ULONG        size_;
    ULONG        pos_;
    volatile LONG refs_;
};

/**
 * SHM setup
 * Same pattern as Jackalope/test.cpp
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
 * The persistent target.
 * TinyInst rewrites the RET to loop back to the entry, so each iteration re-enters fuzz() instead of returning to main().
 * extern "C" + dllexport keep the symbol findable and prevent the linker from removing it.
 * noinline prevents the compiler from inlining fuzz() into main() under /O2, which would leave TinyInst hooking dead code.
 */
extern "C" __declspec(dllexport) __declspec(noinline)
void fuzz(char* /*shm_name*/){
    // pull sample out of shared memory
    uint32_t sample_size = *(uint32_t*)g_shm_data; // [4 size][N bytes]
    if(sample_size == 0 || sample_size > MAX_SAMPLE_SIZE) return;
    const BYTE* sample_bytes = (const BYTE*)(g_shm_data + SHM_HEADER_SIZE); // bytes[0]

    // Arm input-taint tagging for this iteration: a sink hit whose module path is present in these
    // bytes is provably mutator-driven (see oracle.h). Re-armed every call; the pointer is into SHM.
    oracle_set_sample(sample_bytes, sample_size);

    // wrap the bytes in an IStream the ShellLink parser can consume.
    // allocated onto the heap because IPersistStream::Load may keep references
    // transiently; refcounting handles the lifetime properly.
    MemStream* stream = new MemStream(sample_bytes, sample_size);

    // create a fresh IShellLinkW for this iteration. Keeping creation inside fuzz() means
    // each iteration starts from a known COM state and any state from the previous sample
    // won't bleed forward into the next one.
    IShellLinkW* link = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&link);
    if(FAILED(hr) || !link){
        stream->Release();
        return;
    }

    // get the IPersistStream interface. This is the structural parser entry point.
    // CShellLink::Load walks ShellLinkHeader, LinkTargetIDList, LinkInfo, StringData,
    // and ExtraData blocks here. This is the call that hits the byte-level format parsing.
    IPersistStream* persist = nullptr;
    hr = link->QueryInterface(IID_IPersistStream, (void**)&persist);
    if(SUCCEEDED(hr) && persist){
        // the actual parse.
        // crashes here are structural parsing bugs.
        persist->Load(stream);
        persist->Release();

        // Resolve()
        // walks PIDL through the shell namespace, dispatches each SHITEMID by class type byte,
        // builds the full target path including any CommonNetworkRelativeLink computation, runs
        // tracker stuff, loads icons from the icon location string.
        //  . Stuxnet:       CControlPanelFolder dispatch here
        //  . CVE-2017-8464: SpecialFolderDataBlock + KnownFolderDataBlock namespace redirect here
        link->Resolve(nullptr, SLR_NO_UI | SLR_NOSEARCH | SLR_NOTRACK);
        
        // GetIDList
        // force full PIDL serialization back out, which re-walks every SHITEMID and exercises the
        // CCFSFolder / CControlPanelFolder / CRegFolder dispatch paths.
        ITEMIDLIST* idl = nullptr;
        if(SUCCEEDED(link->GetIDList(&idl)) && idl){
            // Reachability for the CPL-load sink. The historic CControlPanelFolder LoadLibrary
            // (CVE-2010-2568) fires on icon *extraction*, not on Resolve() — which we call with
            // SLR_NO_UI, deliberately, to avoid UI/hangs on a headless box. Bind the PIDL to its
            // parent folder and drive IExtractIconW::Extract so the SHITEMID dispatch walks into
            // CPL_LoadCPLModule -> LoadLibraryW, the exact call the sink oracle watches. Without
            // this the sink is never reached and GROUP_PIDL / GROUP_*FOLDER mutations can't trip it.
            IShellFolder* parent = nullptr;
            LPCITEMIDLIST child  = nullptr;
            if(SUCCEEDED(SHBindToParent(idl, IID_IShellFolder, (void**)&parent, (PCUITEMID_CHILD*)&child)) && parent){
                IExtractIconW* eiw = nullptr;
                if(SUCCEEDED(parent->GetUIObjectOf(nullptr, 1, (PCUITEMID_CHILD_ARRAY)&child,
                                                   IID_IExtractIconW, nullptr, (void**)&eiw)) && eiw){
                    WCHAR icon_path[MAX_PATH] = {0};
                    int   index = 0;
                    UINT  flags = 0;
                    if(SUCCEEDED(eiw->GetIconLocation(0, icon_path, MAX_PATH, &index, &flags))){
                        // Extract is the call that ends in LoadLibraryW for a control-panel item.
                        // system .cpl paths pass the oracle's allowlist; an attacker-controlled
                        // module path trips it.
                        HICON big = nullptr, ico_small = nullptr;
                        if(SUCCEEDED(eiw->Extract(icon_path, index, &big, &ico_small, MAKELONG(32, 16)))){
                            if(big)   DestroyIcon(big);
                            if(ico_small) DestroyIcon(ico_small);
                        }
                    }
                    eiw->Release();
                }
                parent->Release();
            }
            CoTaskMemFree(idl);
        }

        // GetPath
        // exercises the path construction logic that CVE-2015-0096 lived in (LinkInfo path concat with
        // embedded spaces, fallback to LinkTargetIDList path).
        WCHAR path_buf[MAX_PATH] = {0};
        WIN32_FIND_DATAW fd = {0}; // required by API; we don't read the result
        link->GetPath(path_buf, MAX_PATH, &fd, SLGP_RAWPATH);

        // GetIconLocation
        // even with MS10-046 patched, the resolution path is still parsed; we want coverage of that code
        // regardless of whether the whitelist accepts the result.
        WCHAR icon_buf[MAX_PATH] = {0};
        int icon_index = 0;
        link->GetIconLocation(icon_buf, MAX_PATH, &icon_index);

        // IPropertyStore enumeration
        // forces the SerializedPropertyStorage decoded by Load to actually flow through the property marshaling
        // code. without this, propstore mutations get parsed and then sit in CShellLink's member fields untouched.
        IPropertyStore* propstore = nullptr;
        hr = link->QueryInterface(IID_IPropertyStore, (void**)&propstore);
        if(SUCCEEDED(hr) && propstore){
            DWORD count = 0;
            if(SUCCEEDED(propstore->GetCount(&count))){
                // cap at 64 so a malformed propstore claiming a billion properties
                // can't pin the iteration. realistic .lnk files have <10 properties.
                // understand: this cap limits how many properties the harness enumerates
                // per iteration. it doesn't limit what the mutator can produce.
                if(count > 64) count = 64;
                for(DWORD i = 0; i < count; i++){
                    PROPERTYKEY key = {0};
                    if(FAILED(propstore->GetAt(i, &key))) continue;
                    PROPVARIANT val;
                    PropVariantInit(&val);
                    propstore->GetValue(key, &val);   // exercises the actual decode path
                    PropVariantClear(&val);
                }
            }
            propstore->Release();
        }

        // StringData getters
        WCHAR desc[INFOTIPSIZE] = {0};
        link->GetDescription(desc, INFOTIPSIZE);
        WCHAR args[INFOTIPSIZE] = {0};
        link->GetArguments(args, INFOTIPSIZE);
        WCHAR wd[MAX_PATH] = {0};
        link->GetWorkingDirectory(wd, MAX_PATH);
        WORD hotkey = 0;
        link->GetHotkey(&hotkey);
        int show_cmd = 0;
        link->GetShowCmd(&show_cmd);

        // ExtraData re-marshal via IShellLinkDataList::CopyDataBlock.
        // CShellLink::Load decoded each ExtraData block into member fields. CopyDataBlock(SIG)
        // forces the inverse path: serialize the cached fields back into the on-disk block layout.
        // Without this, the per-block marshal code (struct repack, GUID write, length recompute)
        // sits cold even when mutators emit interesting payloads.
        //
        // Every signature listed here corresponds to one of the GROUP_EXTRA_* / GROUP_*FOLDER /
        // GROUP_DARWIN / GROUP_TRACKER / GROUP_PROPSTORE_* operator groups in mutate.h. Keep this
        // list aligned with the LinkFlags-gated set in deserialize.c.
        IShellLinkDataList* dl = nullptr;
        if(SUCCEEDED(link->QueryInterface(IID_IShellLinkDataList, (void**)&dl)) && dl){
            // Raw hex literals rather than EXP_*/NT_*_SIG macros: not all of these names
            // are present in every Windows SDK and we want this harness portable across
            // Jackalope build environments.
            static const DWORD kSigs[] = {
                0xA0000001, // EnvironmentVariableDataBlock
                0xA0000002, // ConsoleDataBlock
                0xA0000003, // TrackerDataBlock                — GROUP_TRACKER
                0xA0000004, // ConsoleFEDataBlock
                0xA0000005, // SpecialFolderDataBlock          — GROUP_SPECIALFOLDER
                0xA0000006, // DarwinDataBlock                 — structural decode here, msi.dll consumption in harness_darwin
                0xA0000007, // IconEnvironmentDataBlock
                0xA0000009, // PropertyStoreDataBlock          — GROUP_PROPSTORE_*
                0xA000000B, // KnownFolderDataBlock            — GROUP_KNOWNFOLDER
                0xA000000C  // VistaAndAboveIDListDataBlock
            };
            for(size_t i = 0; i < sizeof(kSigs)/sizeof(kSigs[0]); i++){
                void* blk = nullptr;
                if(SUCCEEDED(dl->CopyDataBlock(kSigs[i], &blk)) && blk){
                    LocalFree(blk);
                }
            }
            dl->Release();
        }
    }
    link->Release();
    stream->Release();
}

/**
 * main: wire SHM, init COM once, jump into persistent loop.
 */
int main(int argc, char** argv){
    if(argc != 3 || strcmp(argv[1], "-m") != 0){
        fprintf(stderr, "Usage: %s -m <shm_name>\n", argv[0]);
        return 1;
    }

    if(!setup_shmem(argv[2])){
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

    // Install the behavioral (sink) oracle before any sample runs. Hooks the code-execution sinks
    // in the modules that carry shell32's LNK / namespace handlers, so an attacker-steered module
    // load becomes a recorded crash. These are the same modules worth instrumenting with TinyInst
    // (shell32 plus the property/storage helpers the propstore path forwards into).
    static const wchar_t* kOracleModules[] = { L"shell32.dll", L"windows.storage.dll", L"propsys.dll" };
    oracle_install(kOracleModules, sizeof(kOracleModules) / sizeof(kOracleModules[0]));

    // The persistent target. TinyInst rewrites the RET so each call loops
    // back to fuzz()'s entry; -iterations on the fuzzer command line
    // bounds how many loops before the process is recycled to bound heap
    // accumulation in shell32's internal caches.
    fuzz(argv[2]);

    CoUninitialize();
    return 0;
}