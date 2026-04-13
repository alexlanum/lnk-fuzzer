# MS-SHLLNK Format

```
[ShellLinkHeader]        (required)
[LinkTargetIDList]       (optional, if LinkFlags.HasLinkTargetIDList)
[LinkInfo]               (optional, if LinkFlags.HasLinkInfo)
[StringData]             (optional fields, individually flag controlled)
[ExtraData]              (optional sequence of blocks ending with TerminalBlock)
```



### ShellLinkHeader

The presence of most sections is controlled by flags in `ShellLinkHeader->LinkFlags`.

```c
typedef struct {
    uint32_t HeaderSize;      // always 0x4C
    GUID     LinkCLSID;       // identifies shell link
    uint32_t LinkFlags;       // controls which sections exist
    uint32_t FileAttributes;
    FILETIME CreationTime;
    FILETIME AccessTime;
    FILETIME WriteTime;
    uint32_t FileSize;
    int32_t  IconIndex;
    uint32_t ShowCommand;
    uint16_t HotKey;
    uint16_t Reserved1;
    uint32_t Reserved2;
    uint32_t Reserved3;
} ShellLinkHeader;
```



### LinkTargetIDList

If the `ShellLinkHeader.LinkFlags` field has the `HasLinkTargetIDList` bit set, a `LinkTargetIDList` structure will exist immediately after the `ShellLinkHeader`.

The `LinkTargetIDList` specifies the target of the shortcut when the target is a Shell Item. A Shell Item such as a Control Panel item is identified by a list of `SHITEMID`, which is ultimately a `ITEMIDLIST*` (PIDL).

This differs from a traditional filesystem path such as `C:\Users\a.exe`. A filesystem path is a string-based representation that the Windows path resolution handler interprets before ultimately resolving the object in NTFS. This representation only works for filesystem objects.

Many Windows Shell objects are not filesystem objects, and therefore cannot be located using a filesystem path.

Examples:

- Control Panel
- Recycle Bin
- Network
- Libraries

These objects exist in the Shell namespace, which is a hierarchical object tree managed by the Shell.

For these types of Shell objects, the Shell navigates a sequences of Shell Item IDs instead of parsing a path string. Each item is represented by a `SHITEMID` structure, and a sequence of these structures forms an `ITEMIDLIST` (PIDL). Each `SHITEMID` represents one shell item in the Shell namespace, allowing the Shell to traverse from the namespace root to the target object using only Item IDs.



[Windows Shell Item format classification][https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc]

```c
typedef struct _SHITEMID {
    USHORT cb;      // size of this item including cb. determines where next item begins.
    BYTE   abID[];  // variable-length shell item data (type-specific payload)
    				// first byte (abID[0]) is the class type indicator
    				// everything after is data formatted according to the class type
} SHITEMID;

typedef struct _ITEMIDLIST {
    SHITEMID mkid; // first SHITEMID in a variable-length sequence of SHITEMIDs
                   // sequence is terminated by an SHITEMID with cb = 0 (00 00 in memory)
} ITEMIDLIST;
```

`SHITEMID` binary layout:

```
Offset  Size  Field
0x00    2     cb
0x02    1     abID[0]    – first payload byte (class type byte)
0x03    ?     abID[1]    – rest of payload
```

The class type indicator is not infallible; some items don't use the type byte for dispatch, rather, they contain a GUID inside the payload to identifiy the shell namespace object that the parser can read instead to determine the type. These are signature-based items – where `abID[0]` isn't enough for the parser.

Example of a CLSID embedded inside a shell item:

```
14 00              – SHITEMID.cb = 20
1F                 – abID[0] = 0x1F (CLSID-based shell item)
50                 – abID[1] = sort order (0x50 = My Computer)
E0 4F D0 20 ...    – abID[2..17] = CLSID GUID (16 bytes)
```

In this case, the embedded GUID identifies the namespace object. The shell reads the CLSID and loads the corresponding COM namespace handler responsible for that object (ex. Desktop, Control Panel, etc.).

This is an example of a type-indicator-based shell item because the parser first checks `abID[0]` and sees `0x1F`, which indicates that the shell item contains a CLSID and the parser is to read the 16-byte GUID that follows in memory to determine which namespace object the item represents.



The Shell will read the type byte, and, if it is a known type, parse accordingly. If the type indicator alone is insufficient to determine the format, the parser may inspect additional fields within the payload or rely on the context of the parent namespace to interpret the structure.

For this reason, shell items are divided into three categories:

- [type indicator-based shell items][https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#3-type-indicator-based-shell-items] – The item format can be determined from `abID[0]`.
- [signature-based shell items][https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#4-signature-based-shell-items] – The format is recognized by patterns or structure inside the payload.
- [ancestor-based shell items][https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#5-ancestor-based-shell-items] – The structure can only be interpreted when you know the parent namespace.

The libfwsi documentation also lists several unknown shell item structures. These represent observed items whose internal format has not yet been fully reverse engineered and therefore cannot yet be classified into the categories above. I will introduce myself to these unknown structures later in this research and target them with the fuzzer.



#### Shell Item Class Type Indicators

If the link target is `Desktop\Control Panel\Programs and Features`, the `LinkTargetIDList` stores the navigation sequence as a PIDL composed of `SHITEMID` structures:

```
LinkTargetIDList
 . PIDL
     . [SHITEMID] 											– (Desktop / This PC root)
         abID[0] = 0x1F										– Root / CLSID shell item
         GUID    = {20D04FE0-3AEA-1069-A2D8-08002B30309D}

     . [SHITEMID]											– (Control Panel)
         abID[0] = 0x1F 									– CLSID shell item
         GUID    = {21EC2020-3AEA-1069-A2DD-08002B30309D}

     . [SHITEMID]											– (Programs and Features)
         abID[0] = 0x31  									– File entry (directory)
         name    = "Programs and Features"

     . [00 00]  → Terminator (SHITEMID with cb = 0)
```



`abID[0]` determines the format of the shell item and how the remainder of the payload should be interpreted.

| Type   | Class                | Desc                                                         |
| ------ | -------------------- | ------------------------------------------------------------ |
| `0x1F` | CLSID namespace item | A shell item containing a CLSID GUID identifying the namespace object (Desktop, Control Panel, etc.). |
| `0x2F` | Volume / drive       | Represents a filesystem volume (ex. `C:`).                   |
| `0x31` | File directory       | Filesystem directory entry.                                  |
| `0x32` | File                 | Filesystem file entry.                                       |
| `0x41` | Network              | Represents a network resource (`\\server\share`).            |
| `0x42` | Network server       | Network server entry.                                        |
| `0x46` | Network share        | Network share entry.                                         |

Each type byte hits different shell folder implementations. Fuzzing them will reach different attack surfaces.

The payload after `abID[0]` is formatted differently depending on the class type:
```
0x1F (root/CLSID):
    abID[1]     = sort order (0x50 = My Computer, 0x58 = Network, etc.)
    abID[2..17] = CLSID GUID (16 bytes)

0x2F (volume):
    abID[1]     = volume flags (drive type, has name, removable, etc.)
    abID[2..]   = volume name string, drive letter

0x31/0x32 (file entry):
    abID[1]     = unknown (possibly file size low byte)
    abID[2..5]  = file size (4 bytes)
    abID[6..9]  = modification date/time
    abID[10]    = file attributes (FILE_ATTRIBUTE_*)
    abID[11..]  = short filename string

0x41/0x42/0x46 (network):
    abID[1]     = network item flags
    abID[2..]   = network name string (\\server or \\server\share)
```
There is no universal layout for `abID[1..]`. The class type byte at `abID[0]` determines how every following byte is to be interpreted. This is why `MUTATE_PIDL_PARENT_CHILD_MISMATCH` exists: swapping a child class type causes the parent handler to read the payload using the wrong layout, misinterpreting every field.

The class type indicator is not always sufficient for determining the shell item format. Some shell items require additional inspection of the payload (such as embedded CLSIDs or structure signatures), and in certain cases the interpretation depends on the parent namespace context.



#### Shell Item Signatures

Some shell items cannot be identified using the first byte. Instead, their format must be determined by examining specific byte patterns or fields inside the payload.

Example of how such identification may occur conceptually:

```c
if payload[0:4] == known_pattern
    interpret as format_X

if certain flags / offsets match expected values
    treat item as structure_Y
```

In these cases the shell item structure is recognized by matching characteristic values or layout patterns within the payload rather than relying on the class type indicator byte. This approach is called signature-based identification.



##### Delegate items

One peculiar case is that of delegate items
[Geoff Chappell's reverse engineering of SHELL32's RegFolder class][https://www.geoffchappell.com/studies/windows/shell/shell32/classes/regfolder.htm]
[libfwsi DELEGATEITEMID docs][https://github.com/libyal/libfwsi/blob/main/documentation/Windows%20Shell%20Item%20format.asciidoc#46-delegate-folder-shell-item]

A delegate folder shell item is a COM object that injects shell items into a parent folder. Its outer data is the data that specific delegate folder needs to describe its item. For example, Dropbox registers itself as a delegate folder under Desktop's `DelegateFolders` registry key. When Explorer enumerates Desktop, `RegFolder` loads Dropbox's COM handler. Explorer was able to do this because it always performs a check to see whether or not a folder is delegate. The check is done by searching for a specific delegate CLSID marker in the `abID` payload of the folder currently being parsed – specifically if the first 16 bytes of payload data match the marker value `0x48D3DF965E591A74LL`. This makes the Dropbox `SHITEMID` into a slightly different, embedded structure: `DELEGATEITEMID`. Only Dropbox's COM handler knows how to interpret the outer data bytes within this `DELEGATEITEMID` structure, so `RegFolder` does not read the outer data at all, rather, it uses the outer data size field as a way to skip past the outer data and reach the marker CLSID, which it then uses as the dispatch destination. 

Corrupting the outer data size field would be interesting because `RegFolder` blindly trusts it to calculate the marker offset. If the marker check passes but the outer data bytes is corrupted, the COM handler after dispatch will ingest garbage/controlled data instead of its expected item data.

So, the COM handler that Explorer delegates to for some `DELEGATEITEMID` can be manipulated into reading incorrect fields that it expects, such as flag, path, or whatever fields. These theoretically make viable control primitives.

A delegate shell item is a `SHITEMID` structure that has a sub-item embedded inside its `abID[]` payload. The delegate item structure (inner cb, inner payload, delegate CLSID) is how the bytes inside `abID[]` are laid out for the particular class type.

```
Offset  Size  Field                     Desc
0x00    2     cb                        size of entire item
0x02    2     folder class identifier   parent RegFolder type
0x04    2     outer data size           size of delegate folder's data
0x06    var   outer data                delegate folder's data for item – only the delegate's COM handler interprets this
var     16    GUID                      delegate folder marker CLSID
var     16    delegate item CLSID       identifies COM handler for this item
```



The `RegFolder` class in SHELL32 implements the common `IShellFolder` behavior shared by most of the Shell’s virtual folders.

Example virtual namespace folders:

```
CDesktopFolder      (Desktop)         
CDrivesFolder       (My Computer)      
CControlPanelFolder (Control Panel)   
CNetFolder          (Network Places)  
CPrinterFolder      (Printers)          
CUsersFilesFolder   (Users Files)      
CCommonPlaceFolder  (Common Places)     
CTasksFolder        (Control Panel Tasks)
```

Common `IShellFolder` operations handled by the `RegFolder` class embedded in each of these virtual folders:

- PIDL parsing and validation
- shell item enumeration
- binding to child objects
- display name resolution
- delegate item dispatch to COM andlers

The outer class adds folder-specific behavior on top of this behavior.

The PIDL walking and delegate shell item dispatch logic is all done by the `RegFolder` class implemented within these outer classes.

During binding / dispatch, the flow goes like this for every virtual namespace folder:

```
CShellLink::_ResolveIDList
	. SHBindToObject
		. CDesktopFolder::BindToObject
			. RegFolder::BindToObject – walks to next SHITEMID in PIDL
				. CDrivesFolder::BindToObject
					. RegFolder::BindToObject – walks to next SHITEMID in PIDL
						. CControlPanelFolder::BindToObject
							. RegFolder::BindToObject – checks for delegate marker
```

`RegFolder` is doing the walking at each level because every outer virtual folder class delegates `BindToObject` to it fundamentally.

At the beginning of `CRegFolder::BindToObject`, a check is done:

```c
 v16 = IsDelegateRegId(PIDL, 2147942414LL);
```

This confirms to `RegFolder` if the shell item at hand is delegate. It then reads the CLSID at the calculated offset and compares it against the known marker value:

```c
// delegate marker value: {5E591A74-DF96-48D3-8D67-1733BCEE28BA}
if ( (unsigned int)v12 > 7 ){
    v45 = *((unsigned __int16 *)Item + 2); // read outer data size @0x04 (regardless of SHITEMID or DELEGATEITEMID)
    if( v12 >= v45 + 38 ){
        v50 = *(__m128i *)((char *)Item + v45 + 6);  // try to read marker
        v60 = v50;
        v51 = v50.m128i_i64[0] - 0x48D3DF965E591A74LL; // half of marker CLSID
        if ( v50.m128i_i64[0] == 0x48D3DF965E591A74LL )
            v51 = _mm_srli_si128(v50, 8).m128i_u64[0] + 0x45D71143CCE89873LL;
        if ( !v51 ) // match
            goto LABEL_90; // delegate dispatch path
    }
}
```

It reads offset 0x04 as if it's the outer data size no matter what the item actually is. Then it checks if the item is large enough `(v12 >= v45 + 38)`, calculates where the marker would be, reads 16 bytes, and compares. For a non-delegate item, `v45` is some unrelated field value, the calculated offset lands on random payload bytes, the 16-byte comparison against the marker fails, and `RegFolder` moves on to the standard path.

The outer data size (`v45`) is added to the start of the `SHITEMID` and then `+ 6` is done to skip `cb`, `class_type`, and the outer data size field itself. If the item is a delegate, then this offset in the payload will have the delegate marker CLSID occupying the next 16 bytes. If the 16 bytes at this point match the delegate marker CLSID, then `RegFolder` goes to `LABEL_90`. Otherwise, `RegFolder` checks which interface was requested (`a4`) and attempts to query it.

At delegate dispatch (`LABEL_90` and beyond), `RegFolder` reads the next 16 bytes of the payload which come immediately after the marker CLSID. These 16 bytes determine which COM object gets loaded.

This second CLSID is passed to `CRegFolder::_CreateDachedDelegateFolder`, which checks if the COM object is already cached. If not, it creates the COM object by calling:

```c
CachedObject = _SHCoCreateInstance(
    a2, // delegate CLSID from the PIDL (16 bytes after the marker)
    0,
    0x401u,
    1,
    0,
    &GUID_add8ba80_002b_11d0_8f0f_00c04fd7d062, // IID_IShellExtInit
    (LPVOID *)&v20
);
```

The loaded object is then initialized via `_InitFromMachine`, queried for `IShellFolder`, and cached for future use.

Corrupting the delegate CLSID (16 bytes after marker) in a `DELEGATEITEMID` causes `_SHCoCreateInstance` to process attacker-controlled bytes. For instance, if you corrupt the delegate item CLSID, `_CreateCachedDelegateFolder` calls `_SHCoCreateInstance` with whatever 16 bytes you put there, then queries for `IShellFolder`. If those bytes happen to be the CLSID of My Computer (`CDrivesFolder`), the call succeeds: `CDrivesFolder` implements `IShellFolder`. Now `RegFolder` hands the delegate's outer data to `CDrivesFolder`, which tries to parse it as if it's drive enumeration data. But the outer data was written by a completely different delegate handler. Every field is misinterpreted.

Outcomes:

1. CLSID doesn’t exist anywhere – `CoCreateInstance` returns `CLASSNOTREGISTERED`. 
   - Error handling paths in `_CreateCachedDelegateFolder` tested.

   

   

2. CLSID exists but COM object doesn’t implement `IShellFolder`.

   - `_SHCoCreateInstance` succeeds (DLL loaded, constructor runs),
   - `_InitFromMachine` inits the object (state potentially modified),
   - `QueryInterface` for `IShellFolder` fails with `E_NOINTERFACE`.
   - The object was created and partially initialized before failure.
   - Error path must tear down the object and undo any `_InitFromMachine` state changes.
   - Incomplete cleanup has potential.

   

   

3. CLSID maps to a real `IShellFolder` that receives payload data it wasn’t meant to

   - Handler misparsing, potential crash in `BindToObject`/`ParseDisplayName`.

   

   

4. CLSID is blocked by shell extension load policy

   - `_ShouldLoadShellExt` returns `E_ACCESSDENIED`, policy enforcement tested.



5. `CoCreateInstance` fails with `CLASS_E_CLASSNOTREGISTERED` or `CO_E_ERRORINDLL`, but CLSID has `InProcServer32` registry entry. Function falls back to `LoadLibraryExW` on the DLL path from registry, then `_CreateFromModule`. Secondary DLL loading path.



6. CLSID matches a SHELL32 class, `_CreateFromDllGetClassObject` or `_CreateFromSystem32Dll` creates the object through windows.system.launcher.dll class factory, bypassing `CoCreateInstance` and the registry entirely. Internal class receives attacker-controlled delegate payload data.



#### Shell Item Ancestors

These are items whose structure can only be interpreted correctly based on their parent namespace.

- same bytes
- different meaning depending on parent

The parser must know the parent namespace in order to know how to interpret child item in these cases.



**Example 1**

- Network
  - server
    - share

The share item structure only makes sense if the parent is a network server.

**Example 2**

- Control Panel
  - applet

The payload structure is defined by the Control Panel namespace handler.



When Shell resolves a PIDL, it walks each item left to righ. It interprets each item by the namespace handler that was used on the item before it (the parent). So, the parent determines how the child is parsed.

A PIDL looks like this:

```
[Desktop 0x1F] -> [C: drive 0x2F] -> [Users folder 0x31] -> [file.txt 0x32]
```
In this case, Desktop is the root namespace. It knows how to interpret the next item in the list.
It sees 0x2F and hands it to the filesystem volume handler. The handler sees 0x31 and hands it to the directory handler. The directory handler sees 0x32 and hands it to the file handler. 

Each parent knows what child types are valid. A filesystem volume expects filesystem directories as children, network resource expects network servers, CLSID namespace item expects items that belong to that specific COM handler, and so on.

For example, `CDesktopFolder::_GetFolderForItem` shows this behavior:

```c
type = pidl->mkid.abID[0]; // type = item class type byte
if((type & 0x78) == 0x38)
    return m_pSpecialFolderFactory; // special folder handler
else
    return m_pDefaultFolderFactory; // default handler
```
The parent folder decides which handler processes the child based on the child's type byte. But deeper in the tree, a network folder handler is processing children; it expects network server items. If you put a filesystem directory item (0x31) as a child of a network resource (0x41), the network handler will try to interpret filesystem directory bytes as network data. It will read fields at offsets that mean one thing in a directory item but something completely different in a network item. This is what `MUTATE_PIDL_PARENT_CHILD_MISMATCH` targets; it changes a child's class type to something the parent handler does not expect, for instance:
```
[Desktop 0x1F] -> [C: drive 0x2F] -> [network share 0x46] <- wrong!
```
The volume handler (0x2F) gets an 0x46 child and either crashes, misparses, or dispatches to a handler that reads the payload with completely wrong assumptions about its layout. The bytes are structured as a filesystem item but are interpreted as a network item, meaning field boundaries are wrong, string offsets land between integers, and size fields get read from arbitrary positions. Corrupting the relationship between items and their parents is a direct path to parser confusion.




#### PIDL Resolution

When resolving the link target, the Shell walks the PIDL and resolves each `SHITEMID` through the Shell namespace.

The PIDL itself is not interpreted directly by the Shell, rather, resolution is delegated to the specific Shell namespace extension folder responsible for the parent namespace node.

1. The Shell calls `SHCreateItemFromIDList` to convert the PIDL into a `CShellItem` object, which internally stores the PIDL but does not immediately resolve it.
2. When the Shell needs to access this object, it calls `CShellItem::BindToHandler`.
3. `BindToHandler` calls `SHBindToFolderIDListParentEx`, which splits the PIDL into two components:
   - The parent namespace folder for this specific class of item
   - The last `SHITEMID` (child object)
4. Then `SHBindToFolderIDListParentEx` is called, which binds to the parent namespace folder.
   - If no root folder, the Shell begins resolution from the Desktop shell folder (`CDesktopFolder`).
5. Once the parent namespace folder is obtained, the Shell calls `IShellFolder::BindToObject`, passing the child `SHITEMID` to it.
6. The parent shell folder implementation (ex. `CDesktopFolder`) interprets `SHITEMID.abID[0]` ItemID class/type byte and returns the correct namespace handler based on that.



#### Namespace Dispatch

The parser is deeply stateful here and delegates to specific COM objects registered per-CLSID.

ItemID dispatch happening within `CDesktopFolder::BindToObject`:

```c
FolderForItem = CDesktopFolder::_GetFolderForItem((CDesktopFolder*)(v9 - 48), a2, &v22);
```

That `_GetFolderForItem` function:

```c
HRESULT CDesktopFolder::_GetFolderForItem(
    LPCITEMIDLIST pidl,
    IShellFolder2 **ppFolder)
{
    BYTE type;

    *ppFolder = NULL;

    // If the PIDL is already rooted, return the desktop handler
    if (_SHIsRooted(pidl))
    {
        return this->m_pDesktopFolderFactory->QueryInterface(
            IID_IShellFolder,
            (void**)ppFolder
        );
    }

    if (pidl && pidl->mkid.cb != 0)
    {
        type = pidl->mkid.abID[0]; // pidl.item.payload[0]

        // check shell item class bits
        // masking `type` with 0x78 (01111000) keeps bits 6, 5, 4, 3 and clears the others
        // (type & 0x78) == 0x38 means (type & 01111000) == 00111000
        // so this is isolating the upper nibble of the first byte in the SHITEMID
        if ((type & 0x78) == 0x38)
        {
            if (!this->m_pSpecialFolderFactory)
                return E_FAIL;

            return this->m_pSpecialFolderFactory->QueryInterface(
                IID_IShellFolder,
                (void**)ppFolder
            );
        }
    }

    if (!this->m_pDefaultFolderFactory)
        return RPC_E_DISCONNECTED;

    return this->m_pDefaultFolderFactory->QueryInterface(
        IID_IShellFolder,
        (void**)ppFolder
    );
}
```



### LinkInfo

If the `ShellLinkHeader.LinkFlags` field has the `HasLinkInfo` bit set, a LinkInfo structure exists in the file. The LinkInfo section specifies information necessary to resolve a link target if it is not found in its original location.

This includes:

- volume which the target was stored on in a VolumeID
- mapped drive letter
- UNC path if one existed when the link was created

When Windows tries to open an LNK and the target isn't at the path stored in the `IDList`, it falls back to LinkInfo to try to find it. It encodes two alternative resolution strategies — local volume path, and UNC network path — and the parser tries them in order. This is why it exists as a separate section from the `IDList` entirely.



LinkInfo binary layout:

```
Offset  Size  Field
──────────────────────────────────────────────────────────────────────
0x00    4     LinkInfoSize                		. total size of this structure
0x04    4     LinkInfoHeaderSize          		. size of header portion only
0x08    4     LinkInfoFlags               		. which fields are present
0x0C    4     VolumeIDOffset              		. offset from LinkInfo start
0x10    4     LocalBasePathOffset         		. offset from LinkInfo start
0x14    4     CommonNetworkRelativeLinkOffset
0x18    4     CommonPathSuffixOffset

// these two are present only when LinkInfoHeaderSize >= 0x24
0x1C    4     LocalBasePathOffsetUnicode  		. (optional)
0x20    4     CommonPathSuffixOffsetUnicode 	. (optional)

// variable data
?       var   VolumeID                    		. (if flag A set)
?       var   LocalBasePath               		. (if flag A set, null-terminated ANSI)
?       var   CommonNetworkRelativeLink   		. (if flag B set)
?       var   CommonPathSuffix            		. (always present, null-terminated ANSI)
?       var   LocalBasePathUnicode        		. (if flag A set AND header >= 0x24)
?       var   CommonPathSuffixUnicode     		. (if header >= 0x24)
```



The spec defines bit 0 as `VolumeIDAndLocalBasePath`. It is one flag controlling both fields together. If `VolumeID` is present, `LocalBasePath` is present. If not, neither is. They always come as a pair.

A link target is either local (`VolumeID` path) or on a remote network (`CommonNetworkRelativeLink` path). The spec allows both flags to be set simultaneously, which is itself a fuzz target, as the parser may not handle that well.



#### VolumeID

[VolumeID][https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/b7b3eea7-dbff-4275-bd58-83ba3f12d87a] records which physical volume the link target lived on at creation time.

```
Offset  Size  Field
──────────────────────────────────────────────────────────────────────
0x00    4     VolumeIDSize         . size of entire VolumeID structure
                                     MUST be > 0x00000010
                                     all offsets within MUST be < this
0x04    4     DriveType            . see spec
0x08    4     DriveSerialNumber    . volume serial number
0x0C    4     VolumeLabelOffset    . offset from VolumeID start to label string
                                     if this value == 0x00000014 exactly,
                                     it is IGNORED and VolumeLabelOffsetUnicode
                                     is used instead
── present only when VolumeLabelOffset == 0x00000014 ─────────────────
0x10    4     VolumeLabelOffsetUnicode  (optional)
── variable data ─────────────────────────────────────────────────────
?       var   Data                 . the actual label string lives here,
                                     accessed via the offset field(s)
```



#### CommonNetworkRelativeLink

[CommonNetworkRelativeLink][https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/23bb5877-e3dd-4799-9f50-79f05f938537] specifies which network path must be used to get to the physical volume defined by the `VolumeID`. It stores the UNC share path and optionally the drive letter that was substituted for it. These are two different representations of the same network location, and the parser uses whichever is available. More docs [here][https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc#43-network-share-information].

```
Offset  Size  Field
──────────────────────────────────────────────────────────────────────
0x00    4     CommonNetworkRelativeLinkSize
                MUST be >= 0x00000014
                all offsets within MUST be < this value
0x04    4     CommonNetworkRelativeLinkFlags
                bit 0 = ValidDevice. bit 1 = ValidNetType.
                all other bits reserved/must be zero
0x08    4     NetNameOffset
                offset, in bytes, from the start of the CommonNetworkRelativeLink structure to
                the NetName string. Always present.
0x0C    4     DeviceNameOffset
                offset from structure start to DeviceName string
                if ValidDevice not set, MUST be zero
0x10    4     NetworkProviderType
                if ValidNetType not set, MUST be zero
                if ValidNetType set, MUST be one of the defined values
── present only when CommonNetworkRelativeLinkSize >= 0x00000022 ──────
0x14    4     NetNameOffsetUnicode   (optional)
0x18    4     DeviceNameOffsetUnicode (optional)
── variable data ─────────────────────────────────────────────────────
?       var   NetName         null-terminated ANSI — the UNC path
?       var   DeviceName      null-terminated ANSI — the mapped drive letter
?       var   NetNameUnicode  null-terminated Unicode
?       var   DeviceNameUnicode null-terminated Unicode
```



### ExtraData

Individual ExtraData blocks have their own relationship to LinkFlags. Some blocks are only meaningful when a corresponding LinkFlag is set:

- `EnvironmentVariableDataBlock` – `LinkFlags->HasExpString`
- `IconEnvironmentBlock` – `LinkFlags->HasExpIcon`
- `DarwinDataBlock` – `LinkFlags->HasDarwinID`
- `ShimDataBlock` – `LinkFlags->RunWithShimLayer`



# Deserialization

- `Load(IStream*)`
- `Load(…)`
- `_LoadFromFile`
  - Path-based loader
  - Converts a path to an `IStream`
  - Calls `_LoadFromStream`
  - Adds reset logic and recursive link prevention
- `_LoadFromStream`
  - The actual MS-SHLLNK parser that almost everything calls
- `_LoadFromPIF`
- `_LoadFromSymLink`
- `_LoadIDList`
- `_LoadMarshalOnlyValue`
- `LoadFromIdList`
  - binds a namespace PIDL to a shell item and dispatches to the appropriate deserialization loader based on the object’s backing type (conditionally calls `_LoadFromFile` or `_LoadFromStream`).
- `LoadFromPathHelper`
- `CTracker::Load`
- `Load(IPropertyBag*, IErrorLog*)` -- IGNORE FOR NOW
  - This is not MS-PROPSTORE or an extra data block; it is an entirely separate key/value mechanism.
  - A COM client has an existing `CShellLink` instance and asks it to load its state from an `IPropertyBag` instead of from a binary `.lnk` stream.
  - Occurs when the ShellLink is being fed structured key/value data rather than MS-SHLLNK bytes.
  - This is COM persistence, not file parsing. It must be explicitly driven; i dont think Explorer will ever automatically call it.
  - ActiveX controls can be persisted via property bags -- interesting equivalent concept, look at historical vulnerabilities



## ExtraData: Property Storage

The parsing of the `PropertyStoreDataBlock` must be understood at a deep level.

### Windows Property System

Windows doesn’t treat metadata as arbitrary key/value strings. It has a typed, schema-driven property system.

A property in Windows is made up of three components:

1. Property key (`PROPERTYKEY`)
2. Variant type (`VARTYPE`)
3. Value (`PROPVARIANT`)

```c++
struct PROPERTYKEY{
  GUID fmtid; // format ID / property set ID
  DWORD pid;  // numeric property ID in that set
}
```

A Property Store inside a `.lnk` is a *serialized* representation of the Windows Property System, as a `.lnk` file is just bytes on disk. By serialized, I mean Windows converts the in-memory `IPropertyStore` (which contains `PROPERTYKEY` -> `PROPVARIANT` pairs) into the MS-PROPSTORE binary format. That formatted binary stream is then embedded inside the `.lnk` as a payload inside the `PropertyStoreDataBlock` block.



### Property Store

A Property Store is an object implementing [IPropertyStore][https://learn.microsoft.com/en-us/windows/win32/api/propsys/nn-propsys-ipropertystore] that maintains multiple sets of a key -> variant pairs.

- Property: one FMTID + PID (key) value
- Property set: all properties that share the same FMTID
- Property store: a container of properties from multiple FMTIDs (thus multiple property set entries)

In the MS-PROPSTORE format, each FMTID group becomes one “Serialized Property Storage” set.



Example adding into a property store using a full key:

```c++
store->SetValue(PKEY_Title, pv);
```

The `PKEY` defines which property set it belongs to, as keys are FMTID + PID and property sets are defined by the FMTID.

If there is no existing property entry with that exact `PROPERTYKEY` (same FMTID + PID), `IPropertyStore::SetValue` creates one.

If a property with the same `PROPERTYKEY` (same FMTID + PID) already exists in the store, `IPropertyStore::SetValue` replaces the existing value with the new `PROPVARIANT`.



### MS-PROPSTORE

A Serialized Property Store is not just a container of key value pairs, rather, it's a multilayered structure by which alignment and indexing must be done carefully. The structure defines how the data within an object implementing `IPropertyStore` is to be persisted as a binary stream.



The Serialized Property Store (MS-PROPSTORE) binary format is a variable-sized sequence of Serialized Property Storage (property set) structures:

| Offset | Size | Value      | Description                                                  |
| ------ | ---- | ---------- | ------------------------------------------------------------ |
| 0      | 4    |            | Size of the property store. Includes the 4 bytes of the size itself |
| 4      | Var  |            | Zero or more Serialized Property Storage (property set) structures |
| …      | 4    | 0x00000000 | Terminal identifier                                          |

The last property set must have a Storage Size of 0 to terminate the property store.

> NOTE: In Windows Shell items the size of the property store is not necessarily stored directly before the first property set.



The Serialized Property Storage structure is a variable-sized sequence of Serialized Property Value structures (property records):

The property store payload layout in bytes:
```
BYTE 0  – [storage_size]    . 4  bytes: size of this whole storage
BYTE 4  – [version]         . 4  bytes: must be "1SPS"
BYTE 8  – [fmtid]           . 16 bytes: property set (determines naming scheme)
```

Integer-named values (`fmtid != D5CDD505-2E9C-101B-9397-08002B2CF9AE`):
```
BYTE 24 – [value_size]      . 4  bytes: size of this value entry (min 9)
BYTE 28 – [property_id]     . 4  bytes: numeric PID
BYTE 32 – [reserved]        . 1  byte:  must be 0x00
BYTE 33 – [typed_value]     . variable: actual property data
```

String-named values (`fmtid == D5CDD505-2E9C-101B-9397-08002B2CF9AE`):
```
BYTE 24 – [value_size]      . 4  bytes: size of this value entry
BYTE 28 – [name_size]       . 4  bytes: byte count of name string incl. null
BYTE 32 – [reserved]        . 1  byte:  must be 0x00
BYTE 33 – [name_string]     . variable: null-terminated Unicode property name
BYTE ?? – [typed_value]     . variable: actual property data
```

One Serialized Property Storage structure corresponds to one FMTID. If a Property Store holds properties from multiple FMTIDs, there will consequently be multiple Serialized Property Storage entries.

If the Format ID is `{D5CDD505-2E9C-101B-9397-08002B2CF9AE}`, all Serialized Property Values in the set must be "String Named". Otherwise, all values must be "Integer Named".

The last Serialized Property Value in the set must have a Value Size of 0 to terminate the property set.


The [Serialized Property Value (String Name)][https://winprotocoldoc.z19.web.core.windows.net/MS-PROPSTORE/%5bMS-PROPSTORE%5d.pdf#%5B%7B%22num%22%3A55%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C181%2C0%5D] variable-sized structure specifies a single property within a serialized property set, where it is identified by a unique Unicode string:

| Offset | Size | Value | Description                                                  |
| ------ | ---- | ----- | ------------------------------------------------------------ |
| 0      | 4    |       | Value Size. Includes the 4 bytes of the size itself          |
| 4      | 4    |       | Name Size                                                    |
| 8      | 1    | 0x00  | Reserved                                                     |
| 9      | Var  |       | Name String. Null-terminated Unicode string (must be unique within the enclosing set) |
| …      | Var  |       | TypedPropertyValue                                           |



The [Serialized Property Value (Integer Name)][https://winprotocoldoc.z19.web.core.windows.net/MS-PROPSTORE/%5bMS-PROPSTORE%5d.pdf#%5B%7B%22num%22%3A58%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C405%2C0%5D] variable-sized structure specifies a single property within a serialized property set, where it is identified by a unique unsigned integer.

| Offset | Size | Value | Description                                                  |
| ------ | ---- | ----- | ------------------------------------------------------------ |
| 0      | 4    |       | Size of the property record  The size includes the 4 bytes of the size itself |
| 4      | 4    |       | Numeric Property ID (must be unique within the enclosing set) |
| 8      | 1    | 0x00  | Reserved                                                     |
| 9      | Var  |       | TypedPropertyValue                                           |



[more][https://github.com/libyal/libfwps/blob/main/documentation/Windows%20Property%20Store%20format.asciidoc#3-property-sets]



#### Alignment

MS-PROPSTORE tries to enforce the following alignment rules:

- 4-byte alignment for structures
- Offsets must reference aligned value positions
- Storage Size must include padding

If alignment is incorrect, deserialization fails.



### PropertyStoreDataBlock

The [ExtraData][https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/c41e062d-f764-4f13-bd4f-ea812ab9a4d1] section of a `.lnk` file contains a sequence of variable-length blocks; each block sharing the following layout:

```c
DWORD BlockSize;
DWORD BlockSignature;
BYTE  Payload[BlockSize - 8]
```



When a `BlockSignature` of `0xA0000009` is present, the file layout becomes:

```c#
[ShellLinkHeader]
[StringData]					// optional
[LinkInfo]						// optional
[ExtraData Blocks...]
								// may or may not be ExtraData blocks before
    [BlockSize]
    [0xA0000009]
    [SerializedPropertyStore]	// MS-PROPSTORE formatted bytes
		...
    [0x00000000] 				// terminator
            					// may or may not be ExtraData blocks after
```

The payload for the `PropertyStoreDataBlock` block is an MS-PROPSTORE binary stream, which is a serialized representation of an `IPropertyStore` implementation.



### Materialization

`CShellLink::_LoadFromStream` performs two different kinds of work on ExtraData blocks:

First, it unconditionally reads all blocks:

```c
StringCoAlloc = SHReadDataBlockList(a2, this + 55);
```

- Reads every ExtraData block
- Stores them in a linked list
- Does not interpret them
- Just reads all of the blocks into the list unconditionally

After that, it selectively interprets certain block signatures during load:

```c
SHFindDataBlock(*(this + 55), 2684354572LL); // A000000C (VistaAndAboveIDListDataBlock)
SHFindDataBlock(v17, 2684354566LL); 		 // A0000006 (DarwinDataBlock)
SHFindDataBlock(*(this + 55), 2684354563LL); // A0000003 (TrackerDataBlock)
```

- `TrackerDataBlock` is handled via `CTracker::Load`
- `VistaAndAboveIDListDataBlock` is used to clone PIDLs

Only those three blocks are actively interpreted during load; there is no immediate parsing of the `PropertyStoreDataBlock`. Instead, it is parsed when a system component requests anything that requires properties from this specific property store, at which point `CShellLink::_GetPropertyStore` is called to ingest, then, `CMemPropStore::GetValue` is called for actual parsing. Understand that parsing happens on demand per property access.



`CShellLink::_GetPropertyStore` lazily ingests the `PropertyStoreDataBlock` and materializes it:

```assembly
mov    edx, 0A0000009h
mov    rcx, [rax+1B8h]
call   cs:__imp_SHFindDataBlock ; returns pointer to the start of the PropertyStoreDataBlock in the linked list
nop    dword ptr [rax+rax+00h]
test   rax, rax
jz     loc_18014EC30
mov    edx, [rax] 		; edx = BlockSize (first thing in the structure)
cmp    edx, 8 		 	; BlockSize must be >= header size
jb     loc_18014EC30    ; failure handling

; rax + 0 | BlockSize
; rax + 4 | Signature
; rax + 8 | Payload

add    edx, 0FFFFFFF8h  ; subtract 8
lea    rcx, [rax+8]		; rcx = pointer to that serialized payload
mov    [rsp+58h+var_38], rsi
lea    r9, _GUID_886d8eeb_8cf2_4446_8d02_cdba1dbdcf99 ; IID_IPropertyStore
xor    r8d, r8d
call   cs:__imp_PSCreateMemoryPropertyStoreFromSerializedData ; allocate and construct the object
nop    dword ptr [rax+rax+00h]
test   eax, eax
js     loc_18014EC30 ; jump to failure handling
```

`propsys.dll!PSCreateMemoryPropertyStoreFromSerializedData` allocates and constructs an `IID_IPropertyStore` object:

```c++
PSCreateMemoryPropertyStoreFromSerializedData(
    /* const BYTE* */  payload_ptr,        // rcx
    /* DWORD       */  payload_size,       // rdx
    /* DWORD       */  0,                  // r8
    /* REFIID      */  IID_IPropertyStore, // r9
    /* void**      */  &ppv                // stack
){
    IPersistSerializedPropStorage* persist;
    PSCreateMemoryPropertyStore(IID_IPersistSerializedPropStorage, (void**)&persist);
    persist->SetPropertyStorage(payload_ptr, payload_size); // store the serialized blob internally
    persist->SetFlags(flags);
    persist->QueryInterface(IID_IPropertyStore, ppv);
    persist->Release();
}
```

`CMemPropStore::SetPropertyStorage` accepts, validates, and stores the serialized MS-PROPSTORE payload:

```c++
// 1. Validates structure (s_ValidateStorage)
// 2. Computes total size by walking chunks
// 3. Allocates buffer
// 4. Copies the serialized blob
HRESULT CMemPropStore::SetPropertyStorage(
    const BYTE* pStorage,
    ULONG cbStorage
){
    if(cbStorage == 0){
        // reset internal state
        CMemPropStore::AcquireWriteLock();
        CMemPropStore::DeleteAllProps();
        CoTaskMemFree(internalBuffer);
        internalBuffer = nullptr;
        storedSize = 0;
        serializedSize = 0;
        CMemPropStore::_ReleaseWriteLock();
        return S_OK;
    }
    
    HRESULT hr = s_ValidateStorage(pStorage, cbStorage); // USER INPUT
    if(FAILED(hr))
        return hr;
    
    ULONG computedSize = 0;
    
    if(pStorage){
        ULONG chunkSize = *(ULONG*)pStorage;
        computedSize = 4;
        
        while(chunkSize != 0){
            pStorage += chunkSize;
            computedSize += chunkSize;
            chunkSize = *(ULONG*)pStorage;
        }
    }
    
    if(computedSize > 0x08000000) // 128MB limit
        return E_INVALIDARG;
    
    // Allocate and copy blob
    BYTE* newBuffer = nullptr;
    
    if(computedSize > 0){
        newBuffer = CoTaskMemAlloc(computedSize);
        memcpy(newBuffer, originalStorage, computedSize);
    }
    
    // Replace internal storage
    AcquireWriteLock();
    DeleteAllProps();
    Free(oldInternalBuffer);
    internalBuffer = newBuffer;
    storedSize = computedSize;
    serializedSize = computedSize;
    ReleaseWriteLock();

    return S_OK;
}
```

`CMemPropStore::GetValue` retrieves a property value using one of two backends:

1. Serialized-blob mode (lazy deserialization path)
   - only the raw MS-PROPSTORE blob exists
   - `GetValue` traverses the blob, finds property entry, calls `StgDeserializePropVariant` (deserialization)
2. Hash-table mode (already materialized properties)
   - properties already exist as real `PROPVARIANT`s in a hash table
   - `GetValue` computes a hash, finds property entry, calls `PropVariantCopy` (no deserialization)

```c++
HRESULT CMemPropStore::GetValue(
    const PROPERTYKEY& key,
    PROPVARIANT* pvar_out
){
    if(!pvar_out)
        return E_POINTER;
    
    PropVariantInit(pvar_out); // zero output
    
    AcquireSRWLockShared(&this->Lock); // Slim Reader/Writer Lock
                                       // (allow multiple readers, but block writers)
    
    //
    // serialized blob backend
    if(this->internalBuffer && !this->fMaterialized){
        const BYTE* blob = this->internalBuffer;
        ULONG cbBlob = this->serializedSize;

        if(SUCCEEDED(s_ValidateStorage((SERIALIZEDPROPSTORAGE*)blob, cbBlob))){
            auto storage = (SERIALIZEDPROPSTORAGE*)blob;

            // walk PROPSTORAGE chunks
            while(storage->cbStorage != 0){

                if(storage->fmtid == key.fmtid){

                    BYTE* prop = storage->SerializedPropertyList;
                    
                    // walk SERIALIZEDPROPERTYVALUE entries
                    while(*(ULONG*)prop != 0){

                        auto entry = (SERIALIZEDPROPERTYVALUE*)prop;

                        if(entry->pid == key.pid){

                            const BYTE* valuePtr = entry->SerializedValue;

                            ULONG valueSize = entry->cbProp - headerOffset;

                            // alignment-sensitive deserialization
                            if(((uintptr_t)valuePtr & 7) != 0){

                                BYTE* temp = (BYTE*)LocalAlloc(0, valueSize);

                                if(temp){
                                    memcpy(temp, valuePtr, valueSize);

                                    StgDeserializePropVariant(
                                        (const SERIALIZEDPROPERTYVALUE*)temp,
                                        valueSize,
                                        pvar_out);

                                    LocalFree(temp);
                                }
                            }
                            else{
                                StgDeserializePropVariant(
                                    (const SERIALIZEDPROPERTYVALUE*)valuePtr,
                                    valueSize,
                                    pvar_out);
                            }

                            ReleaseSRWLockShared(&this->Lock);
                            return S_OK;
                        }

                        prop += entry->cbProp;
                    }
                }

                storage = (SERIALIZEDPROPSTORAGE*)((BYTE*)storage + storage->cbStorage);
            }
        }
    }
    
    //
    // hash-table backend (properties already materialized, fast O(1) lookup)
    if(this->hashTable){

        ULONG hash = ComputeHash(key);
        ULONG index = hash % this->bucketCount;

        for(;;){

            auto entry = &this->hashTable[index];

            if(entry->state == EMPTY)
                break;

            if(entry->state == OCCUPIED && entry->key == key){
                PropVariantCopy(
                    pvar_out,
                    &entry->value);

                ReleaseSRWLockShared(&this->Lock);
                return S_OK;
            }

            index = (index + 1) % this->bucketCount;
        }
    }
    
    ReleaseSRWLockShared(&this->Lock);
    return S_OK; // returns empty variant if nothing found
}
```

- https://learn.microsoft.com/en-us/windows/win32/sync/slim-reader-writer--srw--locks



### Deserialization

`propsys.dll!StgDeserializePropVariant` validates and orchestrates deserialization of the MS-PROPSTORE blob:

```assembly
; Disassembly @ C:\Users\Me\Desktop\Tests\tests\StgDeserializePropVariant.asm
; Disassembly @ C:\Users\Me\Desktop\Tests\tests\DeserializeHelper_Worker.asm
```

The actual parsing engine lies within a member function `propsys.dll!DeserializeHelper::Worker`.



This function is over 1k lines, so I'm going to, at a high level, determine the location of any of the following areas:

- Input consumption points
- LNK parsing
- Loops and conditionals
- Memory operations
- Error paths (early returns or jumps to invalid data)



It ultimately converts a `SERIALIZEDPROPERTYVALUE` into a `PROPVARIANT`:

```c
typedef struct tagPROPVARIANT {
    VARTYPE vt; // type discriminator indicating which union member is active
    union { // structured value storage
        LONG lVal;
        ULONGLONG ullVal;
        LPWSTR pwszVal; // pointer to separately allocated string (for VT_LPWSTR)
        FILETIME filetime;
        ...
    };
} PROPVARIANT;
```



## ExtraData: SpecialFolderDataBlock

If the .lnk file targets one of the special system folders, this block contains the identifying information of that special folder. For example, special folders such as desktops, documents, or program files can be specified here.

```
0x00  4  BlockSize          = 0x10
0x04  4  BlockSignature     = 0xA0000005
0x08  4  SpecialFolderID    = CSIDL value
0x0C  4  Offset             = index into PIDL
```

The "first child segment offset" is just an index into the PIDL that tells the Shell which shell item in the LinkTargetIDList the special folder refers to. So it is just an offset into the PIDL.

CSIDL (Constant Special Item ID List) values:
```
CSIDL_DESKTOP              = 0  (0x00)  — Desktop
CSIDL_INTERNET             = 1  (0x01)  — Internet Explorer
CSIDL_PROGRAMS             = 2  (0x02)  — Start Menu\Programs
CSIDL_CONTROLS             = 3  (0x03)  — Control Panel (see CVE-2017-8464)
CSIDL_PRINTERS             = 4  (0x04)  — Printers
CSIDL_PERSONAL             = 5  (0x05)  — My Documents
CSIDL_FAVORITES            = 6  (0x06)  — Favorites
CSIDL_STARTUP              = 7  (0x07)  — Startup folder
CSIDL_RECENT               = 8  (0x08)  — Recent documents
CSIDL_SENDTO               = 9  (0x09)  — SendTo
CSIDL_BITBUCKET            = 10 (0x0A)  — Recycle Bin
CSIDL_STARTMENU            = 11 (0x0B)  — Start Menu
CSIDL_DESKTOPDIRECTORY     = 16 (0x10)  — Desktop directory
CSIDL_DRIVES               = 17 (0x11)  — My Computer
CSIDL_NETWORK              = 18 (0x12)  — Network Neighborhood
CSIDL_NETHOOD              = 19 (0x13)  — NetHood
CSIDL_FONTS                = 20 (0x14)  — Fonts
CSIDL_SYSTEM               = 37 (0x25)  — System32
CSIDL_WINDOWS              = 36 (0x24)  — Windows directory
CSIDL_CONNECTIONS          = 49 (0x31)  — Network Connections
CSIDL_COMPUTERSNEARME      = 61 (0x3D)  — Computers Near Me
```

Injecting a `SpecialFolderDataBlock` with different CSIDL values forces different namespace invocations. Each one routes resolution through a different handler.
`MUTATE_SPECIALFOLDER_CSIDL` sets the folder ID to known values like `CSIDL_CONTROLS` (3) to force namespace context switches.
`MUTATE_SPECIALFOLDER_CSIDL_RANDOM` tests what happens with undocumented / invalid CSIDLs.
`MUTATE_SPECIALFOLDER_OFFSET` sets the child segment offset to the wrong `SHITEMID` to see if the Shell will reinterpret arbitrary PIDL bytes through whatever namespace the folder ID specifies. For instance, the Control Panel handler might read filesystem directory bytes as a CPL descriptor.
`MUTATE_SPECIALFOLDER_INJECT` does what CVE-2017-8464 did, adding an ExtraDataBlock to change resolution behavior.



## ExtraData: DarwinDataBlock

If the `.lnk` targets an application managed by Microsoft Installer (MSI), this block contains the relevant MSI information. This information defines the instructions for installing / uninstalling the application. The DarwinDataBlock is 788 bytes in size.

```
0x000  4    BlockSize        = 0x314
0x004  4    BlockSignature   = 0xA0000006
0x008  260  SpecialFolderID  = ASCII Darwin application ID
0x268  520  Offset           = Unicode Darwin application ID
```

## ExtraData: TrackerDataBlock

The TrackerDataBlock contains Distributed Link Tracking (DLT) properties.

The TrackerDataBlock is 96 bytes in size.

```
0x000  4   BlockSize              = 0x00000060
0x004  4   BlockSignature         = 0xa0000003
0x008  4   DLT Data Size          = 88
0x012  4   DLT Version            = 0
0x016  16  Machine ID             = String
0x032  16  Droid volume ID        = GUID (NTFS object ID)
0x048  16  Droid file ID          = GUID (NTFS object ID)
0x064  16  Birth droid volume ID  = GUID (NTFS object ID)
0x080  16  Birth droid file ID    = GUID (NTFS object ID)
```

Droid in this context refers to CDomainRelativeObjId.

The Droid volume ID can be found in the NTFS $OBJECT_ID attribute of the Volume file system metadata file. The LSB in the Droid volume ID contains the cross volume move flag. This flag is set if a file is moved across volumes.

The Droid file ID can be found in the NTFS $OBJECT_ID attribute of the corresponding file.


## Resolution

- - Virtual objects (Control Panel, Recycle Bin, This PC)
  - Shell extensions and CLSID-backed items
  - Namespace-only items with no fielsystem path
- `_ResolveKnownFolder` – Link target is a Known Folder (`KNOWNFOLDERID`)
  - Desktop, Documents, Downloads
- `_ResolveNetworkTargetToLocalMachine` – Link target is a UNC path
  - Offline files, DFS, cached network shares
- `_ResolvePackagedAppShortcut` – Link target is AppX / `AppUserModelID`
- `_ResolveRemovable` – Link target was on removable media
  - USB, external disk, optical
  - device has been reinserted with a different drive letter



Resolution doesn’t always happen. It only happens when code requests a resolved target identity.

- “Execute this link”
- “Get the real PIDL of this link”
- “Get the executable path”

Those requests force a call to `Resolve`. Simply loading or parsing a link will not make such requests.

Example A:

```
Explorer enumerates .lnk files
. calls Load
. reads icon location
. does not call Resolve
```

result: Link is never resolved, no filesystem/network/COM activation.

Example B:

```
User double clicks a .lnk file
. Explorer calls CShellLink::ResolveAndInvoke
	. CShellLink::Resolve
		. ResolveLinkInfo / ResolveIDList / etc.
```

result: Resolution occurs, target is validated / repaired, invocation may follow.

Conclusion:

- Load always happens.
- Resolution only happens if explicitly requested by the caller (typically Explorer).
- Invocation only happens if the caller invokes an execution entry point.



### Binding

The Shell does everything through objects:

- filesystem objects: `IShellItem`
- folders: `IShellFolder`
- namespace extensions: COM objects
- AppX: activation context object
- MSI: Darwin execution context object

Without an object, verbs can’t be queried, policies can’t be checked, and actions can’t be invoked.

For this reason, the pipeline follows this flow:

```
identity (data) -> object (thing)
```

That conversion step is binding.

- resolution determined what the link refers to (what exactly is the target)
- nothing can be done until it is represented as an object

Binding is the mechanism used during and immediately after resolution.

Behavior is chosen for the resoled identity based on its specific purpose / intent:

- Show context menu – `IContextMenu`
- Execute item – `IContextMenu` or `IExecuteCommand`
- Get icon – `IExtractIcon`
- Drag item – `IDataObject`
- Enumerate children – `IShellFolder`



Binding can be used transiently as a tool during resolution. For example, `_ResolveKnownFolder` binds the known-folder PIDL via `SHCreateItemFromIDList` to consult namespace logic, but releases the object afterward and stores only a PIDL back into the `CShellLink`. In this sense, known folders resolve to PIDL identities rather than persisting as bound “known folder” objects.



#### Prerequisite: COM apartments

COM apartments are used throughout the binding process. COM apartments exist to control which threads are allowed to call an object and how those calls are serialized. COM objects that are not thread-safe, such as most `IShellFolder` implementations, must be bound to a specific apartment (usually STA) so that COM can enforce serialized access and prevent concurrent reentrant calls. During binding, Shell determines the current apartment context, associates that apartment context a newly created object for that specific apartment, and ensures that any cross-apartment calls are marshaled.

- STA: COM guarantees only only thread at a time can use the object
- MTA: COM allows concurrent usage of the object
- NA or MainSTA : special shell rules

Example `SHCreateItemFromIDList` called during resolution to perform a binding operation:

```c++
// OBJECT CREATION (identity defined by serialized data inside the PIDL)
v6 = (CMarshalByValue *)operator new(0xD8u, ...);
CMarshalByValue::CMarshalByValue(v6);
*(_QWORD *)v7 = &CShellItem::vftable{for CMarshalByValue};
*((_QWORD *)v7 + 1) = &CShellItem::vftable{for IShellItem2};
...

// Shell checks whether apartment enforcement should be applied in this process
// (Explorer is special; many shell objects are STA-only)
_ShouldCheckApartments'::s_tbEnforceForProcess
GetModuleFileNameW(...)
FindStringOrdinal(... "\\EXPLORER.EXE") // are we Explorer?

// Query the current thread's COM apartment type
// STA / MTA / NA / MainSTA
pAptType = APTTYPE_STA;
pAptQualifier = APTTYPEQUALIFIER_NONE;
ApartmentType = CoGetApartmentType(&pAptType, &pAptQualifier);

// If STA or MainSTA:
//   Bind the object to this thread's apartment
//   COM will serialize calls and marshal cross-apartment access
*((_DWORD *)v7 + 30) = GetCurrentThreadId();

// If MTA:
//   Object is free-threaded, no single-thread affinity
//   Concurrent calls are allowed

// Obtain an initialization interface on the newly created object
// (used to attach the identity)
object->QueryInterface(IID_IPersistIDList, &initIface);

// Initialize the object with the resolved PIDL identity
// This binds the abstract PIDL identity to the concrete CShellItem object
initIface->Initialize(pidl);

// Release the initialization interface
initIface->Release();

// Expose the requested interface to the caller
// (ex. IShellItem / IShellItem2)
object->QueryInterface(riid, ppv);

// Release temporary references
object->Release();
```

Result:

- A bound, live `CShellItem` COM object
  - Identity (PIDL) attached
  - Apartment ownership enforced
  - Safe to invoke/query

With this threading model in mind, we can now analyze how binding behaves when crossing apartment boundaries when the time comes.



---



## Invocation

Invocation performs the action on the resolved object (execute, open, activate, etc.).

Binding precedes all of this because `_InvokeDirect` requires an object with a bound interface in order to invoke anything.

Invocation is not an automatic phase: it occurs only when the caller invokes an execution API (ex. `ResolveAndInvoke`, `ShellExecute`), which internally resolves the target and transfers control over to an execution handler.

```
CShellLink::ResolveAndInvoke
. CShellLink::_Resolve
	. ResolveLinkInfo
	. ResolveIDList
	. ResolveKnownFolder
	. etc.
. CShellLink::_EnsureCMTarget 	<-- Bind IContextMenu
. CShellLink::_InvokeDirect	 		<-- Invocation setup
	. IContextMenu::InvokeCommand <-- Give to handler to execute (Enter state 5)
```

Line from `_EnsureCMTarget`:

```
CShellLink::_GetUIObject(this, 0,
&GUID_000214e4_0000_0000_c000_000000000046 /*ContextMenu GUID*/,
(void **)this + 32);
```

Right-clicking a shortcut does not invoke code, rather, it invokes object-specific verbs exposed by the target. The target must first be materialized as a COM object that can receive `InvokeCommand`. The purpose of `_EnsureCMTarget` is to make sure there is a bound shell object. It queries `IContextMenu` and stores it in `this->pContextMenu`.

Line from `_InvokeDirect`:

```c
(*(__int64 (__fastcall **)(_QWORD, struct _CMINVOKECOMMANDINFOEX *))(**((_QWORD **)this + 32) + 32LL))(
              *((_QWORD *)this + 32),
              a2);
```

- access `vtable[4]` in some COM interface
- previous usage of `_EnsureCMTarget` tells me this interface is `IContextMenu`
- two arguments are given:
  - `this->pContextMenu` (at offset `32 * sizeof(QWORD)` in `CShellLink`)
  - `CMINVOKECOMMANDINFOEX* a2`

That signature perfectly matches: `this->pContextMenu->InvokeCommand(a2)`.

https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nn-shobjidl_core-icontextmenu

Now control has been transferred to a specific handler that will check policy and execute the target.



# Fuzzing

This is a structure-aware, state-aware, mutation-based fuzzer for LNK files that integrates with AFL++ as a custom mutator library. AFL++ handles seed scheduling, energy assignment, coverage tracking, corpus management, and forkserver execution. My custom mutator design shall handle LNK deserialization, structure-aware mutation, and mutation operator scheduling.

![Anatomy of a modern fuzzer](image.png)

## Energy

Energy is the number of test cases generated from a single seed before the fuzzer moves to the next seed. If a seed receives energy of 500, the custom mutator's `afl_custom_fuzz` function will be called 500x with that seed's buffer before AFL++ advances the queue.



## Coverage-guided Greybox Fuzzing as a Markov Chain

AFL models fuzzing as a Markov chain where each state is a code path in the target program. The transition probability $p(i→j)$ represents the probability that mutating a seed exercising path $i$ produces an input that exercises path $j$.

The distribution of this chain is heavily skewed: ~30% of paths are reached by only a single generated input, while ~10% of paths are reached by 1k-100k inputs. This means most fuzzing time is wasted reexercising the same few high frequency paths; typically paths that reject malformed input early.



## Dual Scheduler Architecture

This fuzzer operates two independent scheduling layers.



### Layer1 – AFL++ Seed Scheduler

AFL++ will be responsible for:

- selecting which seed from the corpus to fuzz next
- assigning energy ($n$ mutations to generate from that seed) – AKA the power schedule
- tracking edge coverage via SHM bitmap
- growing the corpus when new coverage is found
- prioritizing seeds (favoring small size, fast execution, rare paths / edges not covered by other seeds)
- managing the forkserver for execution of the target

The custom mutator doesn't interfere with any of these decisions. AFL++ calls my mutator's `afl_custom_fuzz` exported function, passing it the current seed's raw bytes, and expects mutated bytes in return. The number of times it calls that function (the energy) is entirely AFL++'s decision, based on its prioritization algorithm.



#### Energy assignment (power scheduler)

Standard AFL assigns energy to its seed mutation operations based on fixed performance score derived from execution speed, input size, and mutation depth. The score is the same every time a seed is selected, which is inefficient because it gives the same energy to seeds that reach rare paths (where new coverage is likely but requires more attempts) as it does for seeds that reach high frequency paths (where new coverage has already been exhausted).



AFLFast builds upon the original AFL constant power schedule design to create an exponential schedule. Theorem: fuzzing is far more efficient if energy is inversely proportional to how frequently a seed's path is exercised (rare paths get more energy) and energy increases monotonically every time that seed is chosen.

In practice, this means:

- Seeds that reach rare paths are given more energy. Rare paths have low probabilities of state transitions into new new paths, so more attempts are needed to statistically trigger such a transition obviously.
- Energy increases on each revisit. If 100 mutations didn't discover any new state, it is evident that the transitions exist but are improbable; 200 mutations on the next visit have better odds.
- A cap must be placed on the energy value itself so it has a reasonable maximum. Required to prevent a single seed from taking up all the resources during fuzzing. Without a cap, a seed for an extremely rare path would get exponentially increasing energy forever (100,200,400,800,1600,...), consuming millions of execs while other seeds in the queue, which are easier to discover, go unfound.

AFLFast tracks two values per seed: $s(i)$ for how many times the seed has been chosen from the queue, and $f(i)$ for how many total generated inputs exercised the same path as seed $i$. The exponential schedule computes energy as $a(i)\space\times\space 2^s(i)\space\div f(i)$, capped at a maximum. $a(i)$ is AFL's base performance score from execution speed and input size.



Seed selection and energy assignment toward seeds interlink with each other. Seed selection determines which seed to fuzz according to its algorithmic vetting. Energy dispersion (the power schedule) determines how hard to fuzz that seed once selected. Such coalescence between these two produces a seed selection mechanism that avoids wasting energy on redundant seeds entirely, and the power schedule ensures promising seeds receive enough energy to find something.

AFL++ implements all of this. My custom mutator does not need to replicate it.



### Layer2 – Mutation Operator Scheduler (custom)

My custom mutator implements its own internal scheduler that decides which out of the hundreds of structure-aware mutation operators to apply each time `afl_custom_fuzz` is called. This scheduler operates after the seed's raw bytes have been deserialized into an `LNKGeneratorState` structure.

The structure-aware scheduler logic designed here must:

- select which mutation operator to apply
- respect structural preconditions (ex. no PIDL mutation if the seed has no IDList)
- learn which operators are productive over time via coverage feedback output from AFL++
- adapt as operator effectiveness changes throughout the fuzzing lifecycle

Since I've modeled 100+ structure-aware mutation operators across 14 different groups, each operator drastically differs in applicability, effectiveness, and granularity. A strict check is done before the scheduler uses an operator to ensure that each operator passes the required preconditions. Probability matching is done to choose among the operators that passed the filter. 



#### Mutation operator scheduler

Each operator maintains a $Beta(\alpha, \beta)$ posterior distribution:

- $\alpha = 1$ and $\beta = 1$ initially (assumes nothing about success rates 0-100).
- when the mutation operator is applied and the resulting mutated input discovers new coverage, $\alpha$ is incremented.
- when it does not, $\beta$ is incremented.

To select an operator: sample a random value from each valid operator's $Beta(\alpha, \beta)$ distribution, then pick the operator whose sample is highest.

Probability matching is expected to be quite slow, so the scheduler can be divised into two levels to improve convergence:

1. probability matching over operator GROUPS.
2. within the chosen group, select a specific operator using a probability matching algorithm.

This ensures all LNK sections are explored early.

> If after running the fuzzer I see evidence that it's converging too slowly or getting stuck, I plan on swapping the scheduler for groups to MOPT's PSO approach (while still keeping Thompson Sampling at the operator level).



#### RE: Mutation-worthy sections

Core deserialization procedure `CShellLink::LoadFromStream`:

```c
// HeaderSize check
if ( HeaderSize != 76 )
    return err; // HeaderSize mutation = early rejection.

if ( LinkCLSID != CLSID_ShellLink )
    return err; // LinkCLSID mutation = early rejection.

...
    
/**
 * LinkFlags
 */
// IsUnicode flows directly into string parsing. No independent validation. Must be mutated.
Stream_ReadStringCoAlloc(a2, flags & 0x80, 260, this + 48); // IsUnicode

// No validation whatsoever. Flags are read as branch conditions without any masking/sanitization.
// Must be mutated.
if ( (*(_BYTE *)(this + 60) & 1) == 0          // HasLinkTargetIDList
if ( (*(_BYTE *)(this + 60) & 2) != 0          // HasLinkInfo
if ( (v10 & 4) != 0                            // HasName
if ( (v11 & 8) == 0                            // HasRelativePath
if ( (v12 & 0x10) == 0                         // HasWorkingDir
if ( (v13 & 0x20) == 0                         // HasArguments
if ( (v14 & 0x40) == 0                         // HasIconLocation
if ( (*(_DWORD *)(this + 60) & 0x100) != 0     // ForceNoLinkInfo
if ( (*(_DWORD *)(this + 60) & 0x1000) != 0    // HasDarwinID
if ( (*(_DWORD *)(this + 60) & 0x2000000) != 0 // PreferEnvironmentPath
if ( (*(_DWORD *)(this + 60) & 0x8000000) != 0 // KeepLocalIDListForUNC

...
    
/**
 * FileAttributes
 */
// FileAttributes are passed directly to SHSimpleIDListFromFindDataAndFlags
// without validation. Any mutation will flow into that function. Must be mutated.
v23 = *((_DWORD *)this + 121);
v32 = v23;
SHSimpleIDListFromFindDataAndFlags(v22, &v32, v24, &v26);

...

/**
 * LinkInfo
 */
// ForceNoLinkInfo 0x100: parser reads and deserializes LinkInfo entirely,
// then frees it if this flag is set.
// Mutation here would consist of setting HasLinkInfo + ForceNoLinkInfo simultaneously.
// It is shown that input will still reach the full LinkInfo deserialization codepath before freeing. // The parse happens before the discard, so any bug in LinkInfo_LoadFromStream is reachable.
if ( (*(_BYTE *)(this + 60) & 2) != 0 )        // HasLinkInfo: parse it
    LinkInfo_LoadFromStream(a2, this + 47, v9);
if ( (*(_DWORD *)(this + 60) & 0x100) != 0 )   // ForceNoLinkInfo: free it
    CShellLink::_FreeLinkInfo(this);

...

/**
 * ExtraData
 */
// Blocks are passed to SHReadDataBlockList, which handles all the block size/signature parsing.
// TrackerDataBlock specifically handled. Tracker loading allows failure.
StringCoAlloc = CTracker::Load(*(this + 56), (unsigned __int8 *)(v19 + 8), *(_DWORD *)v19 - 8);
if ( StringCoAlloc < 0 ) { 		     // if tracker parsing fails
    CTracker::InitNew(*(this + 56)); // reset to default
    StringCoAlloc = 0;
    ...								 // continue without error
```



PIDL deserialization `CShellLink::_LoadIDList`:

```c
// currently loading an LNK file, if target inside it points to yet
// another LNK, reject it before it causes recursion
if((unsigned int)CShellLink::_IsTargetAnotherLink((CShellLink*)this))
  *((_DWORD *)this + 120) &= ~1u; // clear HasLinkTargetIDList
  Pidl_Set(v2, 0);                // null the PIDL
  *((_DWORD *)this + 66) = 1;     // mark as dirty
	// CONTINUE PARSING REST OF LNK SECTIONS

// Network PIDLs take a different codepath:
//  SHCreateItemFromIDList -> SHParseDisplayName
// re-parse display name from scratch
if ( IsIDListInNameSpace(*v2, &CLSID_NetworkPlaces) ) {
    SHCreateItemFromIDList(*v2, &GUID_..., &ppv);
    // extract display name from shell item
    ppv->GetDisplayName(SIGDN_DESKTOPABSOLUTEPARSING, &pszName);
    // re-parse the display name string back into a PIDL
    SHParseDisplayName(pszName, pbc, &ppidl, 0, 0);
    // replace original PIDL with re-parsed one
    Pidl_Set(v2, ppidl);
}
```

The `_IsTargetAnotherLink` check is done because if the PIDL inside this LNK points to another LNK file, and Explorer resolves it, the second LNK will be loaded and parsed too. If the second LNK points to a third LNK, that gets parsed too. An attacker would therefore be able to create a chain of LNK files that point to eachother – causing infinite recursion that crashes Explorer or overflows the stack. 

After rejection (`_IsTargetAnotherLink 0`), the parser nulls the PIDL but continues parsing the remaining LNK sections.

In `CShellLink::_Resolve` later, when the PIDL is null, the following occurs:

```c 
v9 = CShellLink::_ResolveIDList( // receives null bc of earlier Pidl_Set(v2, 0)
    (CShellLink*)a1, a2, *(const struct _ITEMIDLIST_ABSOLUTE**)(a1 + 376), v4
); // will ret E_FAIL (-2147467259)
Path = v9;
if(
   v9 >= 0 				// (success): no, -2147467259 is negative
   || v9 == -2147023673	// no
   || v9 == -2147023436	// no
   || v9 == -2147024891	// no
   || v9 == -2147024883	// no
)
```

None match `-2147467259`, so the `if` is FALSE and execution falls through to:

```c
v12 = *(const ITEMIDLIST**)(a1 + 376); // read PIDL pointer again
if(!v12){ // PIDL is null (was nulled in _LoadIDList after _IsTargetAnotherLink)
    Path = 0; // report SUCCESS despite having no target
    goto LABEL_100;
}

...

LABEL_100:
  // caller (ResolveAndInvoke) will see Path = 0 (S_OK)
  // and proceed to invocation with a null PIDL @ (this + 376)
  if(!(unsigned int)CShellLink::IsDirty((CShellLink*)(a1 + 24)) && (v4 & 4) != 0){
    if((unsigned int)CShellLink::_IsTargetAnotherLink((CShellLink*)a1))
        CShellLink::_SetPidl((CShellLink*)a1, 0); // null the PIDL again
    CShellLink::Save((CShellLink*)(a1 + 40), 0, 1); // save the link with null PIDL
  }
  return (unsigned int)Path; // ret 0 (SUCCESS) to caller with null PIDL xd
```

The caller (`ResolveAndInvoke`) sees a successful resolution but there’s not a target. If invocation proceeds without checking the PIDL pointer, this is a null pointer dereference or logic bug. The logic bug where code proceeds without a target may skip MOTW checks.

The `MUTATE_PIDL_INJECT_CLSID` mutation operator is leveraged here to craft a PIDL that triggers `_IsTargetAnotherLink` rejection, gets nulled, and ultimately causes resolution to report false success to downstream invocation code. Also reachable via `MUTATE_PIDL_MISSING_TERMINAL` or any mutation that causes `_IsTargetAnotherLink` to return 0.



> TODO: trace `ResolveAndInvoke`, see what happens when it receives `Path=0` with a null PIDL at `this + 376`.



Separately, `_IsTargetAnotherLink` can be bypassed entirely. The check only tests whether the PIDL resolves to a `.lnk` file. A CLSID item (`0x1F`) with a GUID pointing to a COM handler (Control Panel, Shell extensions, etc.) is not a `.lnk` file, so it passes the check and reaches namespace resolution.

**worked** – I crafted a `.lnk` with a single PIDL item:

```
Item: 		0x1F
Sort order: 0x50
GUID:		{21EC2020-3AEA-1069-A2DD-08002B30309D} (Control Panel)
```

Explorer displayed the Control Panel icon without any click or interaction. This proves the CLSID reached `_GetFolderForItem`, the COM factory loaded the Control Panel handler DLL, and its `IShellFolder` implementation executed in Explorer's process.

This is the same dispatch path exploited by Stuxnet and CVE-2017-8464. Microsoft patched specific CLSIDs (CPL whitelist kill bits) but the underlying mechanism of an attacker-controlled CLSID in a Shell Item triggering a COM handler to be loaded upon folder view is still functional.

`MUTATE_PIDL_INJECT_CLSID` automates this by injecting `0x1F` items with sort order byte and random GUIDs. The sort order byte at offset 3 is required; without it, the GUID is misaligned and the Shell can't match it to a registered handler. Each of the hundreds of registered COM objects on Windows becomes a fuzz target. A crash in any handler's `BindToObject` or `ParseDisplayName` when processing malformed PIDL payload data is a potential CVE.

Root folder `SHITEMID` binary layout (20 bytes total):
```
Offset  Size  Field
0x00    2     cb = 20         (size of this SHITEMID)
0x02    1     abID[0] = 0x1F  (class type)
0x03    1     abID[1]         (sort order, ex. 0x50)
0x04    16    abID[2..17]     (GUID, 16 bytes)
```
Sort order values for root folder items mapped to specific namespaces:
```
0x00 — Internet Explorer
0x42 — Libraries
0x44 — Users
0x48 — My Documents
0x50 — My Computer
0x58 — My Network Places
0x60 — Recycle Bin
0x68 — Internet Explorer
0x70 — Unknown
0x80 — My Games
```

PIDL deserialization `ILLoadFromStreamEx`:

```c
// IDList total size read as uint16_t (max 0xFFFF).
cbAlloc = stream_read_u16(pstm);

// Allocates buffer of that size, reads that many bytes from stream.
v6 = ILCreate(cbAlloc);
stream_read(pstm, v6, cbAlloc);

// IDListContainerIsConsistent is the PIDL validation.
// Checks if the PIDL items within the allocated buffer are consistent with the declared size.
// PIDL mutation operators live or die based on what this function validates.
if ( IDListContainerIsConsistent(v6, cbAlloc) )
    *pidl = v6; // accepted
else
    CoTaskMemFree(v6); // rejected, no leak
```

PIDL validation `IDListContainerIsConsistent`:

```c
BOOL __stdcall IDListContainerIsConsistent(LPCITEMIDLIST pidl, UINT cbAlloc) {
  BOOL v2; // r8d
  UINT v3; // r9d
  UINT cb; // r10d
  v2 = 0;
  v3 = 2;
  // Walks each SHITEMID in the list, checking only:
  //  . cb >= 2
  //  . cb fits within remaining buffer
  //  . list ends with terminal (cb == 0)
  if ( cbAlloc >= 2 ) {
    do {
      if ( pidl->mkid.cb < 2u )
        break;
      cb = pidl->mkid.cb;
      if ( cb > cbAlloc - v3 )
        break;
      v3 += cb;
      pidl = (LPCITEMIDLIST)((char *)pidl + pidl->mkid.cb);
    }
    while ( v3 <= cbAlloc );
    if ( v3 <= cbAlloc && !pidl->mkid.cb )
      return 1;
  }
  return v2;
}
```

Does not validate:

- `class_type` / `abID[0]` (any value is accepted)
- payload contents within items
- item count
- parent/child type relationships
- exact terminal size (just checks `cb==0` at current pos)



LinkInfo deserialization `LinkInfo_LoadFromStream`:

```c
if ( LinkInfoSize > a3 ) // reject (too big for stream)
    return err;
if ( LinkInfoSize >= 4 ) // accept (big enough to hold at least the size field)
    return err;

// if(LinkInfoSize < 4)
//  skip allocation entirely

LocalAlloc(LinkInfoSize); // MUTATE_SIZE_BOUNDARY good

// ...

linkinfo.dll!IsValidLinkInfo(); // validation where VolumeID offsets and whatnot get checked
```

So there are multiple gates that check sizes at different thresholds:
- `< 4` – allocation skipped entirely
- `>= 4` but `< 0x1C` – allocated but fails `IsValidLinkInfo`
- `>= 0x1C` – passes header check, reaches deeper validation
- `VolumeIDSize < 0x10` – fails VolumeID check
- `VolumeIDSize > remaining` – fails bounds check
Each boundary value hits a different code path. `MUTATE_SIZE_BOUNDARY` can be used here.

LinkInfo validation `linkinfo.dll!IsValidLinkInfo`:

```c
// LinkInfo header checks
if (LinkInfoSize >= 0x1C) // minimum 28 bytes
    continue; else return 0;

if (LinkInfoHeaderSize <= LinkInfoSize)
    return err;

if (LinkInfoHeaderSize == 28 || LinkInfoHeaderSize >= 0x24) // original format and unicode format
    continue; else return 0;

// if VolumeIDAndLocalBasePath (bit 0) is set
if ( (LinkInfo[2] & 1) == 0 )
    goto LABEL_65; // if not set, skip to CommonNetworkRelativeLink check

// VolumeIDOffset, LocalBasePathOffset, CommonPathSuffixOffset must all be < LinkInfoSize
// VolumeIDOffset must be 4-byte aligned
v7 = LinkInfo[3];  // VolumeIDOffset
v8 = LinkInfo[4];  // LocalBasePathOffset
v9 = LinkInfo[6];  // CommonPathSuffixOffset
if ( v7 >= LinkInfoSize || v8 >= LinkInfoSize || v9 >= LinkInfoSize || (v7 & 3) != 0 )
    return 0;

// LocalBasePath string must be null-terminated within bounds
if ( !find_null((char*)LinkInfo + LocalBasePathOffset, LinkInfoSize - LocalBasePathOffset) )
    return 0;

// CommonPathSuffix string must be null-terminated within bounds
if ( !find_null((char*)LinkInfo + CommonPathSuffixOffset, LinkInfoSize - CommonPathSuffixOffset) )
    return 0;

// VolumeID internal validation
VolumeID = (uint32_t*)((char*)LinkInfo + VolumeIDOffset);
VolumeIDSize = VolumeID[0];
if ( VolumeIDSize > remaining || VolumeIDSize < 0x10 )
    return 0;

VolumeLabelOffset = VolumeID[3];
if ( VolumeLabelOffset >= VolumeIDSize )
    return 0;

// Volume label string must be null-terminated within VolumeID bounds
if ( !find_null((char*)VolumeID + VolumeLabelOffset, VolumeIDSize - VolumeLabelOffset) )
    return 0;

// If VolumeLabelOffset == 16: unicode label path
if ( VolumeLabelOffset == 16 ) {
    if ( VolumeIDSize < 0x14 )
        return 0;
    VolumeLabelOffsetUnicode = VolumeID[4];
    if ( VolumeLabelOffsetUnicode >= VolumeIDSize || (VolumeLabelOffsetUnicode & 1) != 0 )
        return 0;
    // unicode label string must pass StringCbLengthW
}

LABEL_65:
// if CommonNetworkRelativeLinkAndPathSuffix (bit 1) is set
if ( (LinkInfo[2] & 2) == 0 )
    goto done_valid;

CNRLOffset = LinkInfo[5];  // CommonNetworkRelativeLinkOffset
if ( CNRLOffset >= LinkInfoSize || LinkInfo[6] >= LinkInfoSize || (CNRLOffset & 3) != 0 )
    return 0;

// Delegates CNRL internal validation to IsValidCNRLink
if ( !IsValidCNRLink((char*)LinkInfo + CNRLOffset, LinkInfoSize - CNRLOffset) )
    return 0;

// If old format header: CommonPathSuffix must be null-terminated
if ( LinkInfo[1] == 28 ) {
    if ( !find_null((char*)LinkInfo + LinkInfo[6], LinkInfoSize - LinkInfo[6]) )
        return 0;
}

// If extended header (>= 0x24) and VolumeIDAndLocalBasePath set:
if ( LinkInfo[1] >= 0x24 && (LinkInfo[2] & 1) ) {
    LocalBasePathOffsetUnicode = LinkInfo[7];
    CommonPathSuffixOffsetUnicode = LinkInfo[8];
    // both must be < LinkInfoSize, both must be 2-byte aligned
    // both unicode strings must pass StringCbLengthW
}

// If extended header and CommonNetworkRelativeLink set:
if ( LinkInfo[1] >= 0x24 && (LinkInfo[2] & 2) ) {
    CommonPathSuffixOffsetUnicode = LinkInfo[8];
    // must be < LinkInfoSize, 2-byte aligned, string must pass StringCbLengthW
}

return 1;
```

Does not validate:

- `DriveType` range (any value is accepted)
- `DriveSerialNumber` (no check whatsoever)
- String contents beyond null-term
- Offset overlap (two offsets pointing to same memory)
- Offset order
- Reserved bits in `LinkInfoFlags` (only checks bit0 and bit1)

Alignment constraints:

- `VolumeIDOffset` must be 4-byte aligned
- `CommonNetworkRelativeLinkOffset` must be 4-byte aligned
- Unicode offsets must be 2-byte aligned

CommonNetworkRelativeLink deserialization `linkinfo.dll!IsValidCNRLink`:
```c
IsValidCNRLink(const struct _cnrlink* cnrl, unsigned int remaining){
    // 0x3E7B: remaining must be >= 0x14
    if (remaining < 0x14) return 0;

    // 0x3E84: cnrl->Size must be <= remaining
    if (cnrl->Size > remaining) return 0;

    // 0x3E8E: cnrl->Size must be >= 0x14
    if (cnrl->Size < 0x14) return 0;

    // 0x3E97: Flags bits 2-31 must be zero (only bit 0 and 1 allowed)
    if (cnrl->Flags & 0xFFFFFFFC) return 0;

    // 0x3EA4: NetNameOffset must be < Size
    if (cnrl->NetNameOffset >= cnrl->Size) return 0;

    // 0x3EAF-0x3EBB: NetName string must pass StringCbLengthA
    StringCbLengthA(cnrl + NetNameOffset, Size - NetNameOffset);

    // 0x3EBF: if ValidDevice (bit 0) set
    if (cnrl->Flags & 0x01) {
        // 0x3EC6: DeviceNameOffset must be < Size
        if (cnrl->DeviceNameOffset >= cnrl->Size) return 0;
        // DeviceName string must pass StringCbLengthA
        StringCbLengthA(cnrl + DeviceNameOffset, Size - DeviceNameOffset);
    }

    // 0x3EE1: if NetNameOffset != 0x14, unicode fields exist
    if (cnrl->NetNameOffset != 0x14) {
        // 0x3EEB: Size must be >= 0x1C for unicode fields
        if (cnrl->Size < 0x1C) return 0;

        // 0x3EF0: NetNameOffsetUnicode must be < Size
        if (cnrl->NetNameOffsetUnicode >= cnrl->Size) return 0;
        // must be 2-byte aligned
        if (cnrl->NetNameOffsetUnicode & 1) return 0;
        // unicode NetName must pass StringCbLengthW
        StringCbLengthW(cnrl + NetNameOffsetUnicode, Size - NetNameOffsetUnicode);

        // 0x3F0D: if ValidDevice (bit 0) set
        if (cnrl->Flags & 0x01) {
            // 0x3F14: DeviceNameOffsetUnicode must be < Size
            if (cnrl->DeviceNameOffsetUnicode >= cnrl->Size) return 0;
            // must be 2-byte aligned
            if (cnrl->DeviceNameOffsetUnicode & 1) return 0;
            // unicode DeviceName must pass StringCbLengthW
            StringCbLengthW(cnrl + DeviceNameOffsetUnicode, Size - DeviceNameOffsetUnicode);
        }
    }

    return 1;
}
```

ExtraData deserialization `SHReadDataBlockList`:

```c
// Block size > 0xFFFF: seeks backward in stream, silently terminates loop.
// Block size < 8: terminates loop.
// Valid range [8, 0xFFFF] -> IsValidDataBlock -> SHAddDataBlock.
// IsValidDataBlock determines accepted signatures.
```

StringData deserialization:

```c
// IsUnicode (bit 7) selects between W and A read paths. No validation.
// Arguments field has no max length cap (a3 = 0). Overlong mutations go here.
// Other fields capped at 260.
```


## Final custom fuzzer architecture
1. AFL++ gives raw bytes (seed)                             → `mutator.c` (`afl_custom_fuzz` entry point)
2. deserialize the seed bytes                               → `deserialize.c`
3. mutate the struct with mutation operators                → `mutate.c` / `mutate.h`
4. serialize the mutated struct back to bytes               → `serialize.c`
5. AFL++ interface feeds those bytes to the harness         → `mutator.c` (return to AFL++)
6. harness program is executed by AFL++ with mutated bytes  → `harness.c`

### (`mutate.c`) group/op scheduler
> Beta: $\alpha$ is the number of successes (found new coverage) plus one. $\beta$ is the number of failures (no new coverage) plus one. You start at 1 (the prior) so the success/fail rate is equal initally.

Each mutation operator group is given an alpha/beta which decides the section of the LNK format to target (ex. PIDL). The mutation operator alpha/beta decides which specific mutation within that section to apply. There are two levels because picking the right section first narrows the search fast, whereas a single-layered sampling trial across 100+ operators would take a long time to learn which areas of the foramt are productive.

Since you don't know the success rate of an operator producing new coverage, a Beta is used to model the probability of its success based on feedback. Early on with $\alpha=1$ and $\beta=1$, the distribution is flat — could be anything from 0% to 100%. After 1000 runs with 50 successes, the distribution narrows to ~5%. At this point, the scheduler can be confident that this operator produces coverage ~5% of the time, and therefore can prioritize it over operators in the same group whose distributions center near zero (many runs, few successes).

Beta distribution's mean:
```math
E[x_i] = \frac{\alpha_i}{\alpha_i + \beta_i}
```
This is the estimated probability of this operator/group producing new coverage. An operator with $\alpha=51$, $\beta=950$ has an estimated success rate of 51/1001 $\approx$ 5%. One with $\alpha=2$, $\beta=998$ has 2/1000 $\approx$ 0.2%. The sampler naturally favors the first.

Important detail:
The Beta distribution is a probability distribution — sampling from it doesn't give you the mean every time. It gives you a random value around the mean, with spread determined by how much data you have.
An operator with $\alpha=51$ $\beta=950$ has a mean of ~5%. But one sample might give you 4.2%, the next 5.8%, the next 3.9%. It changes around. The spread depends on how much data you have; more trials means tighter clustering around the true mean, less trials means wider variance.
An operator with $\alpha=2$ $\beta=3$ has a mean of 40%. But with so little data, its samples are wildly spread — one sample might give you 15%, the next 72%, the next 38%.
That second operator might occasionally sample higher than the first, even though its true success rate might actually be lower. So it gets picked and tried again, giving you more data about it. This randomness in sampling is what makes Thompson Sampling explore uncertain operators instead of always picking the current best. If you were to only pick the operator with the highest mean every time, you'd never try anything new after the first few hundred rounds.

#### Selection (Thompson Sampling)
For each operator candidate $i$, draw a random sample:
```math
x_i \sim \text{Beta}(\alpha_i, \beta_i)
```
Select: $chosen = argmax(x_i)$

Mutation operators with higher $\alpha$ relative to $\beta$ produce higher samples more often, so they get selected more. But because it's a random sample rather than just taking the mean, operators with low data (low $\alpha + \beta$) vary drastically; they occasionally produce high samples, which means they still get explored. This is how Thompson Sampling balances exploitation (use what works) with exploration (try uncertain things).

Two-layer selection:
```math
\text{Level 1:} \quad g^* = \arg\max_g \, x_g \quad \text{where} \quad x_g \sim \text{Beta}(\alpha_g, \beta_g)
```

```math
\text{Level 2:} \quad i^* = \arg\max_{i \in g^*} \, x_i \quad \text{where} \quad x_i \sim \text{Beta}(\alpha_i, \beta_i)
```
- $*$ means "chosen"
- $g*$ is the chosen group
- $i \in g*$ means only operators belonging to that group
- $i*$ is the chosen operator