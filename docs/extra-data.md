# ExtraData blocks — security-relevant deep dives

*Field-level notes on the ExtraData blocks that carry attack surface, and the shell32 code that consumes them. Full section layout is in [lnk-format.md](lnk-format.md); the CVEs are in [attack-surface.md](attack-surface.md).*

## TrackerDataBlock

The TrackerDataBlock contains Distributed Link Tracking (DLT) properties.

MS-SHLLNK defines it as quite the constrained ExtraData block; every single field is required.

Binary layout (96 bytes, no room for variance):

```
0x00  4   BlockSize                      0x00000060 (96)
0x04  4   BlockSignature                 0xA0000003
0x08  4   Length                         0x00000058 (88)
0x0C  4   Version                        0x00000000
0x10  16  MachineID                      Variable string
0x20  16  VolumeID (Droid[0])            GUID
0x30  16  ObjectID (Droid[1])            GUID
0x40  16  BirthVolumeID (DroidBirth[0])  GUID
0x50  16  BirthObjectID (DroidBirth[1])  GUID
```

- `Length` covers the length through `DroidBirth`, inclusive.
- `Version` only version 0 defined.
- `MachineID` is a 16-byte field containing the NetBIOS hostname of the machine where the link target last resided. The name is a NULL-terminated ANSI string, padded with null bytes if the string is shorter than 15 characters.
- `VolumeID`/`Droid[0]` is which NTFS volume the file is on.
- `ObjectID`/`Droid[1]` is which file on that volume (stored in NTFS $OBJECT_ID attribute).
- `BirthVolumeID`/`DroidBirth[0]` is the original volume GUID
- `BirthObjectID`/`DroidBirth[1]` is the original NTFS object ID (never changes).

> "Droid" stands for Domain Relative Object ID (`CDomainRelativeObjID`) – a C++ class that can be used by the DLT service to determine if the file has moved

The `Length` field is unusual, it counts from itself onward, including its own 4 bytes, which is different from how ExtraData blocks typically define their length fields. An [[older spec revision](https://wikileaks.org/ciav7p1/cms/files/%5BMS-SHLLINK%5D.pdf)] defined `Length` as "This value MUST be greater than or equal to" (not an exact match), and `MachineID` as "(variable): A character string" rather than a fixed 16 bytes. The current version says "This value MUST be `0x00000058`" (exact match), and `MachineID` is "16 bytes" (fixed size). This suggests Microsoft encountered implementations that diverged. Reverse engineering of `CTracker::Load` shows that the `Length >= 0x58` check is the one that is currently being used.

Each GUID field uses [MS-DTYP 2.3.4.2][https://winprotocoldoc.z19.web.core.windows.net/MS-DTYP/%5bMS-DTYP%5d.pdf] representation.

## CTracker::Load

`CTracker::Load` is a non-exported class in shell32.dll:

```c
CShellLink::_LoadFromStream
  . SHReadDataBlockList()                   // iterates ExtraData by BlockSize
  . stores all blocks in m_pDBList
  ...
  . SHFindDataBlock(m_pDBList, 0xA0000003)  // retrieves TrackerDataBlock
  . CTracker::Load()                        // parses the 88-byte payload
```

Validation:

- `a3 >= 0x58` AND `Length >= 0x58` (not exact match, old spec `>=` behavior still in code)
- `Version == 0` (non-zero returns `ERROR_UNKNOWN_REVISION`)
- `Length` and `Version` are checked BEFORE content copy: early return, won't partially read

No validation:

- `MachineID`: raw 16-byte OWORD copy, no null/format check (CONFIRMED)
- `Droid`/`DroidBirth`: raw OWORD copies, no GUID validation (CONFIRMED)

Call ordering:

1. _InitRPC() — initializes RPC state (potential leak on later rejection)
2. check a3 >= 0x58 AND Length >= 0x58
3. check Version == 0
4. copy all 5 content fields (80 bytes total)
5. set tracking flags

When validation fails: the caller (`_LoadFromStream`) calls `CTracker::InitNew`, not `Load` itself. `CTracker::InitNew` zeroes out the TrackerDataBlock fields while preserving the header (`BlockSize`, `BlockSignature`, `Length`, `Version`). The link continues to function, it simply cannot use DLT-based resolution. This is silent degradation, but not an error.

## DLT resolution

When `CShellLink::Resolve` cannot find the target file at its stored path, it invokes the DLT client servce (`trkwks.dll`) with the TrackerDataBlock payload. The resolution involves multiple network related steps:

1. MS-DLTW resolution: DLT client opens an SMB connection to the machine identified by `MachineID` to access the named pipe `\\pipe\trkwks` (RPC interface UUID `300f3532-38cc-11d0-a3bf-00a0c9244a82`). It then sends a `LnkSvrMessage` RPC call with a SEARCH operation containing the `VolumeID` (`Droid[0]`) and `ObjectID` (`Droid[1]`).

2. Referral chain following: If the target PC returns `TRK_E_REFERAL`, the response includes a new `MachineID` and FileLocation. The client follows this chain (M0->M1->M2->...), opening new SMB connections to each machine. A crafted referal chain could maybe cause the client to contact multiple attacker-controlled PCs.

3. MS-DLTW Central Manager fallback: If step 1 fails, the client queries a DLT server on a domain controller using `DroidBirth` (FileID) for cross-machine resolution. This involves LDAP queries against the Active Director objects `linkTrackOMTEntry` and `linkTrackVolEntry`.

4. Heuristic search: If DLT fails entirely, the shell falls back to searching the same directory for files with matching creation times, and then performs recursive searches across local volumes.

The outbound SMB connection to `MachineID` includes NTLM authentication by default.
A crafted LNK file with an attacker-controlled `MachineID` could capture NTLMv2 hashes
on corporate Windows 10/11 machines where:

- TrkWks service is running (default on all desktop editions)
- LLMNR/NBNS resolves the attacker hostname (default in Active Directory environments)
- Explorer doesn't set `SLR_NOTRACK` (it doesn't by default)
- The link target is missing from its expected path (triggers DLT resolution fallback)

The peer-to-peer DLT client (TrkWks) contacts the `MachineID` host directly over SMB
without needing the deprecated server-side component (TrkSvr). The main constraint is
that DLT resolution only fires when normal path resolution fails — the target file
must be absent for the tracker to activate.

The exploitation path for this specific attack vector would have to be:

```
CShellLink::Resolve
  1 target file not found at stored path
  2 TrkWks peer-to-peer resolution
  3 SMB connection to \\MachineID\pipe\trkwks
  4 NTLM authentication sent to attacker
```

## MachineID NetBIOS enables network targeting

The 16-byte `MachineID` field stores the null-terminated NetBIOS name of the machine where the link target last resided, which is the machine that created the shortcut. Forensic analysts extract `MachineID` for this so they can track APT campeigns where samples reveal hostnames such as "user-pc", and combining MAC addresses extracted from the Droid UUIDv1 GUIDs provides a hardware fingerprint of attack infrastructure. A crafted LNK with a malicious `MachineID` triggers the DLT client to init SMB connections to the named host during link resolution. This constitutes an SSRF-esque attack vector where the victim machine contacts an attacker-specified endpoint. This attack vector would not work if TrkWks service were to be disabled or if NetBIOS name resolution fails to route to external addresses. Also, modern firewalls block outbound SMB traffic (port 445), making exploitability rare. The `MachineID` field is not validated as a legit NetBIOS name; arbitrary strings are accepted, though resolution requires the string to resolve via NetBIOS/DNS.

## Droid GUIDs

The `Droid` and `DroidBirth` fields are each a `CDomainRelativeObjId` structure – two GUIDs representing a volume ID and a file object ID.

- Droid = current FileLocation: where the file is now (VolumeID + ObjectID)
- DroidBirth = original FileID: where the file was when first tracker (BirthVolumeID + BirthObjectID)
- If Droid equals DroidBirth, the file has never moved across volumes

These GUIDs map to the NTFS `$OBJECT_ID` attribute in the `$Volume$` file system metadata file (MFT attribute type `0x40`), which stores:

```
ObjectId      (16 bytes)
BirthVolumeId (16 bytes)
BirthObjectId (16 bytes)
DomainId      (16 bytes, always zero)
```

Object IDs are created on demand via `FSCTL_CREATE_OR_GET_OBJECT_ID` and indexed in the `$ObjId` system file per volume. Object IDs are generated as UUIDv1 (time-based), encoding a 60-bit timestamp, a clock sequence, and a 48-bit node ID that is typically the MAC address of a network adapter. Bytes 10-15 of the file ObjectID GUID contain the MAC address.

The low-order bit of the first byte of the `VolumeID` GUID stores a `CrossVolumeMoveFlag` indicating whether the file has been moved across volumes. This is a single bit embedded in the GUID that dictates resolution behavior. If the parser treats `VolumeID` as opaque, it will miss this semantic.


## TODO

Content fields (MachineID, Droid, DroidBirth) are likely not validated based on
the consistent pattern observed across the LNK parser: structural fields are
checked, content fields are trusted. Not confirmed via RE of CTracker::Load.
Decompile CTracker::Load to verify.

Use LnkMeMaybe or securifybv/ShellLink to generate seed corpus with valid TrackerDataBlocks, then apply structure-aware mutations targeting: BlockSize/Length/Version fields (envelope), MachineID string content (content), Droid/DroidBirth GUID bytes (content), and cross-field consistency (ex. Droid ≠ DroidBirth to trigger cross-volume resolution paths).

If first call to Resolve initializes CTracker partially but skips DLT due to the SLR_NOTRACK flag, and the second call assumes CTracker is either fully initialized or uninitialized, there could be a state confusion bug. Do multi-call sequences with different legitimate flags that test strategy which single-call harnesses will ideally miss.

test third-party LNK parsers (AV engines, forensic tools, backup/sync software) with Length > 0x58. the older MS-SHLLINK spec (v20131025) defined Length as ">= 0x58" and MachineID as variable-length. parsers built against that spec may accept oversized Length and read past the 88-byte payload into adjacent memory. this is NOT a shell32 target — it targets software that implemented LNK parsing from the pre-2013 spec and never updated. separate harness needed per target.

decompile CTracker::Load in shell32.dll to determine field read ordering. if content fields (MachineID, Droid, DroidBirth) are read before the Length/Version checks, a malformed Length could cause OOB reads from adjacent ExtraData blocks before InitNew zeroes the fields.

---

# KnownFolderDataBlock

The KnownFolderDataBlock stores a GUID identifying a "Known Folder" – Windows' Vista-era replacement for the older CSIDL system. It contains a `KnownFolderID` GUID that identifies the folder, and an `Offset` (4-byte uint32) that specifies the location of the ItemID of the first child segment of the IDList specified by the `KnownFolderID`.

Binary layout (28 bytes):

```
0x00  4   BlockSize       0x0000001C (28)
0x04  4   BlockSignature  0xA000000B
0x08  16  KnownFolderID   GUID MS-DTYP packet repr.
0x18  4   Offset          uint32 byte offset into LinkTargetIDList
```

- `KnownFolderID`: GUID that identifies which Known Folder this shortcut targets (ex. Control Panel, Desktop, Documents).
- `Offset`: byte offset into the `LinkTargetIDList` where the resolved folder's PIDL gets inserted.

This is the smallest ExtraData block with real payload, just 20 bytes of content after the 8-byte header.

## purpose: namespace context switching

The KnownFolderDataBlock specifies the location of a known folder. This data can be used when a link target is a known folder to keep track of the folder so that the link target IDList can be translated.

When an LNK is loaded, the shell uses `KnownFolderID` to resolve the current path to the folder (which may have changed since the LNK was created), then uses `Offset` to locate a specific item within the PIDL relative to that folder. This is the namespace context switching mechanism. The `KnownFolderID` changes which folder namespace interprets the PIDL.

## resolution order (`_DecodeSpecialFolder`)

1. `SHFindDataBlock(m_pDBList, 0xA000000B)` — try KnownFolderDataBlock first
2. `_ShouldDecodeSpecialFolder(KnownFolderID)` — machine identity gate
3. `SHGetKnownFolderIDList_Internal(KnownFolderID, flags)` — resolve GUID to PIDL
4. If no KnownFolderDataBlock: fall back to `SHFindDataBlock(0xA0000005)` + `SHCloneSpecialIDList`
5. Walk `LinkTargetIDList`, clone prefix via `ILCloneCB(pidl, Offset)`
6. `TranslateAliasWithEvent()` — graft resolved PIDL into original

## _ShouldDecodeSpecialFolder

Not a simple flag check. It performs machine identity validation:

1. Creates `KnownFolderManager` COM object
2. Calls `IKnownFolderManager::GetFolder(KnownFolderID)` to get `IKnownFolder`
3. Calls `IKnownFolder::GetFolderDefinition` to get category (virtal, peruser, common)
4. Reads a machine GUID from the LNK's PropertyStore
5. Calls `SHGetMachineGUID` to get the current machine's GUID
6. Compares stored GUID vs current GUID

If same machine: allow decode (return true).

If different machine and folder is `KF_CATEGORY_PERUSER`: only allow if `_IsCurrentUserShortcutCreator` returns false.

## TranslateAliasWithEvent

Receives:

```
a2 = original PIDL (full LinkTargetIDList)
a3 = prefix PIDL (cloned up to Offset bytes via ILCloneCB)
a4 = resolved known folder PIDL
```

Walks both PIDLs counting items and total bytes. If identical (same count, same size, same `memcmp`), no translation needed. Otherwise calls `IShellFolder::CompareIDs` to perform the actual namespace translation, then `ReparseRelativeIDListInternal + ILCombine` to produce the final PIDL.

## relation to SpecialFolderDataBlock

KnownFolderDataBlock is tried in resolution before SpecialFolderDataBlock. If both are present, only KnownFolderDataBlock is used. SpecialFolderDataBlock is the fallback.

KnownFolderDataBlock and SpecialFolderDataBlock do the same thing: switch namespace context. The only difference is that they use different identifier systems:

```
SpecialFolderDataBlock (0xA0000005):
  . uses CSIDL values (legacy, integer constants like CSIDL_CONTROLS = 3)
  . pre-Vista, still works on all Windows versions
  . 16 byte payload (SpecialFolderID integer + Offset)
```

```
KnownFolderDataBlock (0xA000000B):
  . uses KNOWNFOLDERID GUIDs (post-Vista, like FOLDERID_ControlPanelFolder)
  . more extensible, supports custom folders – the old CSIDL system had a fixed list provided by Microsoft, whilst newer versions allow applications to define new ones. For instance, OneDrive uses IKnownFolderManager::RegisterFolder to register FOLDERID_SkyDrive.
  . 20 byte payload (KnownFolderID GUID + Offset)
```

Both of these blocks can trigger the same attack surface. [CVE-2017-8464][https://github.com/securifybv/ShellLink] was exploited using either block.

## CVE-2017-8464

The exploit creates an LNK file with a SpecialFolderDataBlock where the folder ID is set to the Control Panel. This is enough to bypass the [CPL whitelist][https://hackmag.com/wp-content/uploads/2025/12/16692_original-vs-patch.jpg] and trick Windows into loading an arbitrary DLL file.

The exploit works the same if KnownFolderDataBlock uses `FOLDERID_ControlPanelFolder` `{82A74AEB-AEB4-465C-A014-D097EE346D63}`:

1. LNK file has `LinkTargetIDList` pointing to a `.cpl` file on an attacker-controlled path (ex. network share).
2. KnownFolderDataBlock sets `KnownFolderID = FOLDERID_ControlPanelFolder` with `Offset` pointing at the CPL item in the PIDL.
3. Explorer renders the LNK icon, resolves the `KnownFolderID`, switches the namespace context to Control Panel.
4. Under Control Panel namespace, `CControlPanelFolder::GetUIObjectOf` treats the PIDL item as a CPL module.
5. `CControlPanelFolder` calls `LoadLibraryW` on the CPL path -> arbitrary code execution.

The bypass works because `_ShouldDecodeSpecialFolder` skips machine identity verification when the LNK's PropertyStore has no machine GUID property. Control Panel is `KF_CATEGORY_VIRTUAL`, so it falls through the per-user check. Crafting an LNK without the machine GUID property causes `_ShouldDecodeSpecialFolder` to default to true, and the namespace switch to Control Panel proceeds unchecked.

Patch: added `_IsRegisteredCPLApplet` validation.

The patch only mitigated that specific Control Panel loading path. Other namespace folders reachable via `KnownFolderID` were not similarly hardened.

## LinkFlags DisableKnownFolderTracking

LinkFlags bit 22 (0x00400000) is `DisableKnownFolderTracking`:

> "The SpecialFolderDataBlock and the KnownFolderDataBlock are ignored when loading the shell link. If this bit is set, these extra data blocks SHOULD NOT be saved when saving the shell link."

This flag disables both KnownFolderDataBlock and SpecialFolderDataBlock parsing. But like `ForceNoLinkTrack` for TrackerDataBlock, the blocks may still be physically present in the file even when the flag is set. This will test whether the flag is properly enforced and whether any code path reads the blocks despite the flag.

LinkFlags bits 0x400000 (`DisableKnownFolderTracking`) and 0x1000000 (`DisableKnownFolderAlias`) are extracted as:

```c
(LinkFlags & 0x400000 | 0x1000000) >> 10
```

and passed as `dwFlags` to `SHGetKnownFolderIDList_Internal`. They modify resolution behavior rather than blocking the block from being read.

## Security relevant KNOWNFOLDERIDs

```
Virtual/shell namespace folders (no filesystem path, create virtual PIDLs):
```

  FOLDERID_ControlPanelFolder  {82A74AEB-AEB4-465C-A014-D097EE346D63}  CVE-2017-8464 target
  FOLDERID_PrintersFolder      {76FC4E2D-D6AD-4519-A663-37BD56068185}  print subsystem
  FOLDERID_RecycleBinFolder    {B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC}  deletion/restore
  FOLDERID_NetworkFolder       {D20BEEC4-5CA8-4905-AE3B-BF251EA09B53}  network enumeration
  FOLDERID_ComputerFolder      {0AC0837C-BBF8-452A-850D-79D08E667CA7}  drive enumeration
  FOLDERID_ConnectionsFolder   {6F0CD92B-2E97-45D1-88FF-B0D186B8DEDD}  network connections

```
Writable system folders (attacker may plant files):
```

  FOLDERID_CommonStartup       {82A5EA35-D9CD-47C5-9629-E15D2F714E6E}  auto-run on login
  FOLDERID_ProgramData         {62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}  shared app data
  FOLDERID_PublicDesktop       {C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}  visible to all users

```