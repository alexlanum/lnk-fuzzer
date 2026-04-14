
# TrackerDataBlock
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

```
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
0x16  4   Offset          uint32 byte offset into LinkTargetIDList
```

This is the smallest ExtraData block with real payload, just 20 bytes of content after the 8-byte header.

## purpose: namespace context switching
The KnownFolderDataBlock specifies the location of a known folder. This data can be used when a link target is a known folder to keep track of the folder so that the link target IDList can be translated.

When an LNK is loaded. the shell uses the `KnownFolderID` to resolve the current path to the folder (which may have changed since the LNK was created), then uses the `Offset` to locate a specific item within the PIDL relative to that folder. This is the namespace context switching mechanism. The `KnownFolderID` changes which folder namespace interprets PIDL.