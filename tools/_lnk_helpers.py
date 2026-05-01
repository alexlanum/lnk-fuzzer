"""
Shared helpers for the LNK seed generators.

Two responsibilities:
  1. Build raw byte payloads for the eight ExtraData blocks pylnk3 cannot serialize
     (Console, ConsoleFE, Tracker, SpecialFolder, Darwin, Shim, KnownFolder, VistaIDL).
     Each helper returns a complete on-disk block: 4-byte BlockSize + 4-byte BlockSignature
     + payload, ready to drop into a pylnk3 ExtraData_Unparsed slot or concatenate behind a
     hand-built header.
  2. Build raw PIDLs (SHITEMID chains) for shapes pylnk3 won't touch — Stuxnet's
     [MyComputer, ControlPanel, CPL] pattern, deep filesystem chains, delegate items.

Layouts come from MS-SHLLINK and the project's notes/LNK.md / notes/ExtraData.md.
"""
import struct
import uuid

# ---------------------------------------------------------------------------
# Known GUIDs / CLSIDs we'll plant into seeds. Pulled from notes/vulnscool.md
# and the standard shell namespace catalogue.
# ---------------------------------------------------------------------------
CLSID_MY_COMPUTER       = uuid.UUID('20D04FE0-3AEA-1069-A2D8-08002B30309D')
CLSID_CONTROL_PANEL     = uuid.UUID('21EC2020-3AEA-1069-A2DD-08002B30309D')
CLSID_RECYCLE_BIN       = uuid.UUID('645FF040-5081-101B-9F08-00AA002F954E')
CLSID_NETWORK           = uuid.UUID('208D2C60-3AEA-1069-A2D7-08002B30309D')

FOLDERID_ControlPanelFolder = uuid.UUID('82A74AEB-AEB4-465C-A014-D097EE346D63')
FOLDERID_Desktop            = uuid.UUID('B4BFCC3A-DB2C-424C-B029-7FE99A87C641')
FOLDERID_Documents          = uuid.UUID('FDD39AD0-238F-46AF-ADB4-6C85480369C7')
FOLDERID_PrintersFolder     = uuid.UUID('76FC4E2D-D6AD-4519-A663-37BD56068185')
FOLDERID_RecycleBinFolder   = uuid.UUID('B7534046-3ECB-4C18-BE4E-64CD4CB7D6AC')

# CSIDL legacy constants for SpecialFolderDataBlock
CSIDL_DESKTOP   = 0x00
CSIDL_CONTROLS  = 0x03
CSIDL_FONTS     = 0x14
CSIDL_SYSTEM    = 0x25


# ---------------------------------------------------------------------------
# GUID → MS-DTYP packed 16-byte representation (mixed endian).
# Windows GUIDs serialize as: 4 LE + 2 LE + 2 LE + 8 BE.
# Python's uuid.UUID.bytes_le matches this; bytes is pure big-endian (wrong for SHLLINK).
# ---------------------------------------------------------------------------
def guid_bytes(g):
    if isinstance(g, str):
        g = uuid.UUID(g)
    return g.bytes_le


# ---------------------------------------------------------------------------
# ExtraData block builders.
# Every helper returns: <4 BlockSize><4 BlockSignature><payload>.
# These are designed to be valid enough that the deserializer accepts them, but
# small enough to leave plenty of room for the mutator to rearrange.
# ---------------------------------------------------------------------------

def block_environment(env_str=r'%TEMP%\fuzz.exe', unicode=True):
    """EnvironmentVariableDataBlock — 0xA0000001, 260 ANSI bytes + 520 Unicode bytes."""
    ansi = env_str.encode('ascii', errors='replace')[:259].ljust(260, b'\x00')
    uni  = env_str.encode('utf-16-le')[:518].ljust(520, b'\x00')
    payload = ansi + uni
    return struct.pack('<II', 8 + len(payload), 0xA0000001) + payload


def block_console():
    """ConsoleDataBlock — 0xA0000002, fixed 196-byte payload."""
    payload = bytearray(196)
    # FillAttributes = 0x0007 (white on black), screen buffer 80x300, window 80x25
    struct.pack_into('<HHhhhhhh', payload, 0, 0x0007, 0x0000,
                     80, 300, 80, 25, 0, 0)
    # Font weight, family, name (32 wchar). Console uses Lucida Console etc.
    struct.pack_into('<II', payload, 16, 400, 0x36)  # weight, family
    payload[24:24+22] = 'Lucida Console'.encode('utf-16-le')[:22]
    # CursorSize, FullScreen, QuickEdit, InsertMode, AutoPosition
    struct.pack_into('<IIIIIH', payload, 88, 25, 0, 1, 1, 0, 0)
    # HistoryBufferSize, NumberOfHistoryBuffers, HistoryNoDup, ColorTable[16]
    struct.pack_into('<III', payload, 116, 50, 4, 0)
    return struct.pack('<II', 8 + len(payload), 0xA0000002) + bytes(payload)


def block_console_fe(code_page=437):
    """ConsoleFEDataBlock — 0xA0000004, 4-byte code page payload."""
    payload = struct.pack('<I', code_page)
    return struct.pack('<II', 8 + len(payload), 0xA0000004) + payload


def block_tracker(machine_id='WORKSTATION-01',
                  droid=None, droid_birth=None):
    """TrackerDataBlock — 0xA0000003, 88-byte payload."""
    if droid is None:
        droid = (uuid.uuid4(), uuid.uuid4())
    if droid_birth is None:
        droid_birth = (droid[0], droid[1])

    machine = machine_id.encode('ascii', errors='replace')[:15].ljust(16, b'\x00')
    # Length includes itself onward (88 bytes)
    payload = struct.pack('<II', 88, 0)  # Length, Version
    payload += machine
    payload += guid_bytes(droid[0]) + guid_bytes(droid[1])
    payload += guid_bytes(droid_birth[0]) + guid_bytes(droid_birth[1])
    return struct.pack('<II', 8 + len(payload), 0xA0000003) + payload


def block_special_folder(csidl=CSIDL_CONTROLS, offset=0x00000014):
    """SpecialFolderDataBlock — 0xA0000005, 8-byte payload."""
    payload = struct.pack('<II', csidl, offset)
    return struct.pack('<II', 8 + len(payload), 0xA0000005) + payload


def block_darwin(product_code='{12345678-1234-1234-1234-123456789012}',
                 feature_id='DefaultFeature',
                 component_code='{ABCDEF12-3456-7890-ABCD-EF1234567890}'):
    """DarwinDataBlock — 0xA0000006, 260 ANSI + 520 Unicode = 780 bytes payload.

    The 'descriptor' string Microsoft expects is a packed concatenation of GUID-encoded
    product/feature/component identifiers. We emit the concatenated string in both
    encodings so msi.dll's parser sees something plausible in either.
    """
    descriptor = f'{product_code}{feature_id}{component_code}'
    ansi = descriptor.encode('ascii', errors='replace')[:259].ljust(260, b'\x00')
    uni  = descriptor.encode('utf-16-le')[:518].ljust(520, b'\x00')
    payload = ansi + uni
    return struct.pack('<II', 8 + len(payload), 0xA0000006) + payload


def block_icon_environment(icon_path=r'%SystemRoot%\System32\imageres.dll'):
    """IconEnvironmentDataBlock — 0xA0000007, 260 ANSI + 520 Unicode."""
    ansi = icon_path.encode('ascii', errors='replace')[:259].ljust(260, b'\x00')
    uni  = icon_path.encode('utf-16-le')[:518].ljust(520, b'\x00')
    payload = ansi + uni
    return struct.pack('<II', 8 + len(payload), 0xA0000007) + payload


def block_shim(layer_name='RUNASINVOKER'):
    """ShimDataBlock — 0xA0000008, variable Unicode layer name."""
    payload = layer_name.encode('utf-16-le') + b'\x00\x00'
    return struct.pack('<II', 8 + len(payload), 0xA0000008) + payload


def block_property_store_minimal():
    """PropertyStoreDataBlock — 0xA0000009, minimal valid SerializedPropertyStorage.

    One storage with the System.Title FMTID and one VT_LPWSTR value. Real LNKs from
    Windows have many more properties, but one is enough for the parser to enter the
    decode loop.
    """
    # FMTID: System.Title = {F29F85E0-4FF9-1068-AB91-08002B27B3D9}
    fmtid = guid_bytes('F29F85E0-4FF9-1068-AB91-08002B27B3D9')
    # SerializedPropertyValue (integer-named):
    #   [ValueSize:4][PropertyID:4][Reserved:1][TypedPropertyValue:var]
    # TypedPropertyValue VT_LPWSTR (0x001F):
    #   [vt:2][padding:2][cch:4][bytes...]
    title = 'fuzzed'.encode('utf-16-le') + b'\x00\x00'
    cch = len(title) // 2
    tpv = struct.pack('<HHI', 0x001F, 0x0000, cch) + title
    value = struct.pack('<IIB', 9 + len(tpv), 2, 0) + tpv  # PropertyID=2 (System.Title)
    storage = struct.pack('<I', 24 + len(value) + 4)       # StorageSize
    storage += struct.pack('<I', 0x53505331)                # Version "1SPS"
    storage += fmtid
    storage += value
    storage += struct.pack('<I', 0)                         # value-list terminator
    payload = storage + struct.pack('<I', 0)                # storage-list terminator
    return struct.pack('<II', 8 + len(payload), 0xA0000009) + payload


def block_known_folder(folder_id=FOLDERID_Documents, offset=0x00000014):
    """KnownFolderDataBlock — 0xA000000B, 20-byte payload."""
    payload = guid_bytes(folder_id) + struct.pack('<I', offset)
    return struct.pack('<II', 8 + len(payload), 0xA000000B) + payload


def block_vista_idlist(idlist_bytes):
    """VistaAndAboveIDListDataBlock — 0xA000000C, variable IDList payload.

    `idlist_bytes` should be a complete SHITEMID chain ending with a 2-byte terminator.
    """
    return struct.pack('<II', 8 + len(idlist_bytes), 0xA000000C) + idlist_bytes


# ---------------------------------------------------------------------------
# PIDL builders. SHITEMID structure:
#   uint16 cb     (size including cb itself)
#   uint8  abID[] (cb-2 bytes; first byte = class type)
# An IDList ends with a 2-byte zero terminator.
# ---------------------------------------------------------------------------

def shitemid(class_type, payload):
    """Wrap (class_type byte + payload bytes) into a complete SHITEMID."""
    body = bytes([class_type]) + payload
    cb = 2 + len(body)
    return struct.pack('<H', cb) + body


def shitemid_clsid(clsid):
    """Class type 0x1F: CLSID-rooted virtual folder. abID = [0x1F, 0x50, GUID].

    The 0x50 sort-order byte is what Stuxnet's PIDL also used.
    """
    return shitemid(0x1F, b'\x50' + guid_bytes(clsid))


def shitemid_cpl_descriptor(cpl_path, applet_index=0):
    """Class type 0x00 (delegate / control-panel applet inside CControlPanelFolder).

    Real CPL descriptors include CPLINFO/NEWCPLINFO metadata; for fuzzing we just
    embed the path as Unicode and let the mutator scramble the trailing bytes.
    """
    path_bytes = cpl_path.encode('utf-16-le') + b'\x00\x00'
    return shitemid(0x00, struct.pack('<I', applet_index) + path_bytes)


def shitemid_filesystem_dir(name='folder'):
    """Class type 0x31: filesystem directory."""
    # abID[0] = 0x31, then short-name (8.3 ANSI) + extension data + Unicode name
    n = name.encode('ascii', errors='replace').ljust(14, b'\x00')[:14]
    return shitemid(0x31, b'\x00' * 14 + n)


def shitemid_filesystem_file(name='file.txt'):
    """Class type 0x32: filesystem file."""
    n = name.encode('ascii', errors='replace').ljust(14, b'\x00')[:14]
    return shitemid(0x32, b'\x00' * 14 + n)


def shitemid_terminator():
    return b'\x00\x00'


def build_idlist(items):
    """Concatenate SHITEMIDs and append the 2-byte terminator."""
    return b''.join(items) + shitemid_terminator()


def with_idlist_size(idlist):
    """Prepend the 2-byte IDListSize field (the value Jackalope/CShellLink reads)."""
    return struct.pack('<H', len(idlist)) + idlist


# ---------------------------------------------------------------------------
# Hand-built LNK construction (when pylnk3 won't do).
# ---------------------------------------------------------------------------
LNK_CLSID = bytes([
    0x01, 0x14, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xC0, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x46,
])

# LinkFlags bits
LF_HAS_LINK_TARGET_IDLIST   = 0x00000001
LF_HAS_LINK_INFO            = 0x00000002
LF_HAS_NAME                 = 0x00000004
LF_HAS_RELATIVE_PATH        = 0x00000008
LF_HAS_WORKING_DIR          = 0x00000010
LF_HAS_ARGUMENTS            = 0x00000020
LF_HAS_ICON_LOCATION        = 0x00000040
LF_IS_UNICODE               = 0x00000080
LF_FORCE_NO_LINK_INFO       = 0x00000100
LF_HAS_EXP_STRING           = 0x00000200
LF_HAS_DARWIN_ID            = 0x00001000
LF_HAS_EXP_ICON             = 0x00002000
LF_RUN_WITH_SHIM_LAYER      = 0x00800000


def build_header(link_flags, file_attributes=0x00000020,
                 file_size=0, icon_index=0, show_cmd=1, hot_key=0):
    """Construct the 76-byte ShellLinkHeader."""
    return (
        struct.pack('<I', 0x4C)      # HeaderSize
        + LNK_CLSID                  # LinkCLSID
        + struct.pack('<II', link_flags, file_attributes)
        + struct.pack('<QQQ', 0, 0, 0)  # CreationTime, AccessTime, WriteTime
        + struct.pack('<Ii', file_size, icon_index)
        + struct.pack('<IH', show_cmd, hot_key)
        + struct.pack('<HII', 0, 0, 0)  # Reserved1/2/3
    )


def build_string_data(value, is_unicode):
    """StringData field: <uint16 char count><bytes>. Not null terminated."""
    if is_unicode:
        b = value.encode('utf-16-le')
        return struct.pack('<H', len(value)) + b
    else:
        b = value.encode('ascii', errors='replace')
        return struct.pack('<H', len(b)) + b
