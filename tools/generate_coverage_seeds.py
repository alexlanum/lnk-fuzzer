"""
Gap-filling seeds for the live shell32 corpus (seeds/).

The collected corpus is filesystem/CLSID heavy: classifying it with the project's own
deserialize_lnk (tools/classify.c) shows several operator groups have NO seed satisfying their
precondition, so those operators never get live candidates. This script emits one well-formed
seed per missing structural variety, straight into seeds/, using only the struct builders in
_lnk_helpers.py (no pylnk3 dependency).

Gaps filled (vs. the collected seeds/ corpus):
  - ExtraData blocks absent from the live corpus: Darwin, KnownFolder, SpecialFolder, Console,
    Console-FE, Shim, Environment/IconEnvironment, VistaIDList, unknown-signature.
  - PropertyStore depth: String-Named scheme; multi-storage + multi-value (>=2 each).
  - PIDL variety: network items (resource/server/share).
  - LinkInfo: CommonNetworkRelativeLink (UNC).
  - StringData: an ANSI (non-Unicode) seed.

Not produced: delegate / extension PIDL items — deserialize.c does not classify those from
abID[0] (see its TODO), so they cannot be tagged as such regardless of the bytes.

Run from the project root:
    python tools/generate_coverage_seeds.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lnk_helpers import (
    block_darwin, block_known_folder, block_special_folder, block_console,
    block_console_fe, block_shim, block_environment, block_icon_environment,
    block_vista_idlist, block_unknown_signature, block_property_store_string_named,
    block_property_store_rich, shitemid_clsid, shitemid_filesystem_dir,
    shitemid_filesystem_file, shitemid_network, build_idlist, with_idlist_size,
    build_header, build_string_data, linkinfo_unc,
    CLSID_MY_COMPUTER, CLSID_NETWORK, FOLDERID_Documents, FOLDERID_ControlPanelFolder,
    CSIDL_CONTROLS,
    LF_HAS_LINK_TARGET_IDLIST, LF_HAS_LINK_INFO, LF_HAS_NAME, LF_HAS_RELATIVE_PATH,
    LF_HAS_ARGUMENTS, LF_IS_UNICODE, LF_HAS_DARWIN_ID,
)

OUT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'seeds'))
PREFIX = 'cov_'  # marks generator-authored gap-fillers, distinct from the collected corpus


def build_lnk(*, link_flags, idlist=None, link_info=None, strings=None, extra_blocks=()):
    out = build_header(link_flags)
    if idlist is not None:
        out += with_idlist_size(idlist)
    if link_info is not None:
        out += link_info
    if strings:
        is_uni = bool(link_flags & LF_IS_UNICODE)
        for bit in (LF_HAS_NAME, LF_HAS_RELATIVE_PATH, 0x10, LF_HAS_ARGUMENTS, 0x40):
            if link_flags & bit and bit in strings:
                out += build_string_data(strings[bit], is_uni)
    for b in extra_blocks:
        out += b
    out += b'\x00\x00\x00\x00'  # ExtraData terminator
    return out


def write(name, data):
    with open(os.path.join(OUT_DIR, PREFIX + name), 'wb') as f:
        f.write(data)
    print(f'  wrote {PREFIX}{name} ({len(data)} bytes)')


FS_IDL = build_idlist([
    shitemid_clsid(CLSID_MY_COMPUTER),
    shitemid_filesystem_dir('Windows'),
    shitemid_filesystem_file('app.exe'),
])
UNI = LF_HAS_LINK_TARGET_IDLIST | LF_IS_UNICODE

SEEDS = {
    # --- ExtraData blocks missing from the live corpus ---
    'darwin.lnk':            build_lnk(link_flags=UNI | LF_HAS_DARWIN_ID, idlist=FS_IDL,
                                       extra_blocks=[block_darwin()]),
    'knownfolder.lnk':       build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_known_folder(FOLDERID_Documents)]),
    'knownfolder_cpl.lnk':   build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_known_folder(FOLDERID_ControlPanelFolder)]),
    'specialfolder.lnk':     build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_special_folder(csidl=CSIDL_CONTROLS)]),
    'console.lnk':           build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_console(), block_console_fe(437)]),
    'shim.lnk':              build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_shim('RUNASINVOKER')]),
    'envvars.lnk':           build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_environment(), block_icon_environment()]),
    'vista_idlist.lnk':      build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_vista_idlist(FS_IDL)]),
    'unknown_sig.lnk':       build_lnk(link_flags=UNI, idlist=FS_IDL,
                                       extra_blocks=[block_unknown_signature()]),

    # --- PropertyStore depth ---
    'propstore_strnamed.lnk': build_lnk(link_flags=UNI, idlist=FS_IDL,
                                        extra_blocks=[block_property_store_string_named()]),
    'propstore_rich.lnk':     build_lnk(link_flags=UNI, idlist=FS_IDL,
                                        extra_blocks=[block_property_store_rich()]),

    # --- PIDL variety: network items ---
    'pidl_network.lnk':       build_lnk(link_flags=UNI, idlist=build_idlist([
                                  shitemid_clsid(CLSID_NETWORK),
                                  shitemid_network(0x42, r'\\FILESERVER'),       # NETWORK_SERVER
                                  shitemid_network(0x41, r'\\FILESERVER\share'), # NETWORK_RESOURCE
                                  shitemid_network(0x46, r'\\FILESERVER\share\d'),# NETWORK_SHARE
                              ])),

    # --- LinkInfo: UNC / CommonNetworkRelativeLink ---
    'linkinfo_unc.lnk':       build_lnk(link_flags=UNI | LF_HAS_LINK_INFO, idlist=FS_IDL,
                                        link_info=linkinfo_unc()),

    # --- StringData: ANSI (no Unicode flag) ---
    'ansi_strings.lnk':       build_lnk(
                                  link_flags=LF_HAS_LINK_TARGET_IDLIST | LF_HAS_NAME
                                             | LF_HAS_RELATIVE_PATH | LF_HAS_ARGUMENTS,
                                  idlist=build_idlist([shitemid_clsid(CLSID_MY_COMPUTER)]),
                                  strings={LF_HAS_NAME: 'ANSI shortcut',
                                           LF_HAS_RELATIVE_PATH: r'..\target.exe',
                                           LF_HAS_ARGUMENTS: '/ansi'}),
}

if __name__ == '__main__':
    os.makedirs(OUT_DIR, exist_ok=True)
    print(f'=== writing {len(SEEDS)} coverage seeds to {OUT_DIR} ===')
    for name, data in SEEDS.items():
        write(name, data)
    print('done')
