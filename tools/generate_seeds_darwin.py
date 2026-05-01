"""
Generate the Darwin-targeted seed corpus at corpus/seeds_darwin/.

Every file written here contains a real DarwinDataBlock (signature 0xA0000006), which
is what harness_darwin.cpp's signature-scan locates before passing the descriptor to
CommandLineFromMsiDescriptor. Without a Darwin block, MsiGetShortcutTarget returns
ERROR_INVALID_DATA before the descriptor parser is reached.

Coverage strategy: each file varies one axis of the descriptor (well-formed product
code, malformed GUID, near-overlong, ANSI-only, both ANSI and Unicode populated, etc.)
so MUTATE_DARWIN_* operators each have a productive starting point.

Run from the project root:
    python tools/generate_seeds_darwin.py
"""
import os
import sys

import pylnk3

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lnk_helpers import (
    block_darwin, block_environment, block_property_store_minimal,
    shitemid_clsid, shitemid_filesystem_dir, shitemid_filesystem_file,
    build_idlist, with_idlist_size, build_header,
    CLSID_MY_COMPUTER,
    LF_HAS_LINK_TARGET_IDLIST, LF_IS_UNICODE, LF_HAS_DARWIN_ID,
    LF_HAS_RELATIVE_PATH,
)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', 'corpus', 'seeds_darwin')
OUT_DIR = os.path.abspath(OUT_DIR)
os.makedirs(OUT_DIR, exist_ok=True)


def write(name, data):
    path = os.path.join(OUT_DIR, name)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  wrote {name} ({len(data)} bytes)')


# Helper: assemble a hand-built LNK with HasDarwinID flag, an IDList, and one or
# more ExtraData blocks. We prefer hand-built over pylnk3-spliced here because we
# want the HasDarwinID LinkFlags bit set, which pylnk3 doesn't expose.
def build_lnk(*, link_flags, idlist, extra_blocks):
    out = build_header(link_flags)
    out += with_idlist_size(idlist)
    for b in extra_blocks:
        out += b
    out += b'\x00\x00\x00\x00'
    return out


# Minimal IDList every Darwin seed shares — one MyComputer item plus a fake target.
# msi.dll opens the file by path and needs the LNK to parse far enough to reach
# ExtraData; an IDList of any kind keeps that working.
base_idl = build_idlist([
    shitemid_clsid(CLSID_MY_COMPUTER),
    shitemid_filesystem_dir('Program Files'),
    shitemid_filesystem_file('msi.exe'),
])

base_flags = LF_HAS_LINK_TARGET_IDLIST | LF_HAS_DARWIN_ID | LF_IS_UNICODE


# 01: well-formed Darwin descriptor. Standard MSI advertised-shortcut shape.
write('01_darwin_wellformed.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[block_darwin(
              product_code='{12345678-1234-1234-1234-123456789012}',
              feature_id='DefaultFeature',
              component_code='{ABCDEF12-3456-7890-ABCD-EF1234567890}',
          )]))

# 02: empty descriptor (all-zero ANSI + all-zero Unicode).
# MUTATE_DARWIN_NULL_BYTES needs a starting point with already-quiet bytes.
write('02_darwin_empty.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[block_darwin(product_code='', feature_id='',
                                     component_code='')]))

# 03: ANSI-only Darwin (Unicode portion zero). Forces msi.dll to fall back to
# the ANSI parsing path, which has different validation.
darwin_ansi_only = block_darwin(
    product_code='{AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA}',
    feature_id='AnsiOnlyFeature',
    component_code='{BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB}',
)
# Zero out the Unicode half (last 520 bytes of the 780-byte payload).
header = darwin_ansi_only[:8]
ansi   = darwin_ansi_only[8:8+260]
darwin_ansi_only = header + ansi + b'\x00' * 520
write('03_darwin_ansi_only.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[darwin_ansi_only]))

# 04: descriptor right at the 259-char Unicode boundary. CommandLineFromMsiDescriptor
# bounds at 259 wchars + nul; values that fill exactly to the boundary exercise the
# off-by-one paths in the bounds check.
near_overlong = 'X' * 259
write('04_darwin_near_overlong.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[block_darwin(
              product_code=near_overlong[:38],
              feature_id=near_overlong[38:38+38],
              component_code=near_overlong[76:76+38],
          )]))

# 05: malformed GUID brackets — descriptor with wrong/missing braces. Tests the
# GUID parser's rejection branch.
write('05_darwin_malformed_guid.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[block_darwin(
              product_code='12345678-NOT-A-GUID-NOPE',
              feature_id='Default',
              component_code='no-braces-here',
          )]))

# 06: Darwin block alongside the env-var block. Real-world MSI advertised
# shortcuts often have both — exercises the multi-block dispatch in msi.dll.
write('06_darwin_with_envvars.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[
              block_darwin(),
              block_environment(r'%TEMP%\msi-launcher.exe'),
          ]))

# 07: Darwin block plus a PropertyStore block. Some MSI shortcuts attach
# System.AppUserModel.* properties for taskbar grouping; the parser walks both.
write('07_darwin_with_propstore.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[
              block_darwin(),
              block_property_store_minimal(),
          ]))

# 08: HasDarwinID flag set but NO Darwin block present (spec-violating combo).
# Tests msi.dll's behavior when the flag claims a block but none exists.
write('08_darwin_flag_only_no_block.lnk',
      build_lnk(
          link_flags=base_flags, idlist=base_idl,
          extra_blocks=[]))

# 09: Darwin block but flag NOT set. Inverse spec violation — block present in
# bytes but parser shouldn't decode it. Some implementations decode anyway.
write('09_darwin_block_only_no_flag.lnk',
      build_lnk(
          link_flags=LF_HAS_LINK_TARGET_IDLIST | LF_IS_UNICODE,
          idlist=base_idl,
          extra_blocks=[block_darwin()]))

print(f'\nDone. {len(os.listdir(OUT_DIR))} files in {OUT_DIR}')
