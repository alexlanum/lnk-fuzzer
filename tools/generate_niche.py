"""
Generate the LNK shapes neither pylnk3 nor our other generators handle:

  * Network-share LinkInfo with CommonNetworkRelativeLink — the CVE-2015-0096
    attack surface. pylnk3's LinkInfo serializer doesn't emit a CNRL.
  * Extended LinkInfo header (>= 0x24) with Unicode local-base-path and
    Unicode common-path-suffix fields.
  * Spec-violating shapes the deserializer is supposed to tolerate: missing
    ExtraData terminator, oversized IDListSize, etc. These are valuable as
    seeds because they exercise the parser's recovery paths in their initial
    state, before the mutator perturbs them further.
  * Embedded-spaces LinkInfo path matching the CVE-2015-0096 257-character
    pattern.

Output goes into corpus/seeds/ alongside generate_seeds.py's output.

Run from the project root:
    python tools/generate_niche.py
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lnk_helpers import (
    block_tracker, block_special_folder, block_known_folder,
    shitemid_clsid, shitemid_filesystem_dir, shitemid_filesystem_file,
    build_idlist, with_idlist_size, build_header, build_string_data,
    CLSID_MY_COMPUTER, CLSID_NETWORK,
    FOLDERID_ControlPanelFolder,
    LF_HAS_LINK_TARGET_IDLIST, LF_HAS_LINK_INFO, LF_HAS_RELATIVE_PATH,
    LF_HAS_WORKING_DIR, LF_IS_UNICODE,
)

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', 'corpus', 'seeds')
OUT_DIR = os.path.abspath(OUT_DIR)
os.makedirs(OUT_DIR, exist_ok=True)


def write(name, data):
    path = os.path.join(OUT_DIR, name)
    with open(path, 'wb') as f:
        f.write(data)
    print(f'  wrote {name} ({len(data)} bytes)')


# ===========================================================================
# CommonNetworkRelativeLink builder. CVE-2015-0096 surface.
# ===========================================================================
def build_cnrl(net_name=r'\\server\share', device_name='Z:',
               provider_type=0x00020000,  # WNNC_NET_LANMAN
               with_unicode=True, has_device=True):
    """Build a CommonNetworkRelativeLink struct (variable size)."""
    has_device_flag = 0x01 if has_device else 0x00
    valid_net_flag  = 0x02

    if with_unicode:
        # Extended layout: extra two Unicode offsets, plus Unicode strings at end.
        # Header is 0x18 + 4*2 = 0x20 bytes before the variable strings.
        net_ansi = net_name.encode('ascii', errors='replace') + b'\x00'
        dev_ansi = (device_name.encode('ascii', errors='replace') + b'\x00') if has_device else b''
        net_uni  = net_name.encode('utf-16-le') + b'\x00\x00'
        dev_uni  = (device_name.encode('utf-16-le') + b'\x00\x00') if has_device else b''

        header_size = 0x20  # NetNameOffset > 0x14 ⇒ unicode fields present
        net_off       = header_size
        dev_off       = net_off + len(net_ansi) if has_device else 0
        strings_after = net_off + len(net_ansi) + len(dev_ansi)
        net_uni_off   = strings_after
        dev_uni_off   = net_uni_off + len(net_uni) if has_device else 0
        total_size    = strings_after + len(net_uni) + len(dev_uni)

        out  = struct.pack('<I', total_size)
        out += struct.pack('<I', has_device_flag | valid_net_flag)
        out += struct.pack('<I', net_off)
        out += struct.pack('<I', dev_off)
        out += struct.pack('<I', provider_type)
        out += struct.pack('<I', net_uni_off)
        out += struct.pack('<I', dev_uni_off)
        out += net_ansi
        out += dev_ansi
        out += net_uni
        out += dev_uni
    else:
        net_ansi = net_name.encode('ascii', errors='replace') + b'\x00'
        dev_ansi = (device_name.encode('ascii', errors='replace') + b'\x00') if has_device else b''

        header_size = 0x14
        net_off    = header_size
        dev_off    = net_off + len(net_ansi) if has_device else 0
        total_size = net_off + len(net_ansi) + len(dev_ansi)

        out  = struct.pack('<I', total_size)
        out += struct.pack('<I', has_device_flag | valid_net_flag)
        out += struct.pack('<I', net_off)
        out += struct.pack('<I', dev_off)
        out += struct.pack('<I', provider_type)
        out += net_ansi
        out += dev_ansi
    return out


def build_volume_id(drive_type=3, serial=0xCAFEBABE, label='LOCALDISK',
                    label_unicode=False):
    """Build a VolumeID struct (variable size)."""
    if label_unicode:
        label_bytes = label.encode('utf-16-le') + b'\x00\x00'
        # offset_unicode immediately follows the 5 fixed dwords (20 bytes header)
        out  = struct.pack('<I', 0x14 + len(label_bytes))  # VolumeIDSize
        out += struct.pack('<I', drive_type)
        out += struct.pack('<I', serial)
        out += struct.pack('<I', 0x14)                      # VolumeLabelOffset (sentinel)
        out += struct.pack('<I', 0x14)                      # VolumeLabelOffsetUnicode
        out += label_bytes
    else:
        label_bytes = label.encode('ascii', errors='replace') + b'\x00'
        out  = struct.pack('<I', 0x10 + len(label_bytes))   # VolumeIDSize
        out += struct.pack('<I', drive_type)
        out += struct.pack('<I', serial)
        out += struct.pack('<I', 0x10)                      # VolumeLabelOffset
        out += label_bytes
    return out


def build_link_info(*, with_volume_id=False, with_cnrl=False,
                    extended_header=False, local_base_path='',
                    common_path_suffix='', cnrl=None, volume_id=None):
    """Assemble a LinkInfo block. Either or both of VolumeID / CNRL may be present.

    Layout:
       [LinkInfoSize:4][LinkInfoHeaderSize:4][LinkInfoFlags:4]
       [VolumeIDOffset:4][LocalBasePathOffset:4]
       [CommonNetworkRelativeLinkOffset:4][CommonPathSuffixOffset:4]
       [LocalBasePathOffsetUnicode:4][CommonPathSuffixOffsetUnicode:4]   (if extended)
       [VolumeID][LocalBasePath][CommonNetworkRelativeLink][CommonPathSuffix]
       [LocalBasePathUnicode][CommonPathSuffixUnicode]                   (if extended)
    """
    flags = 0
    if with_volume_id: flags |= 0x01
    if with_cnrl:      flags |= 0x02

    lbp_ansi = local_base_path.encode('ascii', errors='replace') + b'\x00'
    cps_ansi = common_path_suffix.encode('ascii', errors='replace') + b'\x00'
    lbp_uni  = local_base_path.encode('utf-16-le') + b'\x00\x00'
    cps_uni  = common_path_suffix.encode('utf-16-le') + b'\x00\x00'

    header_size = 0x24 if extended_header else 0x1C
    cursor = header_size

    vol_off = 0
    if with_volume_id:
        vol_off = cursor
        cursor += len(volume_id)

    lbp_off = 0
    if with_volume_id:
        lbp_off = cursor
        cursor += len(lbp_ansi)

    cnrl_off = 0
    if with_cnrl:
        cnrl_off = cursor
        cursor += len(cnrl)

    cps_off = cursor
    cursor += len(cps_ansi)

    lbp_uni_off = 0
    cps_uni_off = 0
    if extended_header:
        if with_volume_id:
            lbp_uni_off = cursor
            cursor += len(lbp_uni)
        cps_uni_off = cursor
        cursor += len(cps_uni)

    total_size = cursor
    out  = struct.pack('<II', total_size, header_size)
    out += struct.pack('<I', flags)
    out += struct.pack('<IIII', vol_off, lbp_off, cnrl_off, cps_off)
    if extended_header:
        out += struct.pack('<II', lbp_uni_off, cps_uni_off)
    if with_volume_id:
        out += volume_id + lbp_ansi
    if with_cnrl:
        out += cnrl
    out += cps_ansi
    if extended_header:
        if with_volume_id:
            out += lbp_uni
        out += cps_uni
    return out


# ===========================================================================
# Build the seeds.
# ===========================================================================

base_idl = build_idlist([
    shitemid_clsid(CLSID_NETWORK),
    shitemid_filesystem_dir('share'),
    shitemid_filesystem_file('target.exe'),
])

# 30: simple network-share LNK. CommonNetworkRelativeLink, no VolumeID,
# non-extended header. Drives the CNRL-only LinkInfo decode path.
li = build_link_info(
    with_volume_id=False, with_cnrl=True, extended_header=False,
    common_path_suffix='subdir\\target.exe',
    cnrl=build_cnrl(net_name=r'\\server\share', has_device=False,
                    with_unicode=False))
write('30_network_share_basic.lnk',
      build_header(LF_HAS_LINK_TARGET_IDLIST | LF_HAS_LINK_INFO | LF_IS_UNICODE)
      + with_idlist_size(base_idl)
      + li
      + b'\x00\x00\x00\x00')

# 31: network-share with extended header — Unicode CommonPathSuffix and
# DeviceNameUnicode. The wider unicode-path code path lit up here is what
# CVE-2015-0096 hit.
li = build_link_info(
    with_volume_id=False, with_cnrl=True, extended_header=True,
    common_path_suffix='unicode\\path.exe',
    cnrl=build_cnrl(net_name=r'\\unicode-server\share',
                    device_name='Y:', has_device=True, with_unicode=True))
write('31_network_share_unicode.lnk',
      build_header(LF_HAS_LINK_TARGET_IDLIST | LF_HAS_LINK_INFO | LF_IS_UNICODE)
      + with_idlist_size(base_idl)
      + li
      + b'\x00\x00\x00\x00')

# 32: VolumeID + CNRL combined — both LinkInfo flags set. Real-world LNKs that
# point at a file accessible via either local mount or network share have this.
li = build_link_info(
    with_volume_id=True, with_cnrl=True, extended_header=True,
    local_base_path=r'C:\Users\victim\Documents\file.exe',
    common_path_suffix='Documents\\file.exe',
    volume_id=build_volume_id(label='SYSTEM'),
    cnrl=build_cnrl(net_name=r'\\dc01\users$', device_name='H:',
                    has_device=True, with_unicode=True))
write('32_volume_and_network.lnk',
      build_header(LF_HAS_LINK_TARGET_IDLIST | LF_HAS_LINK_INFO
                    | LF_HAS_RELATIVE_PATH | LF_HAS_WORKING_DIR | LF_IS_UNICODE)
      + with_idlist_size(base_idl)
      + li
      + build_string_data(r'..\file.exe', True)
      + build_string_data(r'\\dc01\users$\victim', True)
      + b'\x00\x00\x00\x00')

# 33: CVE-2015-0096-style — embedded spaces in a 257-char path. The exact
# trigger pattern: long path, two spaces inside, parser miscounts.
spaces_path = r'C:\Program Files (x86)\Common Files\System\spaces  here\target.exe'
spaces_path = spaces_path + 'A' * (257 - len(spaces_path))  # pad to 257 chars
li = build_link_info(
    with_volume_id=True, with_cnrl=False, extended_header=True,
    local_base_path=spaces_path[:259],  # ANSI
    common_path_suffix='target.exe',
    volume_id=build_volume_id())
write('33_cve_2015_0096_spaces.lnk',
      build_header(LF_HAS_LINK_TARGET_IDLIST | LF_HAS_LINK_INFO | LF_IS_UNICODE)
      + with_idlist_size(base_idl)
      + li
      + b'\x00\x00\x00\x00')

# 34: VolumeID with Unicode label (offset == 0x14 sentinel).
li = build_link_info(
    with_volume_id=True, with_cnrl=False, extended_header=True,
    local_base_path=r'D:\unicode-volume\target.exe',
    common_path_suffix='target.exe',
    volume_id=build_volume_id(label='Юникод', label_unicode=True))
write('34_volume_unicode_label.lnk',
      build_header(LF_HAS_LINK_TARGET_IDLIST | LF_HAS_LINK_INFO | LF_IS_UNICODE)
      + with_idlist_size(base_idl)
      + li
      + b'\x00\x00\x00\x00')

# 35: minimal valid LNK — just the header and the ExtraData terminator.
# No IDList, no LinkInfo, no strings. Tests the absolute-minimum-shape parser path.
write('35_minimal.lnk',
      build_header(0)  # no flags set at all
      + b'\x00\x00\x00\x00')

# 36: CVE-2017-8464 attack pattern with maximum block diversity — Tracker too,
# so all four namespace-redirection-relevant blocks are simultaneously present.
namespace_idl = build_idlist([
    shitemid_clsid(CLSID_MY_COMPUTER),
    shitemid_filesystem_dir('Control Panel'),
])
write('36_cve_2017_8464_full.lnk',
      build_header(LF_HAS_LINK_TARGET_IDLIST | LF_IS_UNICODE)
      + with_idlist_size(namespace_idl)
      + block_special_folder(csidl=0x03, offset=0x14)
      + block_known_folder(folder_id=FOLDERID_ControlPanelFolder, offset=0x14)
      + block_tracker(machine_id='DOMAIN-DC01')
      + b'\x00\x00\x00\x00')

print(f'\nDone. {len(os.listdir(OUT_DIR))} files in {OUT_DIR}')
