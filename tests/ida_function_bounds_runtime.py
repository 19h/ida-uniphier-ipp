"""Check ELF-backed boundaries and bounded function-start hints in scratch IDBs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import warnings

p = argparse.ArgumentParser()
p.add_argument('--corpus', type=Path)
p.add_argument('--image', required=True)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if args.image != 'synthetic' and args.corpus is None:
    p.error('--corpus is required unless --image is synthetic')
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_bytes
import ida_funcs
import ida_idp
import ida_netnode
import ida_segment
import ida_ua
import ida_xref
import idautils
warnings.filterwarnings('ignore', category=DeprecationWarning)


def extents(raw):
    offset = struct.unpack_from('>I', raw, 32)[0]
    stride, count = struct.unpack_from('>HH', raw, 46)
    sections = [struct.unpack_from('>10I', raw, offset + i * stride) for i in range(count)]
    result = {}
    for section in sections:
        if section[1] not in (2, 11):
            continue
        strings_section = sections[section[6]]
        strings = raw[strings_section[4]:strings_section[4] + strings_section[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            no, va, size, info, _, index = struct.unpack_from('>IIIBBH', raw, offset)
            if not index or not size or info & 15 != 2 or no >= len(strings) or strings[no] == 0:
                continue
            if any(s[2] & 6 == 6 and s[3] <= va < s[3] + s[5] and va + size <= s[3] + s[5] for s in sections):
                result[va] = max(result.get(va, 0), size)
    return result


def synthetic_elf():
    raw = bytearray(0x300)
    raw[0x100:0x300] = bytes.fromhex('014f') * 256
    raw[0x188:0x18c] = bytes.fromhex('3000014f')
    strings = b'\0outer\0inner\0isolated\0nexta\0nextb\0zero\0last\0'
    symbols = bytes(16)
    for name, va, size in [('outer', 0x1000, 64), ('inner', 0x1010, 64),
                           ('isolated', 0x1080, 8), ('nexta', 0x10a0, 8),
                           ('nextb', 0x10a8, 4), ('zero', 0x10c0, 0), ('last', 0x11f8, 8)]:
        symbols += struct.pack('>IIIBBH', strings.index(name.encode() + b'\0'), va, size, 0x12, 0, 1)
    names = b'\0.text\0.strtab\0.symtab\0.shstrtab\0'
    stroff = len(raw); raw.extend(strings)
    raw.extend(bytes(-len(raw) % 4)); symoff = len(raw); raw.extend(symbols)
    nameoff = len(raw); raw.extend(names)
    raw.extend(bytes(-len(raw) % 4)); shoff = len(raw)
    sections = [(0,) * 10,
                (1, 1, 6, 0x1000, 0x100, 0x200, 0, 0, 2, 0),
                (7, 3, 0, 0, stroff, len(strings), 0, 0, 1, 0),
                (15, 2, 0, 0, symoff, len(symbols), 2, 0, 4, 16),
                (23, 3, 0, 0, nameoff, len(names), 0, 0, 1, 0)]
    raw.extend(b''.join(struct.pack('>10I', *s) for s in sections))
    ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
    struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, 0x1000,
                     52, shoff, 0, 52, 32, 1, 40, len(sections), 4)
    struct.pack_into('>8I', raw, 52, 1, 0x100, 0x1000, 0x1000, 0x200, 0x200, 5, 2)
    return raw


result = {'image': args.image, 'passed': False, 'version': idapro.get_library_version()}
temp = tempfile.TemporaryDirectory(prefix='ipp-function-bounds-')
opened = False
try:
    copied = Path(temp.name) / args.image
    if args.image == 'synthetic':
        raw = synthetic_elf()
        copied.write_bytes(raw)
        original = None
    else:
        original = args.corpus / args.image
        raw = original.read_bytes()
        shutil.copyfile(original, copied)
    result['input_sha256'] = hashlib.sha256(raw).hexdigest()
    options = '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')
    assert idapro.open_database(str(copied), False, options) == 0
    opened = True
    ida_auto.auto_wait()
    if args.image != 'synthetic':
        expected = extents(raw)
        differences = []
        for start, size in expected.items():
            function = ida_funcs.get_func(start)
            if not function or function.start_ea != start or function.end_ea != start + size:
                differences.append([hex(start), size, None if not function else hex(function.end_ea)])
        result.update(symbol_extents_checked=len(expected), extent_differences=differences)
        assert not differences, differences[:8]
        # Fixed regression addresses come from the independently archived
        # original-module audit. Confirm each remains an ELF symbol end.
        merged_ends = {
            'libicui18n.so.44.1': (0x9e4bc, 0xa0e32, 0xa5844, 0xa6530, 0xc8dc8, 0x15a336, 0x1919dc),
            'libicuuc.so.44.1': (0x41472, 0xaff7c, 0xb81b0, 0xda4c8, 0xdc5f2, 0xe2756),
            'libstdc++.so.6': (0x491d2, 0x55e9e, 0x9853e, 0xac72a, 0xc4386, 0xd1eae, 0xd2506),
            'libwvcdm_shared.so': (0x2655fe, 0x2660ba, 0x271186, 0x274928, 0x274bbc, 0x2d73d0,
                                   0x2df6f4, 0x2e0754, 0x2fc2ec, 0x3139ec, 0x31c0f6),
        }[args.image]
        for end in merged_ends:
            parents = [start for start, size in expected.items() if start + size == end]
            assert parents and ida_funcs.get_func_start(end) == end, hex(end)
            assert any(x.type == ida_xref.fl_JN and any(start <= x.frm < end for start in parents)
                       for x in idautils.XrefsTo(end)), hex(end)
        result['following_function_starts_checked'] = len(merged_ends)
        result['cross_boundary_branch_references_preserved'] = True
    else:
        boundaries = ida_netnode.netnode('$ ipp.function-ends')
        assert boundaries.altval_ea(0x1040) == 0  # inside the overlapping inner extent
        assert boundaries.altval_ea(0x1050) != 0
        assert boundaries.altval_ea(0x1088) != 0
        assert boundaries.altval_ea(0x10a8) == 0  # already a declared start
        assert boundaries.altval_ea(0x10c0) == 0  # no size for this symbol
        assert boundaries.altval_ea(0x1200) == 0  # end of executable mapping
        assert ida_segment.add_segm(0, 0x70000000, 0x70004000, 'BOUNDARY_PROBES', 'CODE')
        entries = ida_netnode.netnode('$ ipp.function-symbols')
        cases = [
            ('leaf', '3000014f', 100),
            ('framed_save', '0f5e40e10842014f', 100),
            ('framed_leaf', '0f5f78fed8077ffe6017014f', 100),
            ('correlated_restore_return', '0f5f78fed8077ffe601001487ffe6017014f', 100),
            ('uncorrelated_return', '0f5f78fed8077ffe601001497ffe6017014f', 0),
            ('predicate_overwritten', '0f5f78fed8077ffe6010602093c701487ffe6017014f', 0),
            ('unbalanced_sp', '0f5f014f', 0),
            ('unknown', '60e09807014f', 0),
            ('loop_without_return', '0001', 0),
            ('outside_window', '60000407014f', 0),
            ('conditional_entry', '60008000014f', 0),
            ('raw_e_entry', 'b000014f', 0),
            ('return_state_write', '1574014f', 0),
            ('no_metadata_hint', '3000014f', 0),
            ('explicit_data', '3000014f', 0),
            ('cross_known_entry', '0f5e40e10842014f', 0),
        ]
        checks = []
        for index, (name, code, expected) in enumerate(cases):
            ea = 0x70000000 + 0x200 * index
            ida_bytes.put_bytes(ea, bytes.fromhex(code))
            if name != 'no_metadata_hint':
                boundaries.altset_ea(ea, 1)
            if name == 'explicit_data':
                assert ida_bytes.create_dword(ea, 4)
            if name == 'cross_known_entry':
                entries.altset_ea(ea + 2, 5)
            insn = ida_ua.insn_t()
            decoded = ida_ua.decode_insn(insn, ea)
            score = ida_idp._processor_t.may_be_func(insn, 1) if decoded else 0
            checks.append({'case': name, 'score': score, 'expected': expected})
            assert score == expected, checks[-1]
        result.update(overlap_and_metadata_controls=6, classifier_cases=checks)
    assert copied.read_bytes() == raw
    if original:
        assert original.read_bytes() == raw
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
