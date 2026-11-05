"""Exercise relocation classes and sh_link with a generated ELF, in a scratch IDB.

The expected operations come from the supplied runtime linker investigation.
No native execution is claimed. No corpus input or user database is opened.
"""
import argparse
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_bytes
import ida_fixup
import ida_funcs
import ida_idp
import ida_nalt
import ida_segment
import ida_ua
import ida_xref
import idautils


def fixture():
    raw = bytearray(0x300)
    raw[0x100:0x104] = bytes.fromhex('014f077f')  # return; padding
    originals = {0x200c: 0x11223344, 0x2010: 0x55667788, 0x2014: 0xdeadbeef,
                 0x2018: 0xabcdef01, 0x201c: 0x99887766, 0x2020: 0x10}
    for ea, word in originals.items():
        struct.pack_into('>I', raw, 0x200 + ea - 0x2000, word)
    # name, type, flags, address, offset, size, link, info, alignment, stride
    sections = [(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)]
    names = bytearray(b'\0')

    def section(name, kind, flags, va, data, link=0, stride=0, offset=None):
        name_offset = len(names)
        names.extend(name.encode() + b'\0')
        if offset is None:
            raw.extend(b'\0' * (-len(raw) % 4))
            offset = len(raw)
            raw.extend(data)
        sections.append((name_offset, kind, flags, va, offset, len(data), link, 0, 4, stride))
        return len(sections) - 1

    section('.text', 1, 6, 0x1000, bytes(raw[0x100:0x102]), offset=0x100)
    section('.data', 1, 3, 0x2000, bytes(raw[0x200:0x300]), offset=0x200)
    strings = b'\0_probe\0defined\0external\0'
    strings_index = section('.dynstr', 3, 0, 0, strings)

    def symbol(name, value, size, info, shndx):
        return struct.pack('>IIIBBH', strings.index(name), value, size, info, 0, shndx)

    symbols = bytes(16) + symbol(b'_probe', 0x1000, 2, 0x12, 1)
    symbols += symbol(b'defined', 0x2040, 4, 0x11, 2) + symbol(b'external', 0, 4, 0x11, 0)
    symbols_index = section('.dynsym', 11, 0, 0, symbols, strings_index, 16)
    altstrings = b'\0alternate\0'
    altstrings_index = section('.altstr', 3, 0, 0, altstrings)
    altsymbols = bytes(16) + struct.pack('>IIIBBH', 1, 0x2050, 4, 0x11, 0, 2)
    altsymbols_index = section('.altsym', 2, 0, 0, altsymbols, altstrings_index, 16)
    rels = [(0x2000, 0, 179, 0x2040), (0x2004, 2, 177, 4), (0x2008, 2, 237, 8),
            (0x200c, 3, 177, 4), (0x2010, 2, 178, 0), (0x2014, 3, 176, 0),
            (0x2018, 3, 180, 0), (0x201c, 2, 255, 0)]
    data = b''.join(struct.pack('>IIi', ea, (sym << 8) | kind, addend)
                    for ea, sym, kind, addend in rels)
    section('.rela.data', 4, 0, 0, data, symbols_index, 12)
    section('.rel.data', 9, 0, 0, struct.pack('>II', 0x2020, (2 << 8) | 177), symbols_index, 8)
    section('.rela.extra', 4, 0, 0, struct.pack('>IIi', 0x2024, (1 << 8) | 177, 4), altsymbols_index, 12)
    name_offset = len(names)
    names.extend(b'.shstrtab\0')
    raw.extend(b'\0' * (-len(raw) % 4))
    strings_offset = len(raw)
    raw.extend(names)
    sections.append((name_offset, 3, 0, 0, strings_offset, len(names), 0, 0, 1, 0))
    raw.extend(b'\0' * (-len(raw) % 4))
    shoff = len(raw)
    raw.extend(b''.join(struct.pack('>10I', *s) for s in sections))
    ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
    struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 3, 0x1040, 1, 0x1000,
                     52, shoff, 0x34000, 52, 32, 2, 40, len(sections), len(sections) - 1)
    struct.pack_into('>8I', raw, 52, 1, 0x100, 0x1000, 0x1000, 4, 4, 5, 4)
    struct.pack_into('>8I', raw, 84, 1, 0x200, 0x2000, 0x2000, 0x100, 0x100, 6, 4)
    return raw, originals


opened = False
result = {'version': idapro.get_library_version()}
temp = tempfile.TemporaryDirectory(prefix='ipp-loader-test-')
try:
    raw, originals = fixture()
    source = Path(temp.name) / 'relocations.elf'
    source.write_bytes(raw)
    extra = os.environ.get('IPP_IDA_ARGS', '')
    assert idapro.open_database(str(source), False, extra) == 0
    opened = True
    ida_auto.auto_wait()
    expected = {0x2000: 0x2040, 0x2004: 0x2044, 0x2008: 0x2048,
                0x2020: 0x2050, 0x2024: 0x2054}
    for ea, word in expected.items():
        assert ida_bytes.get_dword(ea) == word, hex(ea)
        fixup = ida_fixup.fixup_data_t()
        assert ida_fixup.get_fixup(fixup, ea) and fixup.get_type() == ida_fixup.FIXUP_OFF32
    for ea, word in originals.items():
        if ea in expected:
            continue
        assert ida_bytes.get_dword(ea) == word, hex(ea)
        assert not ida_fixup.get_fixup(ida_fixup.fixup_data_t(), ea), hex(ea)
        assert ida_bytes.get_cmt(ea, True), hex(ea)
    imported = {}
    for i in range(ida_nalt.get_import_module_qty()):
        ida_nalt.enum_import_names(i, lambda ea, name, ordinal: imported.__setitem__(ea, name) or True)
    assert imported == {0x200c: 'external', 0x2010: 'defined', 0x2014: 'external'}, imported
    assert ida_funcs.get_func_start(0x1000) == 0x1000
    # Zero is a valid mapped target. The explicit has_target/operand kind
    # distinguishes it from an unresolved address; BADADDR is the SDK sentinel.
    assert not ida_bytes.is_mapped(0)
    assert ida_segment.add_segm(0, 0, 0x100, 'ZERO_TARGET', 'CODE')
    assert ida_segment.add_segm(0, 0x3000, 0x3100, 'XREF_TEST', 'CODE')
    ida_bytes.put_bytes(0, bytes.fromhex('014f'))
    assert ida_ua.create_insn(0) == 2

    def branch_word(ea, target, call=False, predicate=7):
        assert (target - ea) % 2 == 0
        displacement = ((target - ea) // 2) & 0x7ffff
        return ((0x68000000 if call else 0x60000000) | predicate
                | ((displacement >> 16) & 7) << 24
                | ((displacement >> 11) & 31) << 16
                | (displacement & 0x7ff) << 3)

    zero_cases = [(0x3000, branch_word(0x3000, 0), 'br', ida_xref.fl_JN),
                  (0x3004, branch_word(0x3004, 0, call=True), 'brl', ida_xref.fl_CN),
                  (0x3008, branch_word(0x3008, 0, predicate=0), 'br', ida_xref.fl_JN),
                  (0x20, 0x60607007 | ((-0x20 // 2) & 255) << 3, 'setlr', ida_xref.dr_O),
                  (0x40, 0x60707007 | ((-0x40 // 2) & 255) << 3, 'settar', ida_xref.dr_O)]
    far_pc = 0x3084
    far_displacement = (-far_pc) & 0xffffffff
    upper = far_displacement >> 16
    half = (far_displacement & 0xffff) >> 1
    high_word = 0x77000007 | ((upper >> 11) & 31) << 16 | (upper & 0x7ff) << 3
    low_word = 0x76000007 | ((half >> 11) & 15) << 16 | (half & 0x7ff) << 3
    ida_bytes.put_bytes(far_pc - 4, high_word.to_bytes(4, 'big'))
    assert ida_ua.create_insn(far_pc - 4) == 4
    zero_cases.append((far_pc, low_word, 'brl', ida_xref.fl_CN))
    checked = []
    for ea, word, mnemonic, kind in zero_cases:
        ida_bytes.put_bytes(ea, word.to_bytes(4, 'big'))
        ins = ida_ua.insn_t()
        assert ida_ua.decode_insn(ins, ea) == 4
        assert ida_ua.create_insn(ea) == 4
        assert ins.get_canon_mnem() == mnemonic
        assert any(op.type == ida_ua.o_near and op.addr == 0 for op in ins.ops)
        assert ida_idp._processor_t.emu_insn(ins) == 1
        refs = list(idautils.XrefsFrom(ea))
        assert any(x.to == 0 and x.type == kind for x in refs), (hex(ea), mnemonic, [(x.to, x.type) for x in refs])
        if mnemonic == 'brl' or ea == 0x3008:
            assert any(x.to == ea + 4 and x.type == ida_xref.fl_F for x in refs)
        checked.append({'ea': hex(ea), 'mnemonic': mnemonic, 'target': 0, 'xref_type': kind})
    assert not ida_bytes.is_mapped(0x5000)
    ea = 0x3040
    ida_bytes.put_bytes(ea, branch_word(ea, 0x5000).to_bytes(4, 'big'))
    ins = ida_ua.insn_t()
    assert ida_ua.decode_insn(ins, ea) == 4 and ida_ua.create_insn(ea) == 4
    assert ida_idp._processor_t.emu_insn(ins) == 1
    assert not any(x.to == 0x5000 for x in idautils.XrefsFrom(ea))
    result['zero_address_reference_cases'] = checked
    result['unmapped_target_reference_suppressed'] = True
    assert source.read_bytes() == raw
    result.update(passed=True, applied_words=len(expected), pending_words=5,
                  import_slots=len(imported), separate_symbol_table_resolved=True)
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
