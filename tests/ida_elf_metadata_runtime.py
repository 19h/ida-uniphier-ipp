"""Check nameless and extended ELF metadata in disposable IDA databases."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--case', choices=('nameless', 'empty', 'extended'), required=True)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_segment
import ida_ua
import idc

extended = args.case == 'extended'
count = 0x10002 if extended else 5
text_index = 0x10000 if extended else 1
names_index = 0x10001 if extended else 4
raw = bytearray(0x180 + 40 * count)
raw[0x100:0x104] = bytes.fromhex('3000014f')
strings = b'\0named_fn\0'
names = b'\0.text\0.strtab\0.symtab\0.shstrtab\0'
raw[0x110:0x110 + len(strings)] = strings
raw[0x140:0x140 + len(names)] = names
ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, 0,
                 52, 0x180, 0, 52, 32, 1, 40, 0 if extended else count,
                 0xffff if extended else 0 if args.case == 'nameless' else names_index)
struct.pack_into('>8I', raw, 52, 1, 0x100, 0x1000, 0x1000, 4, 4, 5, 2)
struct.pack_into('>IIIBBH', raw, 0x130, 1, 0x1000, 4, 0x12, 0,
                 0xffff if extended else text_index)


def section(index, name, kind, flags, va, offset, size, link=0, entsize=0):
    struct.pack_into('>10I', raw, 0x180 + 40 * index,
                     name if extended else 0, kind, flags, va, offset, size, link, 0, 1, entsize)


section(text_index, 1, 1, 6, 0x1000, 0x100, 4)
section(2, 7, 3, 0, 0, 0x110, len(strings))
section(3, 15, 2, 0, 0, 0x120, 32, 2, 16)
section(names_index, 23, 3, 0, 0, 0x140, len(names) if extended else 0)
if extended:
    struct.pack_into('>II', raw, 0x180 + 20, count, names_index)
    section(1, 0, 18, 0, 0, 0x170, 8, 3, 4)
    struct.pack_into('>II', raw, 0x170, 0, text_index)

result = {'case': args.case, 'passed': False, 'version': idapro.get_library_version(),
          'input_sha256': hashlib.sha256(raw).hexdigest(), 'section_count': count,
          'function_section_index': text_index}
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-elf-metadata-')
try:
    source = Path(temp.name) / 'metadata.elf'
    source.write_bytes(raw)
    options = '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')
    assert idapro.open_database(str(source), False, options) == 0
    opened = True
    ida_auto.auto_wait()
    segment = ida_segment.segment_info_t()
    assert ida_segment.get_segment_info(segment, 0x1000, ida_segment.GSI_NAME | ida_segment.GSI_SCLASS)
    expected_name = '.text' if extended else 'IMAGE0_LOAD0'
    actual_name = idc.get_segm_name(0x1000)
    result.update(segment_name=actual_name, segment_info_name=str(segment.get_name()))
    assert actual_name == expected_name == str(segment.get_name()), (actual_name, expected_name)
    assert segment.start_ea == 0x1000 and segment.end_ea == 0x1004 and segment.get_perm() == 5
    assert str(segment.get_sclass()) == 'CODE'
    assert ida_bytes.get_bytes(0x1000, 4) == raw[0x100:0x104]
    function = ida_funcs.get_func(0x1000)
    assert function and function.start_ea == 0x1000 and function.end_ea == 0x1004
    assert ida_name.get_name(0x1000) == 'named_fn'
    insn = ida_ua.insn_t()
    assert ida_ua.decode_insn(insn, 0x1000) == 2
    operands = [idc.print_operand(0x1000, i) for i in range(3)]
    assert all(insn.ops[i].shown() for i in range(3))
    assert insn.ops[1].type == ida_ua.o_imm and insn.ops[1].value == 0
    assert operands == ['R0', '0', 'c7'], operands
    result.update(segment_name=actual_name, function_name='named_fn',
                  rendered_operands=operands)
    assert source.read_bytes() == raw
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
