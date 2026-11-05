"""Check compact 1..16 shifts and wide 0..31 shifts in a disposable IDB."""
import argparse
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_idp
import ida_lines
import ida_ua
import idc

cases = []
for right in range(2):
    for e in range(2):
        for reg in range(16):
            for field in range(16):
                cases.append((2, 0x10a0 | (right << 4) | (e << 15) | (reg << 8) | field,
                              right, e, reg, field or 16, 7))
        for pred in range(8):
            for count in range(32):
                cases.append((4, 0x60602800 | (right << 9) | (e << 31) | (count << 3) | pred,
                              right, e, 0, count, pred))
code = b''.join(word.to_bytes(size, 'big') for size, word, *_ in cases)
raw = bytearray(0x100) + code
ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
struct.pack_into('>8I', raw, 52, 1, 0x100, 0x1000, 0x1000, len(code), len(code), 5, 2)
result = dict(passed=False, version=idapro.get_library_version(), compact_cases=0, wide_cases=0, rendered={})
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-shifts-')
try:
    path = Path(temp.name) / 'shifts.elf'
    path.write_bytes(raw)
    assert idapro.open_database(str(path), False, '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')) == 0
    opened = True
    ea = 0x1000
    for size, word, right, e, reg, count, pred in cases:
        ins = ida_ua.insn_t()
        assert ida_ua.decode_insn(ins, ea) == size, hex(word)
        assert ins.get_canon_mnem() == ('asr' if right else 'asl')
        assert bool(ins.auxpref & 1) == bool(e)
        assert ins.ops[0].type == ida_ua.o_reg and ins.ops[0].reg == ida_idp.str2reg('R' + str(reg))
        index = 1 if size == 2 else 2
        assert ins.ops[index].type == ida_ua.o_imm and ins.ops[index].value == count
        assert ins.ops[index + 1].reg == ida_idp.str2reg('C' + str(pred))
        assert all(op.shown() for op in ins.ops if op.type != ida_ua.o_void)
        if not e and reg == 0 and pred == 7 and count in (0, 1, 16, 31):
            assert ida_ua.create_insn(ea) == size
            line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
            assert int(idc.print_operand(ea, index), 0) == count, line
            result['rendered'][hex(word)] = line
        result['compact_cases' if size == 2 else 'wide_cases'] += 1
        ea += size
    assert result['compact_cases'] == result['wide_cases'] == 1024
    assert path.read_bytes() == raw
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
