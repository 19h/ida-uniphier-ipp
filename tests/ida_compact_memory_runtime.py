"""Check corrected compact halfword forms and withdrawn external candidates."""
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
import ida_ua
import ida_lines
import idc

cases = [(p, a, b, e) for p in (0x5000, 0x5010, 0x5040, 0x5050, 0x4080, 0x4090)
         for a in range(16) for b in range(16) for e in range(2)]
code = b''.join((p | (a << 8) | b | (e << 15)).to_bytes(2, 'big') for p, a, b, e in cases)
raw = bytearray(0x100) + code
ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
struct.pack_into('>8I', raw, 52, 1, 0x100, 0x1000, 0x1000, len(code), len(code), 5, 2)
result = dict(passed=False, version=idapro.get_library_version(), accepted=0, withdrawn=0, rendered={})
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-compact-memory-')
try:
    path = Path(temp.name) / 'compact.elf'
    path.write_bytes(raw)
    assert idapro.open_database(str(path), False, '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')) == 0
    opened = True
    for i, (pattern, base, data, e) in enumerate(cases):
        ea = 0x1000 + 2*i
        ins = ida_ua.insn_t()
        size = ida_ua.decode_insn(ins, ea)
        if pattern in (0x4080, 0x4090):
            assert size == 0, (hex(ea), hex(pattern), size)
            result['withdrawn'] += 1
            continue
        store, post = bool(pattern & 0x10), bool(pattern & 0x40)
        assert size == 2 and bool(ins.auxpref & 1) == bool(e)
        assert ins.get_canon_mnem() == ('sth' if store else 'ldh')
        mem, reg = (ins.ops[0], ins.ops[1]) if store else (ins.ops[1], ins.ops[0])
        assert mem.type == ida_ua.o_displ and mem.dtype == ida_ua.dt_word
        assert mem.phrase == ida_idp.str2reg('R' + str(base))
        assert mem.addr == 0 and mem.specval == (2 if post else 0)
        assert bool(mem.specflag1 & 1) == post
        assert reg.type == ida_ua.o_reg and reg.reg == ida_idp.str2reg('R' + str(data))
        assert all(op.shown() for op in ins.ops if op.type != ida_ua.o_void)
        if base == 3 and data == 5 and not e:
            assert ida_ua.create_insn(ea) == 2
            line = ida_lines.tag_remove(idc.generate_disasm_line(ea, 0))
            assert ('sth' if store else 'ldh') in line and 'R3' in line and 'R5' in line, line
            result['rendered'][hex(pattern)] = line
        result['accepted'] += 1
    assert result['accepted'] == 2048 and result['withdrawn'] == 1024
    assert path.read_bytes() == raw
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
