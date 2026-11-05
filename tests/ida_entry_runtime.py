"""Verify program-entry metadata with mapped-zero and invalid-entry controls."""
import argparse
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--case', choices=('normal', 'zero', 'unmapped', 'nonexec'), required=True)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_entry
import ida_ida
import ida_idaapi
import ida_segment

va = 0 if args.case == 'zero' else 0x1000
entry = 0x5000 if args.case == 'unmapped' else va
executable = args.case != 'nonexec'
valid = args.case == 'normal'  # ELF e_entry=0 means no program entry
raw = bytearray(0x200)
raw[0x100:0x104] = bytes.fromhex('014f077f')
names = b'\0.text\0.shstrtab\0'
raw[0x104:0x104 + len(names)] = names
ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, entry,
                 52, 0x180, 0, 52, 32, 1, 40, 3, 2)
struct.pack_into('>8I', raw, 52, 1, 0x100, va, va, 4, 4, 5 if executable else 6, 4)
struct.pack_into('>10I', raw, 0x1a8, 1, 1, 6 if executable else 3, va, 0x100, 4, 0, 0, 2, 0)
struct.pack_into('>10I', raw, 0x1d0, 7, 3, 0, 0, 0x104, len(names), 0, 0, 1, 0)
result = {'case': args.case, 'passed': False, 'expected_entry': entry,
          'entry_valid': valid, 'version': idapro.get_library_version()}
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-entry-test-')
try:
    source = Path(temp.name) / 'entry.elf'
    source.write_bytes(raw)
    options = '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')
    assert idapro.open_database(str(source), False, options) == 0
    opened = True
    ida_auto.auto_wait()
    actual_entry = ida_ida.inf_get_start_ea()
    actual_ip = ida_ida.inf_get_start_ip()
    actual_cs = ida_ida.inf_get_start_cs()
    entries = [ida_entry.get_entry(ida_entry.get_entry_ordinal(i))
               for i in range(ida_entry.get_entry_qty())]
    result.update(start_ea=hex(actual_entry), start_ip=hex(actual_ip), start_cs=actual_cs,
                  entry_list=[hex(ea) for ea in entries])
    if valid:
        segment = ida_segment.segment_info_t()
        assert ida_segment.get_segment_info(segment, entry)
        assert entry in entries, result
        assert actual_entry == entry and actual_ip == entry and actual_cs == segment.get_sel(), result
    else:
        assert entry not in entries
        assert actual_entry == ida_idaapi.BADADDR and actual_ip == ida_idaapi.BADADDR, result
    assert source.read_bytes() == raw
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
