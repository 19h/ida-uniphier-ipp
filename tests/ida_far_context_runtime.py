"""Check far-call context entries and reference ownership in a disposable IDB."""
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
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import ida_ua
import ida_xref
import idautils
import idc


def instruction(ea, length=4):
    assert ida_ua.create_insn(ea) == length, hex(ea)
    ins = ida_ua.insn_t()
    assert ida_ua.decode_insn(ins, ea) == length
    return ins


def pair(ea, target):
    displacement = (target - (ea + 4)) & 0xffffffff
    assert displacement & 1 == 0
    upper, lower = displacement >> 16, (displacement & 0xffff) >> 1
    high = 0x77000007 | ((upper >> 11) << 16) | ((upper & 0x7ff) << 3)
    call = 0x76000007 | ((lower >> 11) << 16) | ((lower & 0x7ff) << 3)
    return high.to_bytes(4, 'big'), call.to_bytes(4, 'big')


def branch(ea, target):
    half = ((target - ea) // 2) & 0x7ffff
    word = 0x60000007 | ((half >> 16) << 24) | (((half >> 11) & 31) << 16) | ((half & 0x7ff) << 3)
    ida_bytes.put_bytes(ea, word.to_bytes(4, 'big'))
    ins = instruction(ea)
    assert ida_idp._processor_t.emu_insn(ins) == 1
    assert any(x.to == target and x.type == ida_xref.fl_JN for x in idautils.XrefsFrom(ea))


def check(ea, target, resolved, reference=None):
    if reference is None:
        reference = resolved
    ins = ida_ua.insn_t()
    assert ida_ua.decode_insn(ins, ea) == 4
    assert ins.get_canon_mnem() == 'brl' and ins.ops[0].reg == ida_idp.str2reg('LR')
    assert ins.ops[1].type == (ida_ua.o_near if resolved else ida_ua.o_imm), (hex(ea), ins.ops[1].type)
    assert all(o.shown() for o in ins.ops if o.type != ida_ua.o_void)
    assert ida_idp._processor_t.emu_insn(ins) == 1
    refs = [x.to for x in idautils.XrefsFrom(ea) if x.type == ida_xref.fl_CN]
    assert (target in refs) == reference, (hex(ea), refs, hex(target), reference)
    if resolved:
        assert ins.ops[1].addr == target
    return dict(ea=hex(ea), target=hex(target), resolved=resolved, reference=target in refs,
                line=idc.generate_disasm_line(ea, 0))


result = dict(passed=False, version=idapro.get_library_version())
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-far-context-')
try:
    raw = bytearray(0x104)
    ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
    struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, 0, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    struct.pack_into('>8I', raw, 52, 1, 0x100, 0x1000, 0x1000, 4, 4, 5, 2)
    raw[0x100:] = bytes.fromhex('3000014f')
    path = Path(temp.name) / 'far-context.elf'
    path.write_bytes(raw)
    assert idapro.open_database(str(path), False, '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')) == 0
    opened = True
    for start, end, name in ((0, 0x100, 'ZERO'), (0x6000, 0x7000, 'INCOMING'),
                             (0x7000, 0x7100, 'CALLEES'), (0x8000, 0x9000, 'DEFINITIONS')):
        assert ida_segment.add_segm(0, start, end, name, 'CODE')
    for ea in (0, 0x7000, 0x7002):
        ida_bytes.put_bytes(ea, bytes.fromhex('014f'))
        instruction(ea, 2)
    cases = [
        ('ordinary', {}), ('mapped_zero', {'target': 0}),
        ('entry_call', {'entry': 4}), ('entry_tail', {'entry': 2}),
        ('function_entry_call', {'function': 4}),
        ('user_reference', {'entry': 4, 'user': True}),
        ('explicit_data', {'data': True}), ('E_definition', {'e': True}),
        ('self_entry_call', {'self': 4}), ('self_entry_tail', {'self': 2}),
        ('entry_before_definition', {'function': 0}),
        ('unmapped_target', {'target': 0x90000000}),
    ]
    checked = []
    for index, (name, policy) in enumerate(cases):
        ea = 0x8000 + index * 0x100
        target = ea + policy['self'] if 'self' in policy else policy.get('target', 0x7000)
        high, call = pair(ea, target)
        if policy.get('e'):
            high = bytes([high[0] | 0x80]) + high[1:]
        ida_bytes.put_bytes(ea, high + call)
        if policy.get('data'):
            assert ida_bytes.create_dword(ea, 4)
        else:
            instruction(ea)
        instruction(ea + 4)
        if policy.get('user'):
            assert ida_xref.add_cref(ea + 4, target, ida_xref.fl_CN | ida_xref.XREF_USER)
        if 'entry' in policy:
            branch(0x6000 + 4 * index, ea + policy['entry'])
        if 'function' in policy:
            assert ida_funcs.add_func(ea + policy['function'], ea + 8)
        resolved = not any(k in policy for k in ('entry', 'data', 'e', 'self')) and policy.get('function') != 4
        reference = bool(policy.get('user')) or (resolved and ida_bytes.is_mapped(target))
        checked.append(dict(case=name, **check(ea + 4, target, resolved, reference)))
    result['cases'] = checked
    lifecycle = []
    ea = 0x8d00
    high, call = pair(ea, 0x7000)
    ida_bytes.put_bytes(ea, high + call)
    instruction(ea); instruction(ea + 4)
    lifecycle.append(check(ea + 4, 0x7000, True))
    branch(0x6300, ea + 2)
    lifecycle.append(check(ea + 4, 0x7000, False))
    ida_xref.del_cref(0x6300, ea + 2, False)
    assert not any(x.to == ea + 2 and x.iscode for x in idautils.XrefsFrom(0x6300))
    lifecycle.append(check(ea + 4, 0x7000, True))
    high, call = pair(ea, 0x7002)
    ida_bytes.put_bytes(ea, high + call)
    lifecycle.append(check(ea + 4, 0x7002, True))
    assert not any(x.to == 0x7000 and x.type == ida_xref.fl_CN for x in idautils.XrefsFrom(ea + 4))
    stale = ida_ua.insn_t()
    assert ida_ua.decode_insn(stale, ea + 4) == 4
    ida_bytes.put_bytes(ea + 4, bytes.fromhex('ffffffff'))
    invalid = ida_ua.insn_t()
    assert ida_ua.decode_insn(invalid, ea + 4) == 0
    assert ida_idp._processor_t.emu_insn(stale) == -1
    assert not any(x.type == ida_xref.fl_CN for x in idautils.XrefsFrom(ea + 4))
    ea = 0x8e00
    high, call = pair(ea, 0)
    ida_bytes.put_bytes(ea, high + call)
    instruction(ea); instruction(ea + 4)
    lifecycle.append(check(ea + 4, 0, True))
    ida_bytes.put_bytes(ea, bytes.fromhex('60007f87'))
    lifecycle.append(check(ea + 4, 0, False))
    result.update(lifecycle=lifecycle, unknown_call_reference_removed=True, passed=True)
    idapro.close_database(False)
    opened = False
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
assert result['passed']
