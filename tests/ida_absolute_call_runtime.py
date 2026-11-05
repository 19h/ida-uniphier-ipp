"""Validate constant LR calls in disposable synthetic/raw-derived IDBs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--case', choices=('boot', 'synthetic'), required=True)
p.add_argument('--source', type=Path)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if args.case == 'boot' and args.source is None:
    p.error('--case boot requires --source')
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_bytes
import ida_funcs
import ida_idp
import ida_segment
import ida_ua
import ida_xref
import idautils
import idc


def carrier(payload, base):
    # Explicit analysis carrier, no fabricated symbols/entry or ISA assertion.
    raw = bytearray(0x100) + payload
    ident = b'\x7fELF\x01\x02\x01\x09' + bytes(8)
    struct.pack_into('>16sHHIIIIIHHHHHH', raw, 0, ident, 2, 0x1040, 1, 0,
                     52, 0, 0, 52, 32, 1, 0, 0, 0)
    struct.pack_into('>8I', raw, 52, 1, 0x100, base, base, len(payload), len(payload), 5, 2)
    return raw


def immediate(value, reg=0, high=False, predicate=7):
    value &= 0xffff
    return ((0x6000c000 if high else 0x60008000) | (reg << 24)
            | ((value >> 11) << 16) | ((value & 0x7ff) << 3) | predicate).to_bytes(4, 'big')


def sequence(value, reg=0, narrow=False, wide_copy=False, call_predicate=7):
    low = bytes.fromhex('3000') if narrow else immediate(value, reg)
    high = immediate(value >> 16, reg, high=True)
    copy = ((0x61007f0f | (reg << 16)).to_bytes(4, 'big')
            if wide_copy or reg >= 16 else (0x1570 | reg).to_bytes(2, 'big'))
    return [low, high, copy, (0x58 | call_predicate).to_bytes(2, 'big')]


def make_instruction(ea, expected_length):
    length = ida_ua.create_insn(ea)
    assert length == expected_length, (hex(ea), length, hex(ida_bytes.get_item_head(ea)), hex(ida_bytes.get_flags(ea)))
    ins = ida_ua.insn_t()
    assert ida_ua.decode_insn(ins, ea) == expected_length
    return ins


def check_call(ea, target, expected_reference, expected_comment=True):
    ins = ida_ua.insn_t()
    assert ida_ua.decode_insn(ins, ea) == 2
    assert ins.get_canon_mnem() == 'jmpl'
    assert ins.ops[0].type == ida_ua.o_reg and idc.print_operand(ea, 0) == 'LR'
    assert ins.ops[0].shown() and ins.ops[1].shown()
    assert ida_idp._processor_t.emu_insn(ins) == 1
    refs = [x.to for x in idautils.XrefsFrom(ea) if x.type == ida_xref.fl_CN]
    assert (target in refs) == expected_reference, (hex(ea), hex(target), refs)
    line = idc.generate_disasm_line(ea, 0)
    assert ('target=' in line) == expected_comment, (hex(ea), line)
    return {'ea': hex(ea), 'target': hex(target), 'reference': target in refs, 'line': line}


result = {'case': args.case, 'passed': False, 'version': idapro.get_library_version()}
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-absolute-call-')
original = args.source.read_bytes() if args.case == 'boot' else None
try:
    if args.case == 'boot':
        assert len(original) == 21256
        normalized = b''.join(original[i:i + 4][::-1] for i in range(0, len(original), 4))
        payload, base = normalized, 0x80000000
        result.update(input_sha256=hashlib.sha256(original).hexdigest(),
                      normalized_sha256=hashlib.sha256(payload).hexdigest(),
                      mapping_scope='Explicit inferred-base analysis carrier; native base/permissions unproved')
    else:
        payload, base = bytes.fromhex('3000014f'), 0x1000
    raw = carrier(payload, base)
    path = Path(temp.name) / 'analysis-carrier.elf'
    path.write_bytes(raw)
    options = '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')
    assert idapro.open_database(str(path), False, options) == 0
    opened = True
    # Deliberately inspect selected raw sequences without classifying the
    # entire code/data mixture through automatic analysis.
    assert ida_bytes.get_bytes(base, len(payload)) == payload
    checked = []
    if args.case == 'boot':
        # Independently recorded original-image locations, not production rules.
        sites = [(0x498, 0x4a2, 0x800004b8), (0xd78, 0xd82, 0x8000436c),
                 (0xda8, 0xdb2, 0x8000108c), (0xdb4, 0xdbe, 0x800010be),
                 (0xdc0, 0xdca, 0x80001002), (0xdde, 0xde8, 0x800043ac)]
        for start, call, target in sites:
            for offset, length in ((start, 4), (start + 4, 4), (start + 8, 2), (call, 2)):
                make_instruction(base + offset, length)
            checked.append(check_call(base + call, target, True))
        ins = ida_ua.insn_t()
        assert ida_ua.decode_insn(ins, base + 0x436c) == 0  # unresolved frontier stays unresolved
        assert ida_bytes.get_bytes(base, len(payload)) == payload
        result.update(checked_calls=checked, unresolved_target_instruction_preserved=True)
    else:
        for start, end, name in ((0, 0x100, 'ZERO'), (0x3000, 0x6000, 'DEFINITIONS'),
                                 (0x6000, 0x7000, 'INCOMING'), (0x7000, 0x7100, 'CALLEES')):
            assert ida_segment.add_segm(0, start, end, name, 'CODE')
        ida_bytes.put_bytes(0, bytes.fromhex('014f'))
        ida_bytes.put_bytes(0x7000, bytes.fromhex('014f'))
        make_instruction(0, 2); make_instruction(0x7000, 2)
        cases = [
            ('ordinary', {}), ('mapped_zero', {'target': 0}),
            ('upper_gpr', {'reg': 23}), ('narrow_low', {'target': 0, 'narrow': True}),
            ('conditional_call', {'call_predicate': 0}),
            ('entry_high', {'entry': 1}), ('entry_copy', {'entry': 2}), ('entry_call', {'entry': 3}),
            ('entry_preserves_user_reference', {'entry': 1, 'user_reference': True}),
            ('function_entry', {'function': 2}),
            ('E_low', {'e': 0}), ('E_high', {'e': 1}), ('E_copy', {'e': 2}), ('E_call', {'e': 3}),
            ('conditional_low', {'predicate': 0}), ('conditional_high', {'predicate': 1}),
            ('conditional_copy', {'predicate': 2, 'wide_copy': True}),
            ('unknown_gap', {'gap': True}), ('overwritten_source', {'overwrite': True}),
            ('explicit_data', {'data': 0}), ('unmapped_target', {'target': 0x90000000}),
            ('self_entry_high', {'self_entry': 4}), ('self_entry_copy', {'self_entry': 8}),
            ('self_entry_call', {'self_entry': 10}),
            ('entry_low_tail', {'entry_offset': 2}),
            ('entry_high_tail', {'entry_offset': 6}),
            ('entry_copy_tail', {'entry_offset': 10, 'wide_copy': True}),
            ('self_entry_low_tail', {'self_entry': 2}),
            ('self_entry_high_tail', {'self_entry': 6}),
            ('self_entry_copy_tail', {'self_entry': 10, 'wide_copy': True}),
        ]
        for index, (name, policy) in enumerate(cases):
            ea = 0x3000 + index * 0x100
            target = ea + policy['self_entry'] if 'self_entry' in policy else policy.get('target', 0x7000)
            parts = sequence(target, policy.get('reg', 0), policy.get('narrow', False),
                             policy.get('wide_copy', False), policy.get('call_predicate', 7))
            if 'e' in policy:
                j = policy['e']; v = bytearray(parts[j]); v[0] |= 0x80; parts[j] = bytes(v)
            if 'predicate' in policy:
                j = policy['predicate']; v = bytearray(parts[j]); v[-1] &= 0xf8; parts[j] = bytes(v)
            offsets, cursor = [], ea
            for j, part in enumerate(parts):
                offsets.append(cursor); ida_bytes.put_bytes(cursor, part); cursor += len(part)
                if j == 1 and (policy.get('gap') or policy.get('overwrite')):
                    gap = bytes.fromhex('60007f87') if policy.get('gap') else bytes.fromhex('3001')
                    ida_bytes.put_bytes(cursor, gap); cursor += len(gap)
            if 'data' in policy:
                assert ida_bytes.create_dword(offsets[policy['data']], 4)
            for j in range(4):
                if policy.get('data') != j: make_instruction(offsets[j], len(parts[j]))
            if policy.get('user_reference'):
                assert ida_xref.add_cref(offsets[3], target, ida_xref.fl_CN | ida_xref.XREF_USER)
            if 'entry' in policy or 'entry_offset' in policy:
                edge = 0x6000 + index * 4
                destination = ea + policy['entry_offset'] if 'entry_offset' in policy else offsets[policy['entry']]
                displacement = ((destination - edge) // 2) & 0x7ffff
                word = (0x60000007 | ((displacement >> 16) & 7) << 24
                        | ((displacement >> 11) & 31) << 16 | (displacement & 0x7ff) << 3)
                ida_bytes.put_bytes(edge, word.to_bytes(4, 'big'))
                branch = make_instruction(edge, 4)
                assert ida_idp._processor_t.emu_insn(branch) == 1
                assert any(x.to == destination and x.type == ida_xref.fl_JN for x in idautils.XrefsFrom(edge))
            if 'function' in policy:
                assert ida_funcs.add_func(offsets[policy['function']], cursor)
            resolved = not any(key in policy for key in ('entry', 'entry_offset', 'function', 'e', 'predicate', 'gap', 'overwrite', 'data', 'self_entry'))
            expected_reference = policy.get('user_reference', False) or (resolved and ida_bytes.is_mapped(target))
            row = check_call(offsets[3], target, expected_reference, resolved)
            row['case'] = name; checked.append(row)
        result['synthetic_cases'] = checked
        lifecycle = []
        for ea in (0x5600, 0x5800):
            parts = sequence(0x7000)
            cursor = ea
            for part in parts:
                ida_bytes.put_bytes(cursor, part); make_instruction(cursor, len(part)); cursor += len(part)
            lifecycle.append(check_call(cursor - 2, 0x7000, True))
        ida_bytes.put_bytes(0x5600, immediate(0x7002))
        lifecycle.append(check_call(0x560a, 0x7002, True))
        assert not any(x.to == 0x7000 and x.type == ida_xref.fl_CN for x in idautils.XrefsFrom(0x560a))
        for ea, target in ((0x5900, 0), (0x5a00, 0x7000)):
            cursor = ea
            for part in sequence(target):
                ida_bytes.put_bytes(cursor, part); make_instruction(cursor, len(part)); cursor += len(part)
            lifecycle.append(check_call(cursor - 2, target, True))
        ida_bytes.put_bytes(0x5904, bytes.fromhex('60007f87'))
        lifecycle.append(check_call(0x590a, 0, False, False))
        stale = ida_ua.insn_t()
        assert ida_ua.decode_insn(stale, 0x5a0a) == 2
        ida_bytes.put_bytes(0x5a0a, bytes.fromhex('0060'))
        assert ida_idp._processor_t.emu_insn(stale) == -1
        assert not any(x.to == 0x7000 and x.type == ida_xref.fl_CN for x in idautils.XrefsFrom(0x5a0a))
        result['invalidated_instruction_reference_removed'] = True
        delta = 0x10000000
        # The module explicitly advertises PR_NO_SEGMOVE. A rejected move
        # must retain its reference state; successful rebasing is unsupported.
        rebase_rc = ida_segment.rebase_program(delta, ida_segment.MSF_NOFIX | ida_segment.MSF_SILENT)
        result['rebase_rc'] = rebase_rc
        result['successful_rebase_supported'] = False
        assert rebase_rc == ida_segment.MOVE_SEGM_IDP, rebase_rc
        assert ida_bytes.get_bytes(0x5800, 12) == b''.join(sequence(0x7000))
        assert not ida_bytes.is_mapped(delta + 0x5800)
        lifecycle.append(check_call(0x580a, 0x7000, True))
        result['reference_lifecycle'] = lifecycle
    assert path.read_bytes() == raw
    if args.case == 'boot':
        assert args.source.read_bytes() == original
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps(result, indent=2))
