"""Integration assertions against a new, disposable IDA database.

Requires an isolated IDAUSR containing the modules being tested and an
already accepted local license. IPP_IDA_ARGS supplies installation-specific
license options; IPP_IDALIB_PYTHON can locate the idapro package. This script
never opens a database beside the original sample or saves its scratch IDB.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--corpus', type=Path, required=True)
p.add_argument('--image', choices=('libc.so.7', 'acodec'), required=True)
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_bitrange
import ida_bytes
import ida_fixup
import ida_funcs
import ida_ida
import ida_idp
import ida_lines
import ida_name
import ida_nalt
import ida_pro
import ida_regfinder
import ida_segment
import ida_ua
import idautils


def elf(path):
    raw = path.read_bytes()
    shoff = struct.unpack_from('>I', raw, 32)[0]
    stride, count, strings_index = struct.unpack_from('>HHH', raw, 46)
    sections = [struct.unpack_from('>10I', raw, shoff + i * stride) for i in range(count)]
    st = sections[strings_index]
    names = raw[st[4]:st[4] + st[5]]
    by_name = {names[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}
    symbols = []
    for s in sections:
        if s[1] not in (2, 11):
            continue
        st = sections[s[6]]
        strings = raw[st[4]:st[4] + st[5]]
        for off in range(s[4], s[4] + s[5], s[9]):
            name, value, size, info, _, index = struct.unpack_from('>IIIBBH', raw, off)
            symbols.append((strings[name:].split(b'\0', 1)[0].decode(), value, size, info, index))
    return raw, by_name, symbols


def instruction(ea):
    ins = ida_ua.insn_t()
    assert ida_ua.decode_insn(ins, ea), hex(ea)
    assert ida_ua.create_insn(ea), hex(ea)
    assert ida_idp._processor_t.emu_insn(ins) == 1
    assert all(op.shown() for op in ins.ops if op.type != ida_ua.o_void), hex(ea)
    return ins


source = args.corpus / args.image
original_digest = hashlib.sha256(source.read_bytes()).hexdigest()
result = {'image': args.image, 'version': idapro.get_library_version()}
class AuditHooks(ida_idp.IDB_Hooks):
    def func_deleted(self, ea):
        if ea == 0x31e68:
            result.setdefault('focus_deletions', []).append({'ea': hex(ea), 'state': ida_auto.get_auto_state()})
        return 0

hooks = AuditHooks()
hooks.hook()
opened = False
temp = tempfile.TemporaryDirectory(prefix='ipp-ida-test-')
try:
    copied = Path(temp.name) / args.image
    shutil.copy2(source, copied)
    options = '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')
    if args.image == 'acodec':
        paths = ';'.join(str((args.corpus / n).resolve()) for n in ('lib.so', 'libg.so'))
        options += ' -Oelfipp:companions=' + paths
    assert idapro.open_database(str(copied), False, options) == 0
    opened = True
    result['focus_before_auto'] = {'function': hex(ida_funcs.get_func_start(0x31e68)), 'flags': int(ida_bytes.get_flags(0x31e68))} if args.image == 'libc.so.7' else None
    assert ida_ida.inf_get_procname() == 'ipp' and ida_ida.inf_is_be()
    elf_entry = struct.unpack_from('>I', source.read_bytes(), 24)[0]
    entry_segment = ida_segment.segment_info_t()
    assert ida_segment.get_segment_info(entry_segment, elf_entry)
    assert ida_ida.inf_get_start_ea() == ida_ida.inf_get_start_ip() == elf_entry
    assert ida_ida.inf_get_start_cs() == entry_segment.get_sel()
    result['entry_metadata'] = {'ea': hex(elf_entry), 'ip': hex(ida_ida.inf_get_start_ip()),
                                'cs': ida_ida.inf_get_start_cs()}
    assert ida_idp.str2reg('SP') == ida_idp.str2reg('R31') == 31
    assert ida_idp.str2reg('GP') == ida_idp.str2reg('R30') == 30
    assert all(n in ida_idp.ph_get_regnames() for n in ('R16', 'R31', 'SVR', 'C0', 'M1', 'FPCR'))
    alias_checks = [('C0', 'CFR', 0, 1), ('CFR0', 'CFR', 24, 8), ('CFR3', 'CFR', 0, 8),
                    ('VC2', 'CFR', 18, 1), ('CAS', 'CFR', 8, 1), ('MH1', 'M1', 32, 32),
                    ('FS2', 'XD1', 32, 32), ('FS3', 'XD1', 0, 32), ('FD2', 'XD1', 0, 64)]
    alias_checks += [('FD' + str(i), 'XD' + str(16 + i // 2), 0, 64) for i in range(1, 32, 2)]
    for name, parent, offset, count in alias_checks:
        span = ida_bitrange.bitrange_t()
        assert ida_idp.get_reg_info(name, span) == parent, name
        assert span.bitoff() == offset and span.bitsize() == count, name
    result['register_alias_checks'] = len(alias_checks)
    if args.image == 'acodec':
        rendered_examples = {}
        for ea, expected in ((0x08000022, 'add SP,-0x18,c7'),
                             (0x08000024, None),
                             (0x08000026, 'mov R13,R1,c7')):
            probe = instruction(ea)
            assert all(op.shown() for op in probe.ops if op.type != ida_ua.o_void)
            line = ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or '')
            rendered_examples[hex(ea)] = line
            compact = ''.join(line.split())
            if expected:
                assert compact.lower() == ''.join(expected.split()).lower(), (hex(ea), line)
            else:
                assert compact.startswith('stp(SP,') and compact.endswith('),R12:R13,c7'), line
                assert probe.ops[0].addr == 8
        result['rendered_operand_examples'] = rendered_examples
        ins = instruction(0x08000042)
        assert ins.get_canon_mnem() == 'brl' and ins.ops[1].type == ida_ua.o_near
        assert ins.ops[1].addr == 0x38024f3c
        assert any(x.to == 0x38024f3c and x.type == 17 for x in idautils.XrefsFrom(ins.ea))
        assert ida_bytes.is_mapped(0x38024f3c) and ida_bytes.is_mapped(0x3a000000)
        result['cross_image_call'] = {'source': hex(ins.ea), 'target': hex(ins.ops[1].addr)}
    else:
        ins = instruction(0x1fed0)
        assert ins.get_canon_mnem() == 'add' and ins.ops[0].type == ida_ua.o_reg
        assert ins.ops[0].reg == 31 and ins.ops[1].type == ida_ua.o_imm
        assert ins.ops[1].value & 0xffffffff == 0xfffffff8
        access = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(access, ins, 0) == 1
        assert any(a.regnum == 31 and a.access_type == ida_idp.RW_ACCESS for a in access)
        assert not any(a.regnum == ida_idp.str2reg('CFR') for a in access)
        assert ida_idp._processor_t.find_reg_value(ins, ida_idp.str2reg('C7')) == 1
        assert ida_idp._processor_t.find_reg_value(ins, ida_idp.str2reg('C0')) is None
        assert ida_idp._processor_t.find_reg_value(ins, ida_idp.str2reg('CFR')) is None
        assert ida_idp._processor_t.find_op_value(ins, 2) == 1
        assert ida_idp._processor_t.find_op_value(ins, 0) is None
        assert ida_idp._processor_t.find_op_value(ins, -1) is None
        assert ida_regfinder.find_reg_value(ins.ea, ida_idp.str2reg('C0')) is None
        assert ida_regfinder.find_reg_value(ins.ea, ida_idp.str2reg('C7')) == 1
        result['constant_predicate_queries_checked'] = True
        ins = instruction(0x28b48)
        assert ins.ops[0].type == ida_ua.o_near and ins.ops[0].addr == 0x28b5c
        assert not ida_idp.is_indirect_jump_insn(ins)
        ins = instruction(0x1fee8)
        assert ins.ops[1].type == ida_ua.o_near and ins.ops[1].addr == 0xf18a6
        assert any(x.to == 0xf18a6 and x.type == 17 for x in idautils.XrefsFrom(ins.ea))
        assert ida_segment.add_segm(0, 0x70000000, 0x70001000, 'TEST', 'CODE')
        for i, data in enumerate(('fffffff7', '6000', '60', '600000')):
            ea = 0x70000000 + i * 32
            ida_bytes.put_bytes(ea, bytes.fromhex(data))
            probe = ida_ua.insn_t()
            assert ida_ua.decode_insn(probe, ea) == 0 and ida_ua.create_insn(ea) == 0
        ida_bytes.put_bytes(0x70000100, bytes.fromhex('0148077f'))
        ins = instruction(0x70000100)
        assert ida_idp._processor_t.is_cond_insn(ins) == 1
        assert not ins.get_canon_feature() & ida_idp.CF_STOP
        assert any(x.to == 0x70000102 and x.type == 21 for x in idautils.XrefsFrom(ins.ea))
        ida_bytes.put_bytes(0x70000120, bytes.fromhex('814f'))
        ins = instruction(0x70000120)
        assert ins.auxpref & 1 and 'E=1 (raw)' in ida_lines.generate_disasm_line(ins.ea, 0)
        ida_bytes.put_bytes(0x70000140, bytes.fromhex('70e0e807'))
        ins = instruction(0x70000140)
        assert ins.get_canon_mnem() == 'rde' and ins.ops[1].dtype == ida_ua.dt_void
        ida_bytes.put_bytes(0x70000160, bytes.fromhex('118f'))
        ins = instruction(0x70000160)
        assert ida_idp._processor_t.is_cond_insn(ins) == 1
        assert not ins.get_canon_feature() & ida_idp.CF_STOP
        assert ins.ops[4].reg == ida_idp.str2reg('C6')
        ida_bytes.put_bytes(0x70000180, bytes.fromhex('61027ec7'))
        ins = instruction(0x70000180)
        assert ins.get_canon_feature() & ida_idp.CF_USE1
        assert not ins.get_canon_feature() & ida_idp.CF_CHG1
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        for reg in (1, 2):
            assert any(a.regnum == reg and a.access_type == ida_idp.READ_ACCESS for a in accesses)
        for bit in range(16, 20):
            assert any(a.regnum == ida_idp.str2reg('CFR') and a.range.bitoff() == bit
                       and a.access_type == ida_idp.WRITE_ACCESS for a in accesses)
        result['narrow_jloop_predicate'] = 'C6'
        result['vector_compare_effects_checked'] = True
        ida_bytes.put_bytes(0x700001a0, bytes.fromhex('63c2df8f'))
        ins = instruction(0x700001a0)
        assert ins.get_canon_mnem() == 'fnmsub'
        assert ins.ops[0].reg == ida_idp.str2reg('FD0')
        assert ins.ops[3].reg == ida_idp.str2reg('FD3')
        assert ins.get_canon_feature() & ida_idp.CF_CHG1
        assert not ins.get_canon_feature() & ida_idp.CF_USE1
        result['double_madd_four_operands_checked'] = True
        ida_bytes.put_bytes(0x700001c0, bytes.fromhex('60c1da8f70c0db07'))
        ins = instruction(0x700001c0)
        assert ins.get_canon_mnem() == 'fmovp'
        assert ins.ops[0].reg == ida_idp.str2reg('FD3')
        assert ins.ops[1].reg == 0 and ins.ops[2].reg == 1
        assert ins.get_canon_feature() & ida_idp.CF_CHG1
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        assert any(a.regnum == ida_idp.str2reg('XD17') and a.access_type == ida_idp.WRITE_ACCESS for a in accesses)
        ins = instruction(0x700001c4)
        assert ins.get_canon_mnem() == 'fmovp'
        assert ins.ops[1].reg == ida_idp.str2reg('FD1')
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        assert any(a.regnum == ida_idp.str2reg('XD16') and a.access_type == ida_idp.READ_ACCESS for a in accesses)
        ida_bytes.put_bytes(0x700001e0, bytes.fromhex('70c1db07'))
        probe = ida_ua.insn_t()
        assert ida_ua.decode_insn(probe, 0x700001e0) == 0
        result['odd_fd_pair_moves_checked'] = True
        ida_bytes.put_bytes(0x70000200, bytes.fromhex('60017f1f61007f1f'))
        ins = instruction(0x70000200)
        assert ins.ops[0].reg == 1 and ins.ops[1].reg == ida_idp.str2reg('PSR')
        ins = instruction(0x70000204)
        assert ins.ops[0].reg == ida_idp.str2reg('PSR') and ins.ops[1].reg == 0
        ida_bytes.put_bytes(0x70000220, bytes.fromhex('076f'))
        ins = instruction(0x70000220)
        assert ida_idp._processor_t.is_ret_insn(ins, False) == 1
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        for name in ('IPC', 'IPSR', 'EPC', 'EPSR'):
            assert any(a.regnum == ida_idp.str2reg(name) and a.access_type == ida_idp.READ_ACCESS for a in accesses)
        assert any(a.regnum == ida_idp.str2reg('PSR') and a.range.bitoff() == 26
                   and a.range.bitsize() == 1 and a.access_type == ida_idp.READ_ACCESS for a in accesses)
        ida_bytes.put_bytes(0x70000240, bytes.fromhex('62057f8f'))
        ins = instruction(0x70000240)
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        assert any(a.regnum == ida_idp.str2reg('PSR') and a.range.bitoff() == 16
                   and a.range.bitsize() == 1 and a.access_type == ida_idp.WRITE_ACCESS for a in accesses)
        ida_bytes.put_bytes(0x70000260, bytes.fromhex('064f077f'))
        ins = instruction(0x70000260)
        assert ins.get_canon_feature() & ida_idp.CF_CALL
        assert not ins.get_canon_feature() & ida_idp.CF_STOP
        assert ida_idp._processor_t.is_call_insn(ins) == 1
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        assert not any(a.regnum in (ida_idp.str2reg('LR'), ida_idp.str2reg('SVR'))
                       and a.access_type & ida_idp.WRITE_ACCESS for a in accesses)
        assert any(x.to == ins.ea + 2 and x.type == 21 for x in idautils.XrefsFrom(ins.ea))
        result['system_state_and_trap_effects_checked'] = True
        ida_bytes.put_bytes(0x70000280, bytes.fromhex('61a2001f61a200f761a200ff7fa200ff61a23cf7'))
        ins = instruction(0x70000280)
        assert ins.itype == 1 + 2 * 456  # existing ordinary form ID is stable
        assert ins.get_canon_feature() & ida_idp.CF_CHG2
        assert not ins.get_canon_feature() & (ida_idp.CF_CHG3 | ida_idp.CF_CHG4)
        for ea in (0x70000284, 0x70000288, 0x7000028c, 0x70000290):
            ins = instruction(ea)
            assert not ins.get_canon_feature() & (ida_idp.CF_CHG2 | ida_idp.CF_USE2)
            assert ins.get_canon_feature() & ida_idp.CF_CHG1
            accesses = ida_idp.reg_accesses_t()
            assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
            assert not any(a.regnum in (30, 31) and a.access_type & ida_idp.WRITE_ACCESS for a in accesses)
            if ea == 0x7000028c:
                assert any(a.regnum == 31 and a.access_type == ida_idp.READ_ACCESS for a in accesses)
        ida_bytes.put_bytes(0x700002a0, bytes.fromhex('61a200f0'))
        ins = instruction(0x700002a0)
        assert ida_idp._processor_t.is_cond_insn(ins) == 1
        assert not ins.get_canon_feature() & ida_idp.CF_CHG2
        ida_bytes.put_bytes(0x700002c0, bytes.fromhex('61017f47'))
        ins = instruction(0x700002c0)
        assert ins.get_canon_feature() & ida_idp.CF_USE2
        assert not ins.get_canon_feature() & ida_idp.CF_CHG2
        ida_bytes.put_bytes(0x700002e0, bytes.fromhex('61a2081f'))
        ins = instruction(0x700002e0)
        accesses = ida_idp.reg_accesses_t()
        assert ida_idp.ph_get_reg_accesses(accesses, ins, 0) == 1
        assert any(a.regnum == ida_idp.str2reg('PSR') and a.range.bitoff() == 29
                   and a.range.bitsize() == 1 and a.access_type == ida_idp.READ_ACCESS for a in accesses)
        assert any(a.regnum == ida_idp.str2reg('CFR') and a.range.bitoff() == 9
                   and a.range.bitsize() == 1 and a.access_type == ida_idp.RW_ACCESS for a in accesses)
        result['discarded_destination_and_patent_effects_checked'] = True
        stack_cases = [
            ('0f5f', -8), ('0841', 8), ('7f5f0047', 8), ('7c1f0047', 8),
            ('40be', None), ('60fe9007', None), ('60fdbf1f', None),
            ('7ffdbf1f', None), ('7ffeb00f', None), ('7fff600f', None),
            ('7fff6007', None), ('7fe0600f', 4), ('7fff780f', 4),
            ('7fffbf1f', 16), ('7fe06008', None), ('7fe06000', 0),
            ('61a23cf7', 0), ('61a200ff', 0), ('61bfd087', None),
        ]
        for index, (raw, expected_delta) in enumerate(stack_cases):
            ea = 0x70000300 + 8 * index
            ida_bytes.put_bytes(ea, bytes.fromhex(raw))
            ins = instruction(ea)
            delta = ida_pro.sval_pointer()
            delta.assign(1234)
            status = ida_idp._processor_t.calc_spdelta(delta.cast(), ins)
            assert status == (expected_delta is not None), (raw, status, delta.value())
            if expected_delta is not None:
                assert delta.value() == expected_delta, (raw, delta.value())
        result['stack_delta_edge_cases_checked'] = len(stack_cases)
        for index, raw in enumerate(('60007f27', '61007f27', '60007fbf', '61007fbf', '0b20', '014f')):
            ea = 0x70000500 + 8 * index
            ida_bytes.put_bytes(ea, bytes.fromhex(raw))
            probe = instruction(ea)
            accesses = ida_idp.reg_accesses_t()
            assert ida_idp.ph_get_reg_accesses(accesses, probe, 0) == 1
            assert not any(a.regnum == ida_idp.str2reg('CFR') and a.range.bitoff() <= 7
                           and a.range.bitoff() + a.range.bitsize() > 7 for a in accesses)
        result['aggregate_constant_bit_exclusion_checked'] = True
        ida_auto.auto_wait()
        _, sections, symbols = elf(source)
        for name in ('ntohl', '__anddi3', 'memcpy', 'sigsetjmp', 'strlen'):
            ea = ida_name.get_name_ea(0xffffffffffffffff, name)
            assert ida_funcs.get_func_start(ea) == ea, name
        misses = []
        for name, value, size, info, shndx in symbols:
            if shndx and info & 15 == 2 and size:
                if ida_funcs.get_func_start(value) != value:
                    misses.append((name, hex(value), hex(ida_funcs.get_func_start(value)), ida_funcs.get_func_name(value)))
        result['function_seed_misses'] = misses
        assert not misses, misses[:20]
        assert ida_nalt.get_import_module_qty() > 0
        imported = []
        for i in range(ida_nalt.get_import_module_qty()):
            ida_nalt.enum_import_names(i, lambda ea, name, ordinal: imported.append((ea, name)) or True)
        assert len(imported) >= 800
        raw = source.read_bytes()
        rela = sections['.rela.data.rel.ro']
        applied = 0
        for off in range(rela[4], rela[4] + rela[5], rela[9]):
            place, info, addend = struct.unpack_from('>IIi', raw, off)
            if info & 255 == 179:
                assert ida_bytes.get_dword(place) == addend & 0xffffffff
                fixup = ida_fixup.fixup_data_t()
                assert ida_fixup.get_fixup(fixup, place) and fixup.get_type() == ida_fixup.FIXUP_OFF32
                applied += 1
        assert applied > 0
        for name in ('.text', '.rodata'):
            s = sections[name]
            segment = ida_segment.segment_info_t()
            assert ida_segment.get_segment_info(segment, s[3]) and segment.start_ea == s[3]
            assert bool(segment.get_perm() & 1) == (name == '.text')
        result.update(import_slots=len(imported), relative_fixups_checked=applied,
                      named_function_errors=misses, invalid_instruction_probes=4)
    idapro.close_database(False)
    opened = False
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_digest
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    hooks.unhook()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    temp.cleanup()
print(json.dumps(result, indent=2))
