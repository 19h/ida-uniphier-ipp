"""Check object names across two supplied images in a disposable IDA database."""
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
p.add_argument('--output', type=Path, required=True)
args = p.parse_args()
if os.environ.get('IPP_IDALIB_PYTHON'):
    sys.path.insert(0, os.environ['IPP_IDALIB_PYTHON'])
import idapro
import ida_auto
import ida_bytes
import ida_ida
import ida_idaapi
import ida_name


def object_symbols(path):
    """Read ELF symbol/address anchors independently of the production parser."""
    raw = path.read_bytes()
    assert raw[:6] == b'\x7fELF\x01\x02'
    assert struct.unpack_from('>H', raw, 18)[0] == 0x1040
    shoff = struct.unpack_from('>I', raw, 32)[0]
    stride, count = struct.unpack_from('>HH', raw, 46)
    sections = [struct.unpack_from('>10I', raw, shoff + i * stride) for i in range(count)]
    result = {}
    for section in sections:
        if section[1] not in (2, 11):
            continue
        strings_section = sections[section[6]]
        strings = raw[strings_section[4]:strings_section[4] + strings_section[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, value, size, info, _, index = struct.unpack_from('>IIIBBH', raw, offset)
            if info & 15 != 1 or not 0 < index < len(sections) or not sections[index][2] & 2:
                continue
            text = strings[name:].split(b'\0', 1)[0].decode()
            if text:
                result.setdefault(value, set()).add(text)
    return raw, result


opened = False
result = {'version': idapro.get_library_version(), 'passed': False}
temp = tempfile.TemporaryDirectory(prefix='ipp-companion-test-')
try:
    images = []
    for name in ('asr_recognizer', 'libc.so.7'):
        original = args.corpus / name
        raw, symbols = object_symbols(original)
        copied = Path(temp.name) / name
        shutil.copyfile(original, copied)
        images.append((original, copied, raw, symbols))
    primary = images[0][3]
    companion = images[1][3]
    primary_by_name = {name: ea for ea, names in primary.items() for name in names}
    companion_by_name = {name: ea for ea, names in companion.items() for name in names}
    common = sorted(primary_by_name.keys() & companion_by_name.keys())
    assert len(primary) == 10 and len(companion) >= 50 and len(common) >= 5
    assert primary_by_name['__stdoutp'] == 0x79d1b4
    assert companion_by_name['__stdoutp'] == 0x10375c
    options = '-pipp -T"UniPhier IPP ELF" ' + os.environ.get('IPP_IDA_ARGS', '')
    options += ' -Oelfipp:companions=' + str(images[1][1].resolve())
    assert idapro.open_database(str(images[0][1]), False, options) == 0
    opened = True
    assert ida_ida.inf_get_procname() == 'ipp'
    ida_auto.auto_wait()
    misses = []
    checked = []
    for index, (_, _, _, symbols) in enumerate(images):
        prefix = 'image1_' if index else ''
        for ea, names in sorted(symbols.items()):
            assert ida_bytes.is_mapped(ea), hex(ea)
            actual = ida_name.get_name(ea)
            expected = sorted(prefix + name for name in names)
            row = {'image': index, 'ea': hex(ea), 'expected': expected, 'actual': actual}
            checked.append(row)
            if actual not in expected:
                misses.append(row)
    result.update(primary_object_addresses=len(primary), companion_object_addresses=len(companion),
                  duplicate_object_names=common, object_name_checks=checked,
                  object_name_misses=misses,
                  input_sha256={original.name: hashlib.sha256(raw).hexdigest()
                                for original, _, raw, _ in images})
    for original, copied, raw, _ in images:
        assert original.read_bytes() == raw and copied.read_bytes() == raw
    assert not misses, misses[:8]
    for name in common:
        assert ida_name.get_name_ea(ida_idaapi.BADADDR, name) == primary_by_name[name]
        assert ida_name.get_name(companion_by_name[name]) == 'image1_' + name
    result['passed'] = True
finally:
    if opened:
        idapro.close_database(False)
    temp.cleanup()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({key: result[key] for key in ('version', 'passed', 'primary_object_addresses',
                                              'companion_object_addresses', 'duplicate_object_names')}))
