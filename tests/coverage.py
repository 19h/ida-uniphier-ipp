"""Independently compare CLI coverage enumeration to ELF section flags."""
import csv
import io
from pathlib import Path
import struct
import subprocess
import sys

exe, root = sys.argv[1], Path(sys.argv[2])
expected = {}
for path in root.iterdir():
    if not path.is_file():
        continue
    with path.open('rb') as f:
        if f.read(4) != b'\x7fELF':
            continue
    raw = path.read_bytes()
    shoff = struct.unpack_from('>I', raw, 32)[0]
    stride, count, names_index = struct.unpack_from('>HHH', raw, 46)
    records = [struct.unpack_from('>10I', raw, shoff + i * stride) for i in range(count)]
    strings = records[names_index]
    names = raw[strings[4]:strings[4] + strings[5]]
    for s in records:
        if s[1] != 8 and s[2] & 4 and s[5]:
            name = names[s[0]:].split(b'\0', 1)[0].decode()
            expected[path.name, name] = s[5]
r = subprocess.run([exe, '--coverage', str(root)], check=True, capture_output=True, text=True)
rows = list(csv.DictReader(io.StringIO(r.stdout), delimiter='\t'))
actual = {(r['file'], r['section']): int(r['size']) for r in rows}
assert actual == expected, (actual.keys() - expected.keys(), expected.keys() - actual.keys())
assert len(rows) == len(expected), 'duplicate coverage records'
for row in rows:
    assert int(row['size']) == sum(int(row[k]) for k in ('insn_bytes', 'noncode_bytes', 'unresolved_bytes'))
assert ('libg.so', '.text_g') in actual
print(f'PASS {len(actual)} executable sections across {len({k[0] for k in actual})} ELF files')
