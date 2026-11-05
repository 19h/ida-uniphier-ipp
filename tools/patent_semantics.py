"""Explicit primary-figure policies; generation transfer remains an assumption.

Runtime generation never reads OCR. The JSON contains reviewed policies and
their figure references, separate from numeric opcode extraction evidence.
"""
import json
from pathlib import Path

POLICIES = json.loads(Path(__file__).with_suffix('.json').read_text())['policies']
EFFECT_BITS = {name: 1 << i for i, name in enumerate((
    'StickyOverflow', 'ReadFixedPointMode', 'ReadBitPosition', 'ReadAlignment',
    'ReadVectorCondition2', 'ReadVectorConditions', 'WriteVectorConditions', 'ReadVectorCondition0'))}


def policy(rule):
    if '] mov MH' in rule['format']:
        return dict(figures=[397, 398, 399, 400], effects=[], two_dest=False,
                    discard_special_dest=False, single_dest=True)
    return POLICIES.get(rule['mnemonic'], {})


def evidence(rule):
    p = policy(rule)
    return 'US20040078549A1:Fig' + ','.join(map(str, p['figures'])) if p else None


def effects(rule):
    return sum(EFFECT_BITS[name] for name in policy(rule).get('effects', []))
