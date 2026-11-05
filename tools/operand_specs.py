"""Compile V8 operand templates into typed layouts, independently of rendering.

Unestablished implicit arithmetic effects are marked conservative. This is
not an ISA lifter: the template establishes operand identity and syntax;
the small explicit access policy establishes the supported def/use model.
"""
import re
from patent_semantics import policy as patent_policy

BANKS = {'R': 'R0', 'C': 'C0', 'FS': 'FS0', 'FD': 'FD0', 'XD': 'XD0',
         'M': 'M0', 'MH': 'MH0', 'ML': 'ML0'}
LITERALS = {'SP', 'GP', 'LR', 'SVR', 'TAR', 'PC', 'CFR', 'CFR0', 'CFR1',
            'CFR2', 'CFR3', 'FPCR', 'PSR', 'IPSR', 'IPC', 'SAR'}
MEM_WIDTH = {'ld': 4, 'st': 4, 'ldp': 8, 'stp': 8, 'ldq': 16, 'stq': 16,
             'ldb': 1, 'ldbu': 1, 'stb': 1, 'ldh': 2, 'ldhu': 2, 'sth': 2,
             'ldbp': 2, 'stbp': 2, 'ldhp': 4, 'sthp': 4, 'ldstb': 1,
             'cas': 4, 'cash': 2, 'casb': 1,
             'ldbh': 2, 'ldbhp': 4, 'ldbuhp': 4, 'stbh': 2, 'stbhp': 4}


def split_operands(body):
    depth = 0
    start = 0
    result = []
    for i, c in enumerate(body):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == ',' and depth == 0:
            result.append(body[start:i])
            start = i + 1
    if depth:
        raise ValueError('unbalanced template: ' + body)
    if body[start:]:
        result.append(body[start:])
    return result


def scalar(token):
    m = re.fullmatch(r'\{(\d+)\}', token)
    return (int(m[1]), 0) if m else (-1, int(token))


def register(token):
    if token in LITERALS:
        return token, -1
    m = re.fullmatch(r'(FS|FD|XD|MH|ML|R|C|M)(\{\d+\}|\d+)', token)
    if not m:
        raise ValueError('not a register: ' + token)
    idx, const = scalar(m[2])
    return BANKS[m[1]] + (' + %d' % const if const else ''), idx


def layout(rule):
    fmt = rule['format']
    index = -1

    def placeholder(_):
        nonlocal index
        index += 1
        return '{%d}' % index

    text = re.sub(r'%d', placeholder, fmt)
    body = text.split('] ', 1)[1].partition(' ')[2].strip()
    tokens = split_operands(body)
    if len(tokens) > 6:
        raise ValueError('too many explicit operands: ' + fmt)
    result = []
    mnem = rule['mnemonic']
    for token in tokens:
        op = dict(kind='Immediate', reg='-1', arg=-1, end='-1', end_arg=-1,
                  value_arg=-1, constant=0, width=4, access=1, flags=0)
        if token.startswith('('):
            m = re.fullmatch(r'\(([^)]+)\)(.*)', token)
            if not m:
                raise ValueError(token)
            parts = m[1].split(',')
            post = parts[0].endswith('+')
            base = parts[0].removesuffix('+')
            try:
                op['reg'], op['arg'] = register(base)
                if len(parts) == 2:
                    op['value_arg'], op['constant'] = scalar(parts[1])
                if post:
                    op['flags'] |= 1
                    op['value_arg'], op['constant'] = scalar(m[2]) if m[2] else (-1, MEM_WIDTH.get(mnem, 0))
            except ValueError:
                op['value_arg'], op['constant'] = scalar(base)
            op['kind'] = 'Memory'
            op['width'] = MEM_WIDTH.get(mnem, 0)
            if mnem in ('rde', 'wte'):
                op['flags'] |= 2  # a distinct external-register address space
        elif ':' in token:
            a, b = token.split(':')
            op['reg'], op['arg'] = register(a)
            op['end'], op['end_arg'] = register(b)
            op['kind'] = 'RegisterRange'
            op['width'] = 0  # derived from the actual registers, not punctuation
        else:
            try:
                op['reg'], op['arg'] = register(token)
                op['kind'] = 'Register'
                op['width'] = 0
            except ValueError:
                op['value_arg'], op['constant'] = scalar(token)
        if token == 'SP' or token.startswith('(SP,'):
            op['flags'] |= 4
        if token == 'GP' or token.startswith('(GP,'):
            op['flags'] |= 8
        result.append(op)

    # PC-relative address operands. brl LR's low half needs context and is
    # deliberately still an immediate until resolve_far_call succeeds.
    if result and mnem in ('br', 'brl', 'settar', 'setlr') and not body.startswith('LR,'):
        if result[-1]['kind'] != 'Immediate':
            raise ValueError('missing displacement: ' + fmt)
        result[-1]['kind'] = 'CodeAddress'

    if mnem.startswith('st') or mnem == 'wte':
        result[0]['access'] = 2
    elif mnem.startswith('ld') or mnem == 'rde':
        result[0]['access'] = 2
        if mnem == 'ldstb':
            result[1]['access'] = 3
    elif mnem in ('cas', 'cash', 'casb'):
        result[0]['access'] = 2
        result[1]['access'] = result[2]['access'] = 3
    elif mnem in ('br', 'brl', 'jmp', 'jmpl', 'jmpr', 'setbb'):
        pass
    elif mnem == 'jmpf':
        for op in result:
            if op['kind'] == 'RegisterRange':
                op['access'] = 3
                op['flags'] |= 16  # range contains both inputs and outputs
            elif op['reg'].startswith('C0'):
                op['access'] = 2
    elif mnem in ('settar', 'setlr', 'jloop'):
        for op in result:
            if op['kind'] in ('Register', 'RegisterRange') and op['reg'] not in ('TAR', 'LR'):
                op['access'] = 3 if mnem == 'jloop' and (op['reg'].startswith('R0') or op['kind'] == 'RegisterRange') else 2
                if mnem == 'jloop' and op['kind'] == 'RegisterRange':
                    op['flags'] |= 16  # C2 is a destination; C3/C4 are also inputs.
    elif mnem.startswith(('vcmp', 'vscmp')):
        # Fig.616-639: both explicit GPRs are inputs; VC0..VC3 are
        # implicit destinations, represented by register_accesses().
        pass
    elif mnem == 'movcf':
        # Fig.416: Ci <- Cj, Cm <- Cn.
        result[0]['access'] = result[2]['access'] = 2
    elif patent_policy(rule).get('two_dest') and result and result[0]['reg'].startswith(('M0', 'MH0')):
        # The primary equations have two destinations followed by inputs.
        result[0]['access'] = result[1]['access'] = 2
        if patent_policy(rule).get('discard_special_dest'):
            result[1]['flags'] |= 32  # R30/R31 encode a discarded output.
    elif patent_policy(rule).get('single_dest'):
        result[0]['access'] = 2
    elif result and result[0]['reg'].startswith(('M0', 'MH0')):
        # The format identifies multiple destinations but does not prove all
        # implicit accumulator/flag effects. Overapproximate without claiming
        # exact semantics. These flags are exposed to clients and tests.
        for op in result:
            if op['kind'] in ('Register', 'RegisterRange'):
                op['access'] = 3
                op['flags'] |= 16
    elif result and result[0]['kind'] in ('Register', 'RegisterRange'):
        result[0]['access'] = 2
        if mnem in ('sethi', 'fmul2p') or len(result) == 1 or (
                len(result) == 2 and mnem in ('add', 'sub', 'and', 'andn', 'or', 'xor',
                                             'asl', 'asr', 'lsr', 'rol', 'rsub')):
            result[0]['access'] = 3
        if mnem in ('fmax', 'fmin', 'famax', 'famin', 'famaxa', 'famina'):
            # Destructive two-input operation; fmax/fmin are independently
            # anchored by the supplied libm routines of the same names.
            result[0]['access'] = 3
            if mnem not in ('fmax', 'fmin'):
                result[0]['flags'] |= 16
        if mnem == 'vmovt':
            result[0]['access'] = 3
    return result


def cpp(op):
    return ('    {OperandKind::%s, %s, %d, %s, %d, %d, %d, %d, %d, %d},' %
            (op['kind'], op['reg'], op['arg'], op['end'], op['end_arg'],
             op['value_arg'], op['constant'], op['width'], op['access'], op['flags']))
