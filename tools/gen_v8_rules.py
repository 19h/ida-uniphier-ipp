#!/usr/bin/env python3
"""Generate src/decoder/v8_rules.inc from the platinum V8 opcode table.

The table is the disassembler's InstructionDecode rules
(v8_opcode_table.tsv, beside this script). Rule order is match order.
A 16-bit rule never covers top nibble 6, 7, E, or F; those parcels are
32-bit instructions. Operand text is the V8 format string. br and brl
replace the displacement with the absolute target address+disp.
brl writes LR and the next instruction stays live, so its flow is Call.
br does not write LR and stays Branch.

GCC_EXTRA_RULES in gcc_extra_rules.py are appended after the 758 V8 rules.
They are encodings GCC emits and V8's JIT does not. Evidence is
gcc-supplement. The halfword 0000 is that 16-bit br (predicate c6), so
the table has no pad row. V8 wins when a word matches both.
"""

import json
import pathlib
import re
import sys

TOOLS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))
from gcc_extra_rules import GCC_EXTRA_RULES, eval_operand  # noqa: E402
from operand_specs import layout, cpp as operand_cpp  # noqa: E402
from patent_semantics import evidence as patent_evidence, effects as patent_effects  # noqa: E402
TABLE = TOOLS / "v8_opcode_table.tsv"
OUT = TOOLS.parent / "src" / "decoder" / "v8_rules.inc"

TOK = re.compile(
    r"const\(\d+\)|sext|b\[\d+(?::\d+)?\]|<<\d+\+1|\+\d+|<<\d+|[():]"
)


def tokenize(text):
    toks = TOK.findall(text)
    if "".join(toks) != text.replace(" ", ""):
        raise SystemExit("tokenize failed for " + text)
    return toks


class Parser:
    def __init__(self, toks):
        self.toks = toks
        self.i = 0

    def peek(self):
        if self.i >= len(self.toks):
            return None
        return self.toks[self.i]

    def pop(self):
        tok = self.peek()
        if tok is None:
            raise SystemExit("unexpected end")
        self.i += 1
        return tok


def parse_expr(parser):
    tok = parser.pop()
    if tok == "sext":
        if parser.pop() != "(":
            raise SystemExit("sext")
        node = ("sext", parse_expr(parser))
        if parser.pop() != ")":
            raise SystemExit("sext close")
    elif tok == "(":
        node = parse_expr(parser)
        while parser.peek() == ":":
            parser.pop()
            node = ("concat", node, parse_expr(parser))
        if parser.pop() != ")":
            raise SystemExit("concat close")
    elif tok.startswith("const"):
        node = ("const", int(tok[6:-1]))
    elif tok.startswith("b["):
        body = tok[2:-1]
        if ":" in body:
            hi, lo = body.split(":")
            node = ("bits", int(hi), int(lo))
        else:
            bit = int(body)
            node = ("bits", bit, bit)
    else:
        raise SystemExit("bad token " + tok)
    while True:
        nxt = parser.peek()
        if nxt is not None and nxt.startswith("<<"):
            parser.pop()
            if nxt.endswith("+1"):
                node = ("add", ("shl", node, int(nxt[2:-2])), 1)
            else:
                node = ("shl", node, int(nxt[2:]))
        elif nxt is not None and re.fullmatch(r"\+\d+", nxt):
            parser.pop()
            node = ("add", node, int(nxt[1:]))
        else:
            break
    return node


def compile_node(node, out):
    kind = node[0]
    if kind == "bits":
        out.extend((1, node[1], node[2]))
    elif kind == "const":
        value = node[1] & 0xFFFFFFFF
        out.extend(
            (2, value & 255, (value >> 8) & 255, (value >> 16) & 255, (value >> 24) & 255)
        )
    elif kind == "concat":
        compile_node(node[1], out)
        compile_node(node[2], out)
        out.append(3)
    elif kind == "sext":
        compile_node(node[1], out)
        out.append(4)
    elif kind == "shl":
        compile_node(node[1], out)
        out.extend((5, node[2]))
    elif kind == "add":
        compile_node(node[1], out)
        out.extend((6, node[2] & 255))
    else:
        raise SystemExit("compile " + kind)


def mask_width(width):
    if width >= 32:
        return 0xFFFFFFFF
    return (1 << width) - 1


def eval_prog(prog, word):
    stack = []
    values = []
    i = 0
    while i < len(prog):
        op = prog[i]
        i += 1
        if op == 1:
            hi = prog[i]
            lo = prog[i + 1]
            i += 2
            width = hi - lo + 1
            value = (word >> lo) & mask_width(width)
            stack.append((value, width))
        elif op == 2:
            value = prog[i] | (prog[i + 1] << 8) | (prog[i + 2] << 16) | (prog[i + 3] << 24)
            if value & 0x80000000:
                value -= 0x100000000
            i += 4
            stack.append((value, 0))
        elif op == 3:
            bval, bwidth = stack.pop()
            aval, awidth = stack.pop()
            value = (aval << bwidth) | (bval & mask_width(bwidth))
            stack.append((value, awidth + bwidth))
        elif op == 4:
            value, width = stack.pop()
            value &= mask_width(width)
            if width < 32 and width > 0 and (value & (1 << (width - 1))):
                value |= ~mask_width(width)
            value &= 0xFFFFFFFF
            if value & 0x80000000:
                value -= 0x100000000
            stack.append((value, 32))
        elif op == 5:
            value, width = stack.pop()
            shift = prog[i]
            i += 1
            value = (value << shift) & 0xFFFFFFFF
            if value & 0x80000000:
                value -= 0x100000000
            stack.append((value, width + shift))
        elif op == 6:
            value, width = stack.pop()
            add = prog[i]
            if add >= 128:
                add -= 256
            i += 1
            stack.append((value + add, width))
        elif op == 0:
            value, _width = stack.pop()
            if stack:
                raise SystemExit("stack not empty at yield")
            values.append(value)
        else:
            raise SystemExit("bad op")
    return values


def compile_gcc_op(op, out):
    # GCC slices are [pos, len]: bits (pos-len)..(pos-1), concatenated
    # high slice first, then an optional sign-extend and left shift.
    kind = op["type"]
    if kind == "const":
        compile_node(("const", int(op["value"])), out)
        return
    if kind == "plus":
        compile_gcc_op(op["base"], out)
        addend = int(op["addend"])
        if addend < -128 or addend > 127:
            raise SystemExit("addend out of int8: %d" % addend)
        out.extend((6, addend & 255))
        return
    if kind not in ("unsigned", "signed"):
        raise SystemExit("gcc operand " + kind)
    slices = op["slices"]
    if not slices:
        raise SystemExit("empty slices")
    for index, pair in enumerate(slices):
        pos = int(pair[0])
        length = int(pair[1])
        if length <= 0 or length > 32 or pos < length or pos > 32:
            raise SystemExit("bad slice %s" % (pair,))
        out.extend((1, pos - 1, pos - length))
        if index:
            out.append(3)
    if kind == "signed":
        out.append(4)
    shift = int(op.get("shift", 0))
    if shift < 0 or shift > 31:
        raise SystemExit("shift %d" % shift)
    if shift:
        out.extend((5, shift))


def flow_of(mnemonic):
    # brl links LR. The instruction after it is live, including when the
    # predicate is 7, so it is a call rather than a branch.
    if mnemonic in ("jmpl", "brl"):
        return "Call"
    if mnemonic in ("jmpr", "rti"):
        return "Return"
    if mnemonic in ("br", "jmp", "jmpf", "jloop"):
        return "Branch"
    if re.fullmatch(r'(?:pi[0-7]l?|sc[0-7])', mnemonic):
        return "Trap"
    return "Sequential"


def semantic_evidence(mnemonic):
    if re.fullmatch(r'pi[0-7]l?', mnemonic):
        return 'US20040078549A1:Fig256,257'
    if re.fullmatch(r'sc[0-7]', mnemonic):
        return 'US20040078549A1:Table3;corpus:pied:sc1-continuation'
    return {'rti': 'US20040078549A1:Fig11,255',
            'intd': 'US20040078549A1:Fig11,248',
            'inte': 'US20040078549A1:Fig11,249'}.get(mnemonic)


def load_rows():
    rows = []
    with TABLE.open() as handle:
        header = handle.readline().rstrip("\n").split("\t")
        for line in handle:
            parts = line.rstrip("\n").split("\t")
            rows.append(dict(zip(header, parts)))
    return rows


def build():
    prog = []
    rules = []
    for row in load_rows():
        pieces = [piece for piece in row["operands"].split(", ") if piece]
        off = len(prog)
        for piece in pieces:
            parser = Parser(tokenize(piece))
            node = parse_expr(parser)
            if parser.peek() is not None:
                raise SystemExit("trailing tokens in " + piece)
            compile_node(node, prog)
            prog.append(0)
        end = len(prog)
        va = row["decoder_va"]
        if va.startswith("0x"):
            va = va[2:]
        rules.append(
            {
                "id": "v8-" + va,
                "bits": int(row["bits"]),
                "mask": int(row["mask"], 16),
                "match": int(row["match"], 16),
                "mnemonic": row["mnemonic"],
                "format": row["format"],
                "flow": flow_of(row["mnemonic"]),
                "evidence": "v8-" + va,
                "semantic_evidence": semantic_evidence(row['mnemonic']) or patent_evidence(row),
                "off": off,
                "end": end,
                "nops": len(pieces),
            }
        )
    return prog, rules


def append_gcc(prog, rules):
    for row in GCC_EXTRA_RULES:
        off = len(prog)
        for op in row["operands"]:
            compile_gcc_op(op, prog)
            prog.append(0)
        rules.append(
            {
                "id": "gcc-%d" % row["index"],
                "bits": int(row["bits"]),
                "mask": int(row["mask"], 16),
                "match": int(row["match"], 16),
                "mnemonic": row["mnemonic"],
                "format": row["format"],
                "flow": flow_of(row["mnemonic"]),
                "evidence": row["source"],
                "semantic_evidence": row.get("semantic_evidence"),
                "off": off,
                "end": len(prog),
                "nops": len(row["operands"]),
            }
        )


def decode_word(rules, word, bits, address):
    for rule in rules:
        if rule["bits"] != bits:
            continue
        if (word & rule["mask"]) != rule["match"]:
            continue
        # Re-eval from the stored program slice is done by the caller when needed.
        return rule
    return None


def emit(prog, rules):
    lines = []
    lines.append("// Generated by tools/gen_v8_rules.py. Do not edit.")
    lines.append("// 758 InstructionDecode rules, then 26 GCC supplemental encodings.")
    lines.append("// V8 wins on overlap. 0000 is gcc-758 ([c6] br), not a pad.")
    lines.append("constexpr uint8_t OPERAND_PROGRAMS[] = {")
    for i in range(0, len(prog), 16):
        chunk = prog[i : i + 16]
        lines.append("    " + ", ".join(str(b) for b in chunk) + ",")
    lines.append("};")
    lines.append("")
    operands = []
    for rule in rules:
        rule['operand_off'] = len(operands)
        spec = layout(rule)
        rule['operand_count'] = len(spec)
        operands.extend(spec)
    lines.append("constexpr OperandSpec OPERAND_SPECS[] = {")
    lines.extend(operand_cpp(op) for op in operands)
    lines.append("};")
    lines.append("")
    lines.append("constexpr Form FORMS[] = {")
    flow_cpp = {
        "Sequential": "Flow::Sequential",
        "Branch": "Flow::Branch",
        "Call": "Flow::Call",
        "Return": "Flow::Return",
        "Trap": "Flow::Trap",
    }
    for rule in rules:
        width = "Width::W32" if rule["bits"] == 32 else "Width::W16"
        fmt = rule["format"].replace("\\", "\\\\").replace('"', '\\"')
        lines.append(
            '    {"%s", "%s", "%s", %s, Kind::Insn,'
            % (rule["id"], rule["mnemonic"], rule["evidence"], flow_cpp[rule["flow"]])
        )
        lines.append(
            "     %s, 0x%xu, 0x%xu, \"%s\", %u, %u, %u, %u, %s, 0x%xu},"
            % (width, rule["match"], rule["mask"], fmt, rule["off"], rule["nops"],
               rule['operand_off'], rule['operand_count'],
               json.dumps(rule['semantic_evidence']) if rule.get('semantic_evidence') else 'nullptr',
               patent_effects(rule))
        )
    lines.append("};")
    text = "\n".join(lines) + "\n"
    if '--check' in sys.argv:
        if not OUT.exists() or OUT.read_text() != text:
            raise SystemExit('generated table is stale: ' + str(OUT))
        print('generated table verified', len(rules), 'forms')
    else:
        OUT.write_text(text)
        print("wrote", OUT, "rules", len(rules), "prog", len(prog))


def check_gcc(prog, rules):
    gcc = [rule for rule in rules if rule["evidence"] == "gcc-supplement"]
    if len(gcc) != 26:
        raise SystemExit("gcc count %d" % len(gcc))
    want_ids = ["gcc-%d" % i for i in range(758, 786) if i not in (760, 761)]
    if [rule["id"] for rule in gcc] != want_ids:
        raise SystemExit("gcc id order %s" % [rule["id"] for rule in gcc])
    if not rules[0]["evidence"].startswith("v8-") or rules[757]["evidence"].startswith("gcc"):
        raise SystemExit("V8 rules must precede the GCC extras")
    high = {16: 0x8000, 32: 0x80000000}
    width_mask = {16: 0xFFFF, 32: 0xFFFFFFFF}
    for rule in rules:
        if rule["mask"] & high[rule["bits"]]:
            raise SystemExit("mask includes E %s %x" % (rule["id"], rule["mask"]))

    def run(rule, word):
        return eval_prog(prog[rule["off"] : rule["end"]], word)

    for rule in gcc:
        src = next(src for src in GCC_EXTRA_RULES if src["index"] == int(rule["id"].split("-")[1]))
        free = (~rule["mask"]) & width_mask[rule["bits"]]
        for word in (rule["match"], rule["match"] | free, rule["match"] | (free & 0x11111111)):
            got = run(rule, word)
            want = [eval_operand(op, word) for op in src["operands"]]
            if got != want:
                raise SystemExit(
                    "operand %s word %x got %s want %s" % (rule["id"], word, got, want)
                )
    zero = decode_word(rules, 0, 16, 0)
    if zero is None or zero["id"] != "gcc-758" or run(zero, 0) != [6, 0]:
        raise SystemExit("0000 is not gcc-758 br c6 disp 0")
    mov = decode_word(rules, 0x601E7F67, 32, 0)
    if (
        mov is None
        or mov["mnemonic"] != "mov"
        or mov["evidence"] != "gcc-supplement"
        or run(mov, 0x601E7F67) != [7, 30]
    ):
        raise SystemExit("mov R30,PC mismatch")
    jmp = decode_word(rules, 0x60FD9807, 32, 0)
    if jmp is None or jmp["mnemonic"] != "jmp" or jmp["flow"] != "Branch" or run(jmp, 0x60FD9807) != [7, 0]:
        raise SystemExit("jmp (R0) mismatch")
    jmpl = decode_word(rules, 0x60FD9A07, 32, 0)
    if jmpl is None or jmpl["mnemonic"] != "jmpl" or jmpl["flow"] != "Call" or run(jmpl, 0x60FD9A07) != [7, 0]:
        raise SystemExit("jmpl (R0) mismatch")
    br = decode_word(rules, 0x0015, 16, 0x28B48)
    if br is None or br["id"] != "gcc-758" or run(br, 0x0015) != [7, 20]:
        raise SystemExit("0015 br mismatch %s" % (None if br is None else run(br, 0x0015),))
    print("gcc extras ok", len(gcc))


def main():
    prog, rules = build()
    if len(rules) != 758:
        raise SystemExit("v8 count %d" % len(rules))
    append_gcc(prog, rules)
    if len(prog) > 65535:
        raise SystemExit("operand program exceeds uint16 prog_off")
    # Spot-check the gated libc .init words before writing the table.
    checks = [
        (0x014F, 16, 0x3BFDC, "jmpr", None),
        (0x2030, 16, 0x1FED4, "cmpne", None),
        (0x40E0, 16, 0x1FEEC, "ldp", None),
        (0x40E1, 16, 0x1FED2, "stp", None),
        (0x0F5F, 16, 0x1FED0, "add", None),
        (0x0841, 16, 0x1FEEE, "add", None),
        (0x0040, 16, 0, "jmp", None),
        (0x0080, 16, 0, "add", None),
        (0x1090, 16, 0, "rsub", None),
        (0x68082987, 32, 0x1FEE0, "brl", 0x28940),
        (0x7700006F, 32, 0x1FEE4, "sethi", None),
        (0x760126FF, 32, 0x1FEE8, "brl", None),
        (0x680004C7, 32, 0x08000010, "brl", 0x08000140),
    ]
    # Rebuild programs per rule for the check. eval needs the slice.
    # The blob is contiguous; slice is from off until nops YIELDs.
    def run(rule, word):
        return eval_prog(prog[rule["off"] : rule["end"]], word)

    for word, bits, addr, mnem, target in checks:
        rule = decode_word(rules, word, bits, addr)
        if rule is None or rule["mnemonic"] != mnem:
            got = None if rule is None else rule["mnemonic"]
            raise SystemExit("mismatch %x want %s got %s" % (word, mnem, got))
        vals = run(rule, word)
        if mnem == 'brl' and 'LR,' in rule['format']:
            if target is not None:
                raise SystemExit('brl LR needs sethi context, not a low-half target')
            print('%08x brl LR low-half vals %s; target needs context' % (word, vals))
        elif mnem in ("br", "brl"):
            disp = vals[-1]
            got_t = (addr + disp) & 0xFFFFFFFF
            if target is not None and got_t != target:
                raise SystemExit("target %x got %x vals %s" % (word, got_t, vals))
            print("%08x %s target %08x vals %s" % (word, mnem, got_t, vals))
        else:
            print("%08x %s vals %s" % (word, mnem, vals))
    check_gcc(prog, rules)
    emit(prog, rules)
    print("forms", len(rules))


if __name__ == "__main__":
    main()
