"""Encodings that compiled code uses and V8's JIT does not emit.

These supplement the 758 rules in v8_opcode_table.tsv and are matched after them.
Recognizing an encoding here is not independent validation of its semantics.
"""

GCC_EXTRA_RULES = [
    # 16-bit PC-relative branch (b[0]=0 -> [c6], b[0]=1 -> [c7])
    {
        "index": 758, "bits": 16, "mnemonic": "br", "format": "[c%d] br %d",
        "mask": "0x78c0", "match": "0x0000", "source": "gcc-supplement",
        "operands": [
            {"type": "plus", "base": {"type": "unsigned", "slices": [[1, 1]], "shift": 0}, "addend": 6},
            {"type": "signed", "slices": [[11, 3], [6, 5]], "shift": 1},
        ],
    },
    # 16-bit SP-relative address generation: add Rd, SP, imm
    {
        "index": 759, "bits": 16, "mnemonic": "add", "format": "[c%d] add R%d,SP,%d",
        "mask": "0x78e0", "match": "0x0860", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[11, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[5, 5]], "shift": 2},
        ],
    },
    # Compact halfword/word memory forms for R0..R15. Source-aligned
    # FDCT/IDCT and PCM copy establish the halfword forms below.
    # Withdrawn indexes 760/761 (4080/4090): earlier ordinary-memory
    # assignments conflict with external-register access contexts. Their
    # exact semantics remain unresolved; do not renumber subsequent IDs.
    {
        "index": 762, "bits": 16, "mnemonic": "ldh", "format": "[c%d] ldh R%d,(R%d,0)",
        "mask": "0x70f0", "match": "0x5000", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
        ],
    },
    {
        "index": 763, "bits": 16, "mnemonic": "sth", "format": "[c%d] sth (R%d,0),R%d",
        "mask": "0x70f0", "match": "0x5010", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
        ],
    },
    {
        "index": 764, "bits": 16, "mnemonic": "ld", "format": "[c%d] ld R%d,(R%d,0)",
        "mask": "0x70f0", "match": "0x5020", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
        ],
    },
    {
        "index": 765, "bits": 16, "mnemonic": "st", "format": "[c%d] st (R%d,0),R%d",
        "mask": "0x70f0", "match": "0x5030", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
        ],
    },
    {
        "index": 766, "bits": 16, "mnemonic": "ldh", "format": "[c%d] ldh R%d,(R%d+)",
        "mask": "0x70f0", "match": "0x5040", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
        ],
    },
    {
        "index": 767, "bits": 16, "mnemonic": "sth", "format": "[c%d] sth (R%d+),R%d",
        "mask": "0x70f0", "match": "0x5050", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
        ],
    },
    {
        "index": 768, "bits": 16, "mnemonic": "ld", "format": "[c%d] ld R%d,(R%d+)",
        "mask": "0x70f0", "match": "0x5060", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
        ],
    },
    {
        "index": 769, "bits": 16, "mnemonic": "st", "format": "[c%d] st (R%d+),R%d",
        "mask": "0x70f0", "match": "0x5070", "source": "gcc-supplement",
        "operands": [
            {"type": "const", "value": 7},
            {"type": "unsigned", "slices": [[12, 4]], "shift": 0},
            {"type": "unsigned", "slices": [[4, 4]], "shift": 0},
        ],
    },
    # 32-bit 5-bit-immediate compare-to-pair variants
    {
        "index": 770, "bits": 32, "mnemonic": "cmpeqn", "format": "[c%d] cmpeqn C%d:C%d,R%d,%d,C%d",
        "mask": "0x60e0fe00", "match": "0x60209200", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[6, 3]], "shift": 0},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[6, 3]], "shift": 0}, "addend": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "signed", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[9, 3]], "shift": 0},
        ],
    },
    {
        "index": 771, "bits": 32, "mnemonic": "cmpgeun", "format": "[c%d] cmpgeun C%d:C%d,R%d,%d,C%d",
        "mask": "0x60e0fe00", "match": "0x6020b200", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[6, 3]], "shift": 0},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[6, 3]], "shift": 0}, "addend": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[9, 3]], "shift": 0},
        ],
    },
    {
        "index": 772, "bits": 32, "mnemonic": "cmpgen", "format": "[c%d] cmpgen C%d:C%d,R%d,%d,C%d",
        "mask": "0x60e0fe00", "match": "0x6020d200", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[6, 3]], "shift": 0},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[6, 3]], "shift": 0}, "addend": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "signed", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[9, 3]], "shift": 0},
        ],
    },
    # 32-bit read PC (used in PIC prologues: mov R30, PC)
    {
        "index": 773, "bits": 32, "mnemonic": "mov", "format": "[c%d] mov R%d,PC",
        "mask": "0x7fe0fff8", "match": "0x60007f60", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
        ],
    },
    # 32-bit memory-indirect branch (switch jump tables) & subroutine call (vtables/fn ptrs)
    {
        "index": 774, "bits": 32, "mnemonic": "jmp", "format": "[c%d] jmp (R%d)",
        "mask": "0x60fffff8", "match": "0x60fd9800", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
        ],
    },
    {
        "index": 775, "bits": 32, "mnemonic": "jmpl", "format": "[c%d] jmpl (R%d)",
        "mask": "0x60fffff8", "match": "0x60fd9a00", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
        ],
    },
    # 32-bit quad-word (16-byte) post-increment load/store
    {
        "index": 776, "bits": 32, "mnemonic": "ldq", "format": "[c%d] ldq R%d:R%d,(R%d+)%d",
        "mask": "0x60e3ff08", "match": "0x60e1bf08", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 3]], "shift": 2},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[21, 3]], "shift": 2}, "addend": 3},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "signed", "slices": [[8, 4]], "shift": 4},
        ],
    },
    {
        "index": 777, "bits": 32, "mnemonic": "stq", "format": "[c%d] stq (R%d+)%d,R%d:R%d",
        "mask": "0x60e3ff08", "match": "0x60e3bf08", "source": "gcc-supplement",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "signed", "slices": [[8, 4]], "shift": 4},
            {"type": "unsigned", "slices": [[21, 3]], "shift": 2},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[21, 3]], "shift": 2}, "addend": 3},
        ],
    },
    # 32-bit double-precision FPU pair move & four-register double multiply-add
    {
        "index": 778, "bits": 32, "mnemonic": "fmovp", "format": "[c%d] fmovp R%d:R%d,FD%d",
        "mask": "0x60ffff08", "match": "0x60c0db00", "source": "gcc-supplement",
        "semantic_evidence": "corpus:uint64-conversion/pair-move",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[8, 4]], "shift": 1},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[8, 4]], "shift": 1}, "addend": 1},
            {"type": "unsigned", "slices": [[28, 4], [29, 1]], "shift": 0},
        ],
    },
    {
        "index": 779, "bits": 32, "mnemonic": "fmadd", "format": "[c%d] fmadd FD%d,FD%d,FD%d,FD%d",
        "mask": "0x60e0fc88", "match": "0x60c0dc00", "source": "gcc-supplement",
        "semantic_evidence": "corpus:libm:fma,hypot/source-aligned",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[7, 3]], "shift": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[10, 2]], "shift": 0},
        ],
    },
    {
        "index": 780, "bits": 32, "mnemonic": "fmsub", "format": "[c%d] fmsub FD%d,FD%d,FD%d,FD%d",
        "mask": "0x60e0fc88", "match": "0x60c0dc80", "source": "gcc-supplement",
        "semantic_evidence": "corpus:libm:fma,hypot/source-aligned",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[7, 3]], "shift": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[10, 2]], "shift": 0},
        ],
    },
    {
        "index": 781, "bits": 32, "mnemonic": "fnmadd", "format": "[c%d] fnmadd FD%d,FD%d,FD%d,FD%d",
        "mask": "0x60e0fc88", "match": "0x60c0dc08", "source": "gcc-supplement",
        "semantic_evidence": "corpus:libm:fma,hypot/source-aligned",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[7, 3]], "shift": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[10, 2]], "shift": 0},
        ],
    },
    {
        "index": 782, "bits": 32, "mnemonic": "fnmsub", "format": "[c%d] fnmsub FD%d,FD%d,FD%d,FD%d",
        "mask": "0x60e0fc88", "match": "0x60c0dc88", "source": "gcc-supplement",
        "semantic_evidence": "corpus:libm:fma,hypot/source-aligned",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[7, 3]], "shift": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[10, 2]], "shift": 0},
        ],
    },
    # Upper-bank pair move: the destination is an odd FD spelling. The
    # reverse form above rotates its five-bit source field rather than
    # multiplying it by two. See pair-move-corrections.txt for evidence.
    {
        "index": 783, "bits": 32, "mnemonic": "fmovp", "format": "[c%d] fmovp FD%d,R%d,R%d",
        "mask": "0x60e0ff80", "match": "0x60c0da80", "source": "gcc-supplement",
        "semantic_evidence": "corpus:uint64-conversion/pair-move",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "plus", "base": {"type": "unsigned", "slices": [[7, 4]], "shift": 1}, "addend": 1},
            {"type": "unsigned", "slices": [[29, 5]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
        ],
    },
    # Privilege-state save/set/restore sequences in pied identify selector 3
    # as PSR. The patent gives the register and transfer behavior, not these
    # numeric encodings. See system-state-corrections.txt for that distinction.
    {
        "index": 784, "bits": 32, "mnemonic": "mov", "format": "[c%d] mov R%d,PSR",
        "mask": "0x7fe0fff8", "match": "0x60007f18", "source": "gcc-supplement",
        "semantic_evidence": "corpus:pied:privilege-save-restore;US20040078549A1:Fig11,369",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
        ],
    },
    {
        "index": 785, "bits": 32, "mnemonic": "mov", "format": "[c%d] mov PSR,R%d",
        "mask": "0x7fe0fff8", "match": "0x61007f18", "source": "gcc-supplement",
        "semantic_evidence": "corpus:pied:privilege-save-restore;US20040078549A1:Fig11,395",
        "operands": [
            {"type": "unsigned", "slices": [[3, 3]], "shift": 0},
            {"type": "unsigned", "slices": [[21, 5]], "shift": 0},
        ],
    },
]


def eval_operand(op, word):
    t = op["type"]
    if t == "const":
        return op["value"]
    elif t in ("unsigned", "signed"):
        val = 0
        total_len = 0
        for pos, length in op["slices"]:
            bits = (word >> (pos - length)) & ((1 << length) - 1)
            val = (val << length) | bits
            total_len += length
        if t == "signed" and total_len > 0 and (val & (1 << (total_len - 1))):
            val -= (1 << total_len)
        return val << op["shift"]
    elif t == "plus":
        return eval_operand(op["base"], word) + op["addend"]
    raise ValueError(f"Unknown operand spec: {op}")
