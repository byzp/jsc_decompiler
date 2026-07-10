"""Standard MozJS34 (0xB973C02C) opcode table.

Based on SpiderMonkey 34 (ESR34) opcode definitions.
Aliased var ops use 1+3 encoding: hops(1B) + slot(3B big-endian),
total operand length 4 bytes (opcode length = 5).
"""

from ..opcodes import (
    _BINARY_NAME,
    _IDX_NAMES,
    _ALIASED_NAMES,
    _JUMP_NAMES,
    _CALL_NAMES,
    _ARG_NAMES,
    _LOCAL_NAMES,
)


def _default_len(name):
    """Default opcode length/use/push for MozJS34."""
    ln = 1
    use = 0
    push = 0
    if name in _IDX_NAMES:
        ln = 5
        push = 1
    elif name in _ALIASED_NAMES:
        ln = 5
        push = 1
    elif name in _JUMP_NAMES:
        ln = 5
        if name not in ("label", "gosub", "backpatch"):
            use = 1
            push = 1
    elif name in _CALL_NAMES:
        ln = 3
        use = -1
        push = 1
    elif name in _ARG_NAMES:
        ln = 3
        push = 1
    elif name in _LOCAL_NAMES:
        ln = 4
        push = 1
    elif name == "tableswitch":
        ln = -1
        use = 1
    elif name == "uint16":
        ln = 3
        push = 1
    elif name == "uint24":
        ln = 4
        push = 1
    elif name == "int8":
        ln = 2
        push = 1
    elif name == "int32":
        ln = 5
        push = 1
    elif name == "popn":
        ln = 3
        use = -1
    elif name == "pick":
        ln = 2
    elif name in ("pop", "popv"):
        ln = 1
        use = 1
    elif name == "dup":
        ln = 1
        use = 1
        push = 2
    elif name == "dup2":
        ln = 1
        use = 2
        push = 4
    elif name == "swap":
        ln = 1
        use = 2
        push = 2
    elif name == "newinit":
        ln = 5
        push = 1
    elif name == "newarray":
        ln = 4
        push = 1
    elif name == "initelem_array":
        ln = 4
    elif name == "enumconstelem":
        ln = 4
    elif name == "iter":
        ln = 2
        use = 1
        push = 1
    elif name == "loopentry":
        ln = 2
    elif name in ("lineno",):
        ln = 3
    elif name in ("undefined", "zero", "one", "null", "this", "false", "true"):
        push = 1
    elif name == "notearg":
        pass
    elif name == "callee":
        push = 1
    elif name == "hole":
        push = 1
    elif name == "stop":
        pass
    elif name in ("typeof", "typeofexpr"):
        use = 1
        push = 1
    elif name == "void":
        use = 1
        push = 1
    elif name == "neg":
        use = 1
        push = 1
    elif name in (
        "add",
        "sub",
        "mul",
        "div",
        "mod",
        "bitor",
        "bitxor",
        "bitand",
        "lsh",
        "rsh",
        "ursh",
        "eq",
        "ne",
        "lt",
        "le",
        "gt",
        "ge",
        "stricteq",
        "strictne",
        "in",
        "instanceof",
    ):
        use = 2
        push = 1
    elif name in ("not", "bitnot"):
        use = 1
        push = 1
    elif name in (
        "setprop",
        "initprop",
        "setgname",
        "setintrinsic",
        "getter",
        "setter",
    ):
        use = 2
        push = 1
    elif name in ("setelem",):
        use = 3
        push = 1
    elif name in (
        "getprop",
        "callprop",
        "callelem",
        "getelem",
        "enumelem",
        "getgname",
        "getintrinsic",
        "callgname",
        "callintrinsic",
    ):
        use = 1
        push = 1
    elif name == "length":
        use = 1
        push = 1
    elif name == "rest":
        push = 1
    elif name == "arguments":
        push = 1
    elif name in ("setrval", "throwing"):
        use = 1
    elif name == "yield":
        use = 1
        push = 1
    elif name == "throw":
        use = 1
    elif name == "arraypush":
        use = 2
    elif name == "finally":
        push = 2
    elif name == "exception":
        push = 1
    elif name == "spread":
        use = 3
        push = 1
    return (ln, use, push)


# Build the MozJS34 opcode table.
JSOP_MOZJS = {}

for oc in range(0xE6):
    name = _BINARY_NAME.get(oc, f"unused{oc}")
    ln, use, push = _default_len(name)
    if name in _ALIASED_NAMES:
        ln = 5  # 1 opcode + 1 byte hops + 3 bytes slot
    JSOP_MOZJS[oc] = {
        "name": name,
        "image": None,
        "length": ln,
        "use": use,
        "push": push,
    }


def get_op_info(op_byte):
    info = JSOP_MOZJS.get(op_byte)
    if info:
        return info
    return {
        "name": f"unk_{op_byte:02x}",
        "image": None,
        "length": 1,
        "use": 0,
        "push": 0,
    }
