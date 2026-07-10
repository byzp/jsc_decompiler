"""Decompilation engine – walks ops and produces JavaScript text."""

from parser.opcodes import IMAGE_OPS, NOOP_NAMES
from .stack import StackItem

_OBJECT_LITERAL_SKIP = object()

import re as _re


def _is_numeric(s):
    return bool(_re.match(r"^-?\d+(\.\d+)?$", s))


def _js_str(s):
    import json

    if not s:
        return '""'
    return json.dumps(s, ensure_ascii=True)


class DecompileEngine:
    def __init__(self, func, parent_func=None, dump_bytecode=False):
        self.d = func
        self.atoms = func.atoms
        self.consts = func.consts
        self._parent_func = parent_func
        self._dump_bytecode = dump_bytecode
        self._local_vars = {}
        self._stack = []
        self.script = {}
        self.logic_stacks = {}
        self.branch_map = {}
        self.loop_entries = set()
        self._sub_level = 0
        self._open_ifs = []  # stack of (ifeq_offset, target_offset)
        self._block_depth = 0  # track switch/try/block opens that need }
        self._try_depth = 0  # track try block nesting
        self._try_if_base = []  # stack: len(open_ifs) at each try entry
        self._in_catch = (
            False  # inside catch block (between exception and finally/leaveblock)
        )
        self._catch_closed = False  # catch block's } already emitted by leaveblock
        self._switch_labels = {}  # target_offset → 'case val:' / 'default:'
        self._switch_stack = (
            []
        )  # stack of (in_switch, switch_labels, switch_default_target, switch_ifs_start, block_depth_at_switch) for nested switches
        self._in_switch = False
        self._switch_default_target = 0
        self._switch_ifs_start = 0

        # Pre-populate local_vars from var_slot_names
        for vsi, vsname in enumerate(func.var_slot_names):
            if vsname and vsi not in self._local_vars:
                self._local_vars[vsi] = StackItem(name=vsname)

        # Iterator loop tracking
        self._iter_loops = (
            {}
        )  # iternext_offset → {iter_offset, obj_value, flags, loop_var, loop_end}
        self._iter_suppress_setlocal = (
            None  # localno to suppress (from iternext+setlocal pattern)
        )
        self._iter_suppress_setarg = (
            None  # argno to suppress (from iternext+setarg pattern)
        )
        self._iter_destruct = False  # True after iternext in destructuring for-in
        self._iter_gotos = set()  # offsets of gotos that are part of iter loops
        self._iter_ifnes = set()  # offsets of ifnes that are part of iter loops
        self._iter_moreiters = set()  # offsets of moreiters in iter loops
        self._iter_pops = set()  # offsets of pops between moreiter and enditer
        self._iter_loopentries = set()  # offsets of loopentry in iter loops
        self._deffun_names = set()  # names declared by deffun
        self._build_iter_loop_map()
        self._prescan_deffun_names()

    def _build_iter_loop_map(self):
        """Pre-scan ops to identify for-in/for-of iterator loops."""
        ops = self.d.ops
        n = len(ops)
        for i in range(n):
            if ops[i]["nm"] != "iter":
                continue
            iter_off = ops[i]["off"]
            flags = ops[i]["params"].get("flags", 0)
            iternext_off = None
            moreiter_off = None
            loop_end_off = None
            goto_off = None
            ifne_off = None
            for j in range(i + 1, n):
                nm_j = ops[j]["nm"]
                if nm_j == "goto" and goto_off is None and iternext_off is None:
                    goto_off = ops[j]["off"]
                elif nm_j == "iternext" and iternext_off is None:
                    iternext_off = ops[j]["off"]
                elif nm_j == "moreiter":
                    moreiter_off = ops[j]["off"]
                elif nm_j == "ifne" and moreiter_off is not None and ifne_off is None:
                    ifne_off = ops[j]["off"]
                    for k in range(j + 1, n):
                        if ops[k]["nm"] == "enditer":
                            loop_end_off = ops[k]["off"]
                            break
                    break
                elif nm_j == "iter":
                    break
            if iternext_off is not None:
                self._iter_loops[iternext_off] = {
                    "iter_off": iter_off,
                    "flags": flags,
                    "moreiter_off": moreiter_off,
                    "loop_end_off": loop_end_off,
                    "obj_value": None,
                    "loop_var": None,
                }
                if goto_off is not None:
                    self._iter_gotos.add(goto_off)
                if ifne_off is not None:
                    self._iter_ifnes.add(ifne_off)
                if moreiter_off is not None:
                    self._iter_moreiters.add(moreiter_off)
                if moreiter_off is not None and loop_end_off is not None:
                    for k in range(n):
                        if (
                            ops[k]["off"] >= moreiter_off
                            and ops[k]["off"] <= loop_end_off
                        ):
                            if ops[k]["nm"] == "pop":
                                self._iter_pops.add(ops[k]["off"])
                            elif ops[k]["nm"] == "loopentry":
                                self._iter_loopentries.add(ops[k]["off"])

    def _prescan_deffun_names(self):
        """Pre-scan ops to find all deffun names, so defvar can skip them."""
        for op in self.d.ops:
            if op["nm"] == "deffun":
                idx = op["params"].get("idx", 0)
                fname = self._atom(idx) if idx < len(self.atoms) else f"f{idx}"
                if fname and self._is_ident(fname):
                    self._deffun_names.add(fname)

    def run(self):
        for op in self.d.ops:
            try:
                self._dispatch(op)
            except Exception:
                pass
        # Close any remaining open blocks at function end
        close_count = len(self._open_ifs) + self._block_depth
        if close_count > 0:
            last_off = self.d.ops[-1]["off"] if self.d.ops else 0
            self._open_ifs.clear()
            self._block_depth = 0
            self._w(last_off, "}" * close_count)

    def _push(self, **kw):
        self._stack.append(StackItem(**kw))

    def _pop(self):
        return self._stack.pop() if self._stack else StackItem()

    def _resolve_aliased_var(self, hops, slot):
        """Resolve aliased var (hops+slot) to variable name from scope chain.

        In MozJS34, hops=0 means the CURRENT function's own scope (aliased vars
        are locals that have been captured by closures). hops=1 means the
        enclosing scope, hops=2 means two levels up, etc.
        """
        scope = self._parent_func
        for _ in range(hops):
            if scope is None:
                break
            parent = getattr(scope, "_parent_func", None)
            scope = parent
        if scope is None:
            scope = self.d
        lv = self._local_vars.get(slot) if scope is self.d else None
        if lv:
            return lv.name
        if slot < len(scope.var_slot_names):
            return scope.var_slot_names[slot]
        if slot < len(scope.argvs):
            return scope.argvs[slot]
        parent = getattr(scope, "_parent_func", None)
        while parent is not None:
            if slot < len(parent.var_slot_names):
                return parent.var_slot_names[slot]
            if slot < len(parent.argvs):
                return parent.argvs[slot]
            parent = getattr(parent, "_parent_func", None)
        return f"l{slot}"

    def _negate_condition(self, cond):
        """Negate a condition for ifeq (which jumps when true, so we need the negated form).

        For comparisons: negate the operator (=== -> !==, < -> >=, etc.)
        For !expr: double negation simplifies to expr
        For other expressions: wrap in !()
        """
        _NEGATE_OPS = {
            "===": "!==",
            "!==": "===",
            "==": "!=",
            "!=": "==",
            "<": ">=",
            ">=": "<",
            ">": "<=",
            "<=": ">",
            "in": " not in ",
        }
        import re

        # Try to match (l OP r) patterns
        m = re.match(r"^\((.+?) (===|!==|==|!=|<=|>=|<|>) (.+?)\)$", cond)
        if m:
            l, op, r = m.group(1), m.group(2), m.group(3)
            neg_op = _NEGATE_OPS.get(op)
            if neg_op:
                return f"({l} {neg_op} {r})"
        # Try (l in r) pattern
        m = re.match(r"^\((.+?) in (.+?)\)$", cond)
        if m:
            l, r = m.group(1), m.group(2)
            return f"(!({l} in {r}))"
        # Try (!expr) pattern – double negation simplifies
        m = re.match(r"^\(!(.+)\)$", cond)
        if m:
            return f"({m.group(1)})"
        # Fallback: wrap in !()
        return f"(!({cond}))"

    def _atom(self, idx):
        if 0 <= idx < len(self.atoms):
            return self.atoms[idx]
        parent = self._parent_func
        while parent is not None:
            if 0 <= idx < len(parent.atoms):
                return parent.atoms[idx]
            parent = getattr(parent, "_parent_func", None)
        return ""

    _JS_RESERVED = frozenset(
        {
            "break",
            "case",
            "catch",
            "class",
            "const",
            "continue",
            "debugger",
            "default",
            "delete",
            "do",
            "else",
            "export",
            "extends",
            "finally",
            "for",
            "function",
            "if",
            "import",
            "in",
            "instanceof",
            "new",
            "return",
            "super",
            "switch",
            "this",
            "throw",
            "try",
            "typeof",
            "var",
            "void",
            "while",
            "with",
            "yield",
            "enum",
            "implements",
            "interface",
            "let",
            "package",
            "private",
            "protected",
            "public",
            "static",
            "await",
            "null",
            "true",
            "false",
            "set",
            "get",
        }
    )

    @staticmethod
    def _is_ident(s):
        if not s:
            return False
        if s[0] not in "_$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            return False
        return all(
            c in "_$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
            for c in s
        )

    def _prop(self, idx):
        name = self._atom(idx)
        if self._is_ident(name) and name not in self._JS_RESERVED:
            return "." + name
        return "[" + _js_str(name) + "]"

    def _push_name(self, idx):
        name = self._atom(idx)
        if name and self._is_ident(name):
            return name
        return f"_v{idx}"

    def _w(self, idx, text):
        if idx in self.script:
            self.script[idx] += text
        else:
            self.script[idx] = text

    # ────────────────────────────────────────────────────
    def _dispatch(self, op):
        nm = op["nm"]
        p = op["params"]
        o = op["off"]

        # Check for pending switch case/default labels at this offset first
        # (before closing if-blocks, so default: comes before })
        if o in self._switch_labels:
            labels = self._switch_labels[o]
            has_default = any(lb == "default:" for lb in labels)
            if has_default:
                # Close if-blocks from previous case before default
                if self._in_switch:
                    new_ifs = len(self._open_ifs) - self._switch_ifs_start
                    if new_ifs > 0:
                        self._w(o, "}" * new_ifs)
                        self._open_ifs = self._open_ifs[: self._switch_ifs_start]
                self._w(o, "default:\nbreak;\n}")
                if self._block_depth > 0:
                    self._block_depth -= 1
                # Restore previous switch state
                if self._switch_stack:
                    prev = self._switch_stack.pop()
                    self._in_switch = prev[0]
                    self._switch_labels = prev[1]
                    self._switch_default_target = prev[2]
                    self._switch_ifs_start = prev[3]
                else:
                    self._in_switch = False
            else:
                # Close if-blocks from previous case before writing new case label
                new_ifs = len(self._open_ifs) - self._switch_ifs_start
                if new_ifs > 0:
                    prefix = "\n".join("}" for _ in range(new_ifs)) + "\n"
                    self._open_ifs = self._open_ifs[: self._switch_ifs_start]
                else:
                    prefix = ""
                self._w(o, prefix + "\n".join(labels))
            del self._switch_labels[o]

        # Close any if-blocks whose target matches this offset
        while self._open_ifs and self._open_ifs[-1][1] == o:
            self._open_ifs.pop()
            self._w(o, "}")

        if nm == "implicitthis" and self.d.is_cocos:
            return
        if nm in NOOP_NAMES:
            return

        # return / value discard
        if nm == "return":
            if self._stack:
                rv = self._pop()
                val = rv.get_value()
                if val and val != "undefined":
                    self._w(o, "return " + val + ";")
                else:
                    self._w(o, "return;")
            else:
                self._w(o, "return;")
            # Close any open if-blocks at function exit
            if self._open_ifs:
                close_count = len(self._open_ifs)
                self._open_ifs.clear()
                self._w(o, "}" * close_count)
        elif nm in ("pop", "popv", "setrval"):
            rv = self._pop()
            s = rv.get_value()
            # Skip pops that are part of iterator loop control flow
            if o in self._iter_pops:
                pass
            elif s and s != "undefined":
                self._w(o, s + ";")
        elif nm == "popn":
            for _ in range(p.get("n", 0)):
                self._pop()

        # stack manipulation
        elif nm == "dup":
            v = self._pop()
            self._push(**v.copy())
            self._push(**v.copy())
        elif nm == "dup2":
            v1 = self._pop()
            v2 = self._pop()
            self._push(**v2.copy())
            self._push(**v1.copy())
            self._push(**v2.copy())
            self._push(**v1.copy())
        elif nm == "swap":
            v1 = self._pop()
            v2 = self._pop()
            self._push(**v1.copy())
            self._push(**v2.copy())
        elif nm == "pick":
            n = p.get("n", 0)
            temp = [self._pop() for _ in range(n)]
            nth = self._pop()
            for i in range(n - 1, -1, -1):
                self._push(**temp[i].copy())
            self._push(**nth.copy())

        # branching
        elif nm == "ifeq":
            v = self._pop()
            tgt = o + p.get("offset", 0)
            cond = v.get_value()
            if p.get("offset", 0) > 0:
                # ifeq jumps when true = skip body when cond is true
                # So we need to negate: if (!(cond)) { body }
                # For comparisons, negate the operator directly
                cond = self._negate_condition(cond)
                self._w(o, f"if ({cond}) {{")
                self._open_ifs.append((o, tgt))
                self.branch_map[o] = {"goto": tgt, "type": "if"}
            else:
                self.loop_entries.add(tgt)
                self.branch_map[tgt] = {"goto": o, "type": "loop_head", "cond": cond}

        elif nm == "ifne":
            v = self._pop()
            tgt = o + p.get("offset", 0)
            # Skip ifnes that are part of iterator loop control flow
            if o in self._iter_ifnes:
                pass
            elif p.get("offset", 0) > 0:
                self._w(o, "if (" + v.get_value() + ") {")
                self._open_ifs.append((o, tgt))
                self.branch_map[o] = {"goto": tgt, "type": "if"}
            else:
                self.loop_entries.add(tgt)
                self.branch_map[tgt] = {
                    "goto": o,
                    "type": "loop_head",
                    "cond": v.get_value(),
                }

        elif nm == "loophead":
            pass

        elif nm == "loopentry":
            # Skip loopentry in iterator loops (already handled by for-in/for-of structure)
            if o in self._iter_loopentries:
                pass

        elif nm == "goto":
            tgt = o + p.get("offset", 0)
            # Skip gotos that are part of iterator loop control flow
            if o in self._iter_gotos:
                pass
            elif p.get("offset", 0) < 0:
                if tgt in self.loop_entries:
                    self._w(o, "continue;")
                else:
                    pass
            elif p.get("offset", 0) > 0:
                if self._in_switch:
                    if tgt == self._switch_default_target:
                        self._w(o, "break;")
                    elif any(t == tgt for _, t in self._open_ifs):
                        while self._open_ifs and self._open_ifs[-1][1] == tgt:
                            self._open_ifs.pop()
                        self._w(o, "")
                        self._w(tgt, "}")
                    else:
                        self._w(o, "break;")
                elif self._try_depth > 0:
                    pass
                elif tgt >= (self.d.ops[-1]["off"] if self.d.ops else 0) - 8:
                    close_count = len(self._open_ifs)
                    self._open_ifs.clear()
                    self._w(o, "")
                    self._w(tgt, "}" * close_count)
        elif nm == "or":
            v = self._pop()
            self.logic_stacks[o] = {
                "type": "or",
                "goto": o + p.get("offset", 0),
                "value": v.get_value(),
            }
            self._push(tp="logic")
        elif nm == "and":
            v = self._pop()
            self.logic_stacks[o] = {
                "type": "and",
                "goto": o + p.get("offset", 0),
                "value": v.get_value(),
            }
            self._push(tp="logic")

        # function calls
        elif nm in ("call", "new", "funcall", "eval", "funapply"):
            argc = p.get("argc", 0)
            argv = [self._pop() for _ in range(argc)]
            # After args, next is thisArg, then callee
            this_ = self._pop()
            callee = self._pop()
            fn = callee.name if callee.name is not None else callee.get_value()
            args = ",".join(a.get_value() for a in reversed(argv))
            pre = "new " if nm == "new" else ""
            call_str = pre + fn + "(" + args + ")"
            self._push(tp="script", script=call_str)

        # property access
        elif nm in ("getprop", "callprop"):
            obj = self._pop()
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            self._push(name=ov + self._prop(p.get("idx", 0)))
        elif nm == "setprop":
            val = self._pop()
            obj = self._pop()
            aname_expr = self._prop(p.get("idx", 0))
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            val_str = val.get_value()
            if val.type == "function":
                fv = str(val.value) if val.value is not None else ""
                if not fv.startswith("__L_"):
                    val_str = "function(){ " + val_str + " }"
            self._push(tp="script", script=f"{ov}{aname_expr}={val_str}")
        elif nm == "delprop":
            obj = self._pop()
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            self._push(tp="script", script=f'delete {ov}{self._prop(p.get("idx",0))}')
        elif nm in ("getelem", "callelem", "enumelem"):
            idx = self._pop()
            obj = self._pop()
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            self._push(name=f"{ov}[{idx.get_value()}]")
        elif nm == "setelem":
            val = self._pop()
            idx = self._pop()
            obj = self._pop()
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            self._push(tp="script", script=f"{ov}[{idx.get_value()}]={val.get_value()}")
        elif nm == "delelem":
            idx = self._pop()
            obj = self._pop()
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            self._push(tp="script", script=f"delete {ov}[{idx.get_value()}]")
        elif nm == "length":
            obj = self._pop()
            ov = obj.get_value()
            if _is_numeric(ov):
                ov = "(" + ov + ")"
            self._push(tp="script", script=ov + ".length")

        # name resolution
        elif nm in ("callname", "callgname"):
            idx = p.get("idx", 0)
            name_val = self._push_name(idx)
            self._push(name=name_val)
            self._push(tp="void", name=None, value=None)

        elif nm in ("name", "bindname", "implicitthis", "getgname", "callintrinsic"):
            self._push(name=self._push_name(p.get("idx", 0)))

        elif nm in ("setname", "setgname", "setconst"):
            val = self._pop()
            s = self._pop()
            name = s.name if s.name else self._push_name(p.get("idx", 0))
            fn_body = ""
            if val.type == "function":
                fv = str(val.value) if val.value is not None else ""
                if fv.startswith("__L_"):
                    fn_body = fv
                else:
                    fn_body = f"function(){{ {fv} }}"
            else:
                fn_body = val.get_value()
            self._push(tp="script", name=name, script=f"{name}={fn_body}")

        elif nm == "delname":
            self._push(tp="script", script=f'delete {self._push_name(p.get("idx",0))}')

        # variable declarations
        elif nm == "defvar":
            name = self._push_name(p.get("idx", 0))
            if name not in self._deffun_names:
                self._w(o, "var " + name + ";")
        elif nm == "defconst":
            name = self._push_name(p.get("idx", 0))
            if name not in self._deffun_names:
                self._w(o, "var " + name + ";")
        elif nm == "deffun":
            idx = p.get("idx", 0)
            fname = self._atom(idx) if idx < len(self.atoms) else f"f{idx}"
            if not fname or not self._is_ident(fname):
                fname = f"f{idx}"
            is_gen = idx < len(self.d.children) and (
                bool(self.d.children[idx].sbits & (1 << 8))
                or any(op["nm"] == "yield" for op in self.d.children[idx].ops)
            )
            fn_kw = "function*" if is_gen else "function"
            self._w(o, f"{fn_kw} {fname}(__A_{idx}__) {{ __F_{idx}__ }}")
            self._deffun_names.add(fname)
        elif nm == "lambda":
            idx = p.get("idx", 0)
            self._push(tp="function", value=f"__L_{idx}__")
        elif nm == "getfunns":
            self._push(tp="function", value=p.get("idx", 0))

        # args / locals
        elif nm == "getarg" or nm == "callarg":
            an = p.get("argno", 0)
            name = self.d.argvs[an] if an < len(self.d.argvs) else f"a{an}"
            self._push(name=name)
        elif nm == "setarg":
            val = self._pop()
            an = p.get("argno", 0)
            name = self.d.argvs[an] if an < len(self.d.argvs) else f"a{an}"
            # Suppress setarg right after iternext (it's the loop variable assignment)
            if (
                self._iter_suppress_setarg is not None
                and self._iter_suppress_setarg == an
            ):
                self._iter_suppress_setarg = None
                item = StackItem(tp="script", name=name, script=name)
                self._push(**item.copy())
                return
            self._push(tp="script", name=name, script=f"{name}={val.get_value()}")
        elif nm == "getlocal" or nm == "calllocal":
            ln = p.get("localno", 0)
            lv = self._local_vars.get(ln)
            if lv:
                self._push(name=lv.name)
            else:
                self._push(name=f"l{ln}")
        elif nm == "setlocal":
            val = self._pop()
            ln = p.get("localno", 0)
            # Suppress setlocal right after iternext (it's the loop variable assignment)
            if (
                self._iter_suppress_setlocal is not None
                and self._iter_suppress_setlocal == ln
            ):
                self._iter_suppress_setlocal = None
                name = "l%d" % ln
                item = StackItem(tp="script", name=name, script=name)
                self._local_vars[ln] = item
                self._push(**item.copy())
                return
            name = f"l{ln}"
            item = StackItem(tp="script", name=name, script=f"{name}={val.get_value()}")
            self._local_vars[ln] = item
            self._push(**item.copy())

        # inc/dec arg/local/prop/elem shortcuts
        # Prefix: incX, decX (e.g. incarg, declocal, incprop, incelem, incaliasedvar, decaiasedvar)
        # Postfix: Xinc, Xdec (e.g. arginc, localdec, propinc, eleminc, aliasedvarinc, aliasedvardec)
        elif nm in (
            "incarg",
            "decarg",
            "arginc",
            "argdec",
            "inclocal",
            "declocal",
            "localinc",
            "localdec",
            "incaliasedvar",
            "decaiasedvar",
            "aliasedvarinc",
            "aliasedvardec",
            "incprop",
            "decprop",
            "propinc",
            "propdec",
            "incelem",
            "decelem",
            "eleminc",
            "elemdec",
            "incname",
            "decname",
            "nameinc",
            "namedec",
            "incgname",
            "decgname",
            "gnameinc",
            "gnamedec",
        ):
            is_prefix = nm.startswith("inc") or nm.startswith("dec")
            is_inc = "inc" in nm and "dec" not in nm
            op = "++" if is_inc else "--"

            if nm in ("incarg", "decarg", "arginc", "argdec"):
                an = p.get("argno", 0)
                name = self.d.argvs[an] if an < len(self.d.argvs) else f"a{an}"
                if is_prefix:
                    self._push(tp="script", script=f"{op}{name}")
                else:
                    self._push(tp="script", script=f"({name}{op})")
            elif nm in ("inclocal", "declocal", "localinc", "localdec"):
                ln = p.get("localno", 0)
                lv = self._local_vars.get(ln)
                name = lv.name if lv else f"l{ln}"
                if is_prefix:
                    self._push(tp="script", script=f"{op}{name}")
                else:
                    self._push(tp="script", script=f"({name}{op})")
            elif nm in (
                "incaliasedvar",
                "decaiasedvar",
                "aliasedvarinc",
                "aliasedvardec",
            ):
                var_name = self._resolve_aliased_var(p.get("hops", 0), p.get("slot", 0))
                if is_prefix:
                    self._push(tp="script", script=f"{op}{var_name}")
                else:
                    self._push(tp="script", script=f"({var_name}{op})")
            elif nm in (
                "incname",
                "decname",
                "nameinc",
                "namedec",
                "incgname",
                "decgname",
                "gnameinc",
                "gnamedec",
            ):
                name = self._push_name(p.get("idx", 0))
                if is_prefix:
                    self._push(tp="script", script=f"{op}{name}")
                else:
                    self._push(tp="script", script=f"({name}{op})")
            elif nm in ("incprop", "decprop", "propinc", "propdec"):
                obj = self._pop()
                aname_expr = self._prop(p.get("idx", 0))
                ov = obj.get_value()
                if _is_numeric(ov):
                    ov = "(" + ov + ")"
                if is_prefix:
                    self._push(tp="script", script=f"{op}{ov}{aname_expr}")
                else:
                    self._push(tp="script", script=f"({ov}{aname_expr}{op})")
            elif nm in ("incelem", "decelem", "eleminc", "elemdec"):
                idx = self._pop()
                obj = self._pop()
                ov = obj.get_value()
                if _is_numeric(ov):
                    ov = "(" + ov + ")"
                if is_prefix:
                    self._push(tp="script", script=f"{op}{ov}[{idx.get_value()}]")
                else:
                    self._push(tp="script", script=f"({ov}[{idx.get_value()}]{op})")

        elif nm == "arguments":
            self._push(name="arguments")
        elif nm == "rest":
            self._push(name="...rest")

        # aliased vars
        elif nm in ("getaliasedvar", "callaliasedvar"):
            var_name = self._resolve_aliased_var(p.get("hops", 0), p.get("slot", 0))
            if not var_name:
                var_name = f'_av{p.get("slot", 0)}'
            self._push(name=var_name)
        elif nm == "setaliasedvar":
            val = self._pop()
            var_name = self._resolve_aliased_var(p.get("hops", 0), p.get("slot", 0))
            if not var_name:
                var_name = f'_av{p.get("slot", 0)}'
            self._push(
                tp="script", name=var_name, script=f"{var_name}={val.get_value()}"
            )

        # literals
        elif nm == "string":
            idx = p.get("atomIndex", p.get("idx", 0))
            self._push(tp="string", value=self._atom(idx))
        elif nm == "double":
            idx = p.get("constIndex", p.get("idx", 0))
            if 0 <= idx < len(self.consts):
                self._push(tp="number", value=self.consts[idx][1])
            else:
                self._push(tp="number", value=0)
        elif nm == "int8":
            self._push(tp="number", value=p.get("val", 0))
        elif nm in ("uint16", "uint24"):
            self._push(tp="number", value=p.get("val", 0))
        elif nm == "int32":
            self._push(tp="number", value=p.get("val", 0))
        elif nm == "zero":
            self._push(tp="number", value=0)
        elif nm == "one":
            self._push(tp="number", value=1)
        elif nm == "null":
            self._push(tp="null", value="null")
        elif nm == "true":
            self._push(tp="boolean", value=True)
        elif nm == "false":
            self._push(tp="boolean", value=False)
        elif nm == "undefined":
            self._push(tp="undefined", value="undefined")
        elif nm == "void":
            self._pop()
            self._push(tp="undefined", value="undefined")
        elif nm == "this":
            self._push(name="this")
        elif nm == "hole":
            self._push(tp="void", value=None)
        elif nm == "regexp":
            self._push(tp="regexp", value="/re/")

        # arithmetic / comparisons
        elif nm in IMAGE_OPS:
            r = self._pop()
            l = self._pop()
            sym = IMAGE_OPS.get(nm, "?")
            self._push(tp="script", script=f"({l.get_value()} {sym} {r.get_value()})")
        elif nm in (
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
            r = self._pop()
            l = self._pop()
            sym_map = {
                "eq": "==",
                "ne": "!=",
                "lt": "<",
                "le": "<=",
                "gt": ">",
                "ge": ">=",
                "stricteq": "===",
                "strictne": "!==",
                "in": "in",
                "instanceof": "instanceof",
            }
            self._push(
                tp="script", script=f"({l.get_value()} {sym_map[nm]} {r.get_value()})"
            )
        elif nm == "not":
            v = self._pop()
            self._push(tp="script", script=f"(!{v.get_value()})")
        elif nm == "bitnot":
            v = self._pop()
            self._push(tp="script", script=f"(~{v.get_value()})")
        elif nm == "neg":
            v = self._pop()
            self._push(tp="script", script=f"(-{v.get_value()})")
        elif nm in ("typeof", "typeofexpr"):
            self._push(tp="script", script="typeof " + self._pop().get_value())

        # objects / arrays
        elif nm == "newinit":
            kind = p.get("kind", 0)
            self._push(tp="object", value={} if kind == 0 else {})
        elif nm == "newarray":
            self._push(tp="array", value=[])
        elif nm in ("newobject", "object"):
            self._push(tp="object", value={})
        elif nm == "initprop":
            val = self._pop()
            obj = self._pop()
            aname = self._atom(p.get("idx", 0))
            if self._is_ident(aname):
                key_str = aname
            else:
                key_str = _js_str(aname)
            if isinstance(obj.value, dict):
                obj.value[key_str] = val
            self._push(
                tp="object", value=obj.value if isinstance(obj.value, dict) else {}
            )
        elif nm in ("initelem", "initelem_inc"):
            val = self._pop()
            name = self._pop()
            obj = self._pop()
            if isinstance(obj.value, dict):
                obj.value[name.get_value()] = val
            self._push(
                tp="object", value=obj.value if isinstance(obj.value, dict) else {}
            )
        elif nm == "initelem_array":
            val = self._pop()
            arr = self._pop()
            if isinstance(arr.value, list):
                arr.value.append(val)
            self._push(
                tp="array", value=arr.value if isinstance(arr.value, list) else []
            )
        elif nm == "arraypush":
            val = self._pop()
            arr = self._pop()
            self._push(
                tp="array", value=arr.value if isinstance(arr.value, list) else []
            )

        # try / catch
        elif nm == "try":
            self._w(o, "try {")
            self._block_depth += 1
            self._try_depth += 1
            self._try_if_base.append(len(self._open_ifs))
            self._catch_closed = False
        elif nm == "throw":
            self._w(o, "throw " + self._pop().get_value() + ";")
        elif nm == "throwing":
            self._pop()
        elif nm == "exception":
            if self._try_if_base:
                base = self._try_if_base[-1]
                close_ifs = len(self._open_ifs) - base
            else:
                base = 0
                close_ifs = len(self._open_ifs)
            if close_ifs > 0:
                self._w(o, "}" * close_ifs)
                self._open_ifs = self._open_ifs[:base]
            self._w(o, "} catch(e) {")
            self._push(name="e")
            self._in_catch = True
        elif nm == "finally":
            if self._try_if_base:
                base = self._try_if_base[-1]
                close_ifs = len(self._open_ifs) - base
            else:
                base = 0
                close_ifs = len(self._open_ifs)
            if close_ifs > 0:
                self._w(o, "}" * close_ifs)
                self._open_ifs = self._open_ifs[:base]
            if self._in_catch:
                self._w(o, "} finally {")
                self._in_catch = False
            else:
                self._w(o, "} finally {")
            self._push(tp="void", value=None)
            self._push(tp="void", value=None)
        elif nm == "retsub":
            self._w(o, "}")
            if self._block_depth > 0:
                self._block_depth -= 1
            if self._try_depth > 0:
                self._try_depth -= 1
            if self._try_if_base:
                self._try_if_base.pop()
            self._pop()
            self._pop()
        elif nm in ("leaveblock", "leaveblockexpr"):
            has_finally_after = False
            if self._in_catch:
                for si in range(len(self.d.ops)):
                    if self.d.ops[si]["off"] == o:
                        for sj in range(si + 1, min(si + 5, len(self.d.ops))):
                            if self.d.ops[sj]["nm"] == "finally":
                                has_finally_after = True
                                break
                        break
            if self._in_catch and has_finally_after:
                self._in_catch = False
                self._catch_closed = True
            elif self._catch_closed:
                self._catch_closed = False
            elif self._in_catch:
                self._w(o, "}")
                self._in_catch = False
                self._catch_closed = True
            elif self._block_depth > 0:
                self._w(o, "}")
            if self._block_depth > 0:
                self._block_depth -= 1
            if self._try_depth > 0:
                self._try_depth -= 1
            if self._try_if_base:
                self._try_if_base.pop()
            self._in_switch = False
            self._switch_labels = {}

        # switch
        elif nm == "condswitch":
            # Save current switch state before starting new one
            self._switch_stack.append(
                (
                    self._in_switch,
                    dict(self._switch_labels),
                    self._switch_default_target,
                    self._switch_ifs_start,
                )
            )
            v = self._stack[-1] if self._stack else StackItem()
            self._w(o, "switch(" + v.get_value() + "){")
            self._block_depth += 1
            self._in_switch = True
            self._switch_labels = {}
            self._switch_ifs_start = len(self._open_ifs)
        elif nm == "case":
            val = self._pop()  # pop case value; switch value stays on stack
            tgt = o + p.get("offset", 0)
            label_text = "case " + val.get_value() + ":"
            if tgt not in self._switch_labels:
                self._switch_labels[tgt] = []
            self._switch_labels[tgt].append(label_text)
        elif nm == "default":
            if self._stack:
                self._pop()  # pop the switch value
            tgt = o + p.get("offset", 0)
            self._switch_default_target = tgt
            if tgt not in self._switch_labels:
                self._switch_labels[tgt] = []
            self._switch_labels[tgt].append("default:")

        # misc
        elif nm in (
            "spread",
            "getxprop",
            "getter",
            "setter",
            "enumconstelem",
            "setintrinsic",
            "bindgname",
            "setcall",
            "proxy",
            "tableswitch",
            "getintrinsic",
            "bindintrinsic",
        ):
            pass
        elif nm == "iter":
            obj = self._pop()
            obj_val = obj.get_value()
            # Store the iterated object for later for-in/for-of header generation
            self._current_iter_obj = obj_val
            self._current_iter_flags = p.get("flags", 0)
            # Push a marker that we're in an iterator context
            self._push(tp="iter", value=obj_val)
        elif nm == "moreiter":
            # Skip moreiters that are part of iterator loop control flow
            if o in self._iter_moreiters:
                v = self._pop()
                self._push(tp="void", value=None)
                self._push(tp="script", script=v.get_value() if v else "")
            else:
                v = self._pop()
                self._push(tp="void", value=None)
                self._push(tp="script", script=v.get_value())
        elif nm == "iternext":
            # Check if the next opcode is setlocal/setaliasedvar/setname/setarg
            # — that's our loop variable.
            # Also detect dup+getelem+setlocal destructuring pattern where
            # the iterator yields [key, value] pairs.
            loop_var = "_it"
            ops = self.d.ops
            for si in range(len(ops)):
                if ops[si]["off"] == o:
                    if si + 1 < len(ops):
                        next_op = ops[si + 1]
                        if next_op["nm"] == "setlocal":
                            ln = next_op["params"].get("localno", 0)
                            lv = self._local_vars.get(ln)
                            loop_var = lv.name if lv else "l%d" % ln
                            # Suppress the redundant setlocal after iternext
                            self._iter_suppress_setlocal = ln
                        elif next_op["nm"] == "setaliasedvar":
                            loop_var = self._resolve_aliased_var(
                                next_op["params"].get("hops", 0),
                                next_op["params"].get("slot", 0),
                            )
                        elif next_op["nm"] in ("bindname", "setname", "setgname"):
                            # iternext + setname: loop var is the atom name
                            idx = next_op["params"].get("idx", 0)
                            loop_var = self._atom(idx)
                        elif next_op["nm"] == "setarg":
                            # iternext + setarg: loop var is the argument name
                            an = next_op["params"].get("argno", 0)
                            loop_var = (
                                self.d.argvs[an]
                                if an < len(self.d.argvs)
                                else "a%d" % an
                            )
                            # Suppress the redundant setarg after iternext
                            self._iter_suppress_setarg = an
                        elif next_op["nm"] == "dup":
                            # iternext + dup + getelem[N] + setlocal:
                            # Destructuring for-in where iterator yields [key, value].
                            # The loop variable is the first getelem target.
                            if si + 4 < len(ops):
                                op2 = ops[si + 2]  # zero or one
                                op3 = ops[si + 3]  # getelem
                                op4 = ops[si + 4]  # setlocal
                                if op3["nm"] == "getelem" and op4["nm"] == "setlocal":
                                    ln = op4["params"].get("localno", 0)
                                    lv = self._local_vars.get(ln)
                                    loop_var = lv.name if lv else "l%d" % ln
                                    # Suppress the setlocal for key extraction
                                    self._iter_suppress_setlocal = ln
                                    # Also mark the subsequent dup+getelem+setlocal
                                    # for value extraction as iter-related so they
                                    # produce clean output
                                    self._iter_destruct = True
                    break
            # Store loop_var in iter_loops map
            if o in self._iter_loops:
                self._iter_loops[o]["loop_var"] = loop_var
                self._iter_loops[o]["obj_value"] = getattr(
                    self, "_current_iter_obj", ""
                )
                self._iter_loops[o]["flags"] = getattr(self, "_current_iter_flags", 0)
            self._push(name=loop_var)
        elif nm == "enditer":
            v = self._pop()
            # Find and close the iterator loop
            for iternext_off, info in self._iter_loops.items():
                if info.get("loop_end_off") == o:
                    iter_off = info["iter_off"]
                    obj_val = info.get("obj_value", "")
                    loop_var = info.get("loop_var", "_it")
                    flags = info.get("flags", 0)
                    keyword = "of" if flags == 2 else "in"
                    header = "for (%s %s %s) {" % (loop_var, keyword, obj_val)
                    self._w(iter_off, header)
                    self._w(o, "}")
                    break
        elif nm == "yield":
            self._push(tp="script", script="yield " + self._pop().get_value())

    # ────────────────────────────────────────────────────
    def emit(self):
        lines = []
        if self.d.source_path:
            lines.append("// source: " + self.d.source_path)
        for k, v in sorted(self.script.items()):
            if v:
                lines.append(v)
        if self._dump_bytecode:
            lines.append("")
            lines.append("/* bytecode disassembly")
            for op in self.d.ops[:500]:
                nm = op["nm"]
                p = op["params"]
                detail = ""
                if "idx" in p:
                    detail = f" idx={p['idx']} '{self._atom(p['idx'])}'"
                elif "atomIndex" in p:
                    detail = f" atom[{p['atomIndex']}]='{self._atom(p['atomIndex'])}'"
                elif p:
                    detail = " " + " ".join(f"{k}={v}" for k, v in p.items())
                lines.append(f"  {op['off']:06x}: {nm}{detail}")
            if len(self.d.ops) > 500:
                lines.append(f"  ... {len(self.d.ops) - 500} more ops")
            lines.append("*/")

        result = "\n".join(lines)

        # Post-pass: resolve remaining _av{slot} placeholders using local_vars
        # which may have been populated after the aliasedvar opcode was dispatched
        import re as _re

        def _av_replace(m):
            slot = int(m.group(1))
            lv = self._local_vars.get(slot)
            if lv:
                return lv.name
            if slot < len(self.d.var_slot_names):
                return self.d.var_slot_names[slot]
            return m.group(0)  # keep original if can't resolve

        result = _re.sub(r"\b_av(\d+)\b", _av_replace, result)

        return result
