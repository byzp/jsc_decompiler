"""Decompilation engine – walks ops and produces JavaScript text."""
from .opcodes import IMAGE_OPS, NOOP_NAMES
from .stack import StackItem

_OBJECT_LITERAL_SKIP = object()


class DecompileEngine:
    def __init__(self, decompiler):
        self.d = decompiler
        self.atoms = decompiler.atoms
        self.consts = decompiler.consts
        self.script = {}
        self.logic_stacks = {}
        self.branch_map = {}
        self.loop_entries = set()
        self._sub_level = 0
        self._open_ifs = []  # stack of (ifeq_offset, target_offset)
        self._block_depth = 0  # track switch/try/block opens that need }
        self._switch_labels = {}  # target_offset → 'case val:' / 'default:'
        self._in_switch = False
        self._switch_default_target = 0
        self._switch_ifs_start = 0

    def run(self):
        for op in self.d.ops:
            try:
                self._dispatch(op)
            except Exception:
                pass
        # Close any remaining open blocks at function end
        close_count = len(self._open_ifs) + self._block_depth
        if close_count > 0:
            last_off = self.d.ops[-1]['off'] if self.d.ops else 0
            self._open_ifs.clear()
            self._block_depth = 0
            self._w(last_off, '}' * close_count)

    def _push(self, **kw):
        self.d.stack.append(StackItem(**kw))

    def _pop(self):
        return self.d.stack.pop() if self.d.stack else StackItem()

    def _atom(self, idx):
        if 0 <= idx < len(self.atoms):
            return self.atoms[idx]
        return f'#a{idx}'

    def _w(self, idx, text):
        if idx in self.script:
            self.script[idx] += text
        else:
            self.script[idx] = text

    # ────────────────────────────────────────────────────
    def _dispatch(self, op):
        nm = op['nm']; p = op['params']; o = op['off']

        # Check for pending switch case/default labels at this offset
        if o in self._switch_labels:
            labels = self._switch_labels[o]
            has_default = any(lb == 'default:' for lb in labels)
            if has_default:
                # Close switch; default is empty with shared code after
                self._w(o, 'default:\nbreak;\n}')
                if self._block_depth > 0:
                    self._block_depth -= 1
                self._in_switch = False
            else:
                # Close if-blocks from previous case before writing new case label
                new_ifs = len(self._open_ifs) - self._switch_ifs_start
                if new_ifs > 0:
                    prefix = '\n'.join('}' for _ in range(new_ifs)) + '\n'
                    self._open_ifs = self._open_ifs[:self._switch_ifs_start]
                else:
                    prefix = ''
                self._w(o, prefix + '\n'.join(labels))
            del self._switch_labels[o]

        if nm == 'implicitthis' and self.d._is_cocos:
            return
        if nm == 'swap' and self.d._is_cocos:
            return  # swap before call is for thisArg; we handle it in CALL
        if nm in NOOP_NAMES:
            return

        # return / value discard
        if nm == 'return':
            self._w(o, 'return ' + self._pop().get_value() + ';')
            # Close any open if-blocks at function exit
            if self._open_ifs:
                close_count = len(self._open_ifs)
                self._open_ifs.clear()
                self._w(o, '}' * close_count)
        elif nm in ('pop', 'popv', 'setrval'):
            rv = self._pop()
            s = rv.get_value()
            if s and s != 'undefined':
                self._w(o, s + ';')
        elif nm == 'popn':
            for _ in range(p.get('n', 0)):
                self._pop()

        # stack manipulation
        elif nm == 'dup':
            v = self._pop()
            self._push(**v.copy()); self._push(**v.copy())
        elif nm == 'dup2':
            v1 = self._pop(); v2 = self._pop()
            self._push(**v2.copy()); self._push(**v1.copy())
            self._push(**v2.copy()); self._push(**v1.copy())
        elif nm == 'swap':
            v1 = self._pop(); v2 = self._pop()
            self._push(**v1.copy()); self._push(**v2.copy())
        elif nm == 'pick':
            n = p.get('n', 0)
            temp = [self._pop() for _ in range(n)]
            nth = self._pop()
            for i in range(n - 1, -1, -1):
                self._push(**temp[i].copy())
            self._push(**nth.copy())

        # branching
        elif nm == 'ifeq':
            v = self._pop()
            tgt = o + p.get('offset', 0)
            cond = v.get_value()
            if p.get('offset', 0) > 0:
                self._w(o, f'if ({cond}) {{')
                self._open_ifs.append((o, tgt))
                self.branch_map[o] = {'goto': tgt, 'type': 'if'}
            else:
                self.loop_entries.add(tgt)
                self.branch_map[tgt] = {'goto': o, 'type': 'loop_head', 'cond': cond}

        elif nm == 'ifne':
            v = self._pop()
            tgt = o + p.get('offset', 0)
            if p.get('offset', 0) > 0:
                self._w(o, 'if (' + v.get_value() + ') {')
                self._open_ifs.append((o, tgt))
                self.branch_map[o] = {'goto': tgt, 'type': 'if'}
            else:
                self.loop_entries.add(tgt)
                self.branch_map[tgt] = {'goto': o, 'type': 'loop_head', 'cond': v.get_value()}

        elif nm == 'loophead':
            pass

        elif nm == 'goto':
            tgt = o + p.get('offset', 0)
            if p.get('offset', 0) < 0:
                self._w(o, 'continue;')
            elif p.get('offset', 0) > 0:
                if self._in_switch:
                    if tgt == self._switch_default_target:
                        self._w(o, 'break;')
                    elif any(t == tgt for _, t in self._open_ifs):
                        while self._open_ifs and self._open_ifs[-1][1] == tgt:
                            self._open_ifs.pop()
                        self._w(o, '')
                        self._w(tgt, '}')
                elif tgt >= self.d.code_end - 8:
                    close_count = len(self._open_ifs)
                    self._open_ifs.clear()
                    self._w(o, '')
                    self._w(tgt, '}' * close_count)
        elif nm == 'or':
            v = self._pop()
            self.logic_stacks[o] = {
                'type': 'or', 'goto': o + p.get('offset', 0),
                'value': v.get_value(),
            }
            self._push(tp='logic')
        elif nm == 'and':
            v = self._pop()
            self.logic_stacks[o] = {
                'type': 'and', 'goto': o + p.get('offset', 0),
                'value': v.get_value(),
            }
            self._push(tp='logic')

        # function calls
        elif nm in ('call', 'new', 'funcall', 'eval', 'funapply'):
            argc = p.get('argc', 0)
            argv = [self._pop() for _ in range(argc)]
            # After args, next is thisArg, then callee
            this_ = self._pop()
            callee = self._pop()
            fn = callee.name if callee.name is not None else callee.get_value()
            args = ','.join(a.get_value() for a in reversed(argv))
            pre = 'new ' if nm == 'new' else ''
            call_str = pre + fn + '(' + args + ')'
            self._push(tp='script', script=call_str)

        # property access
        elif nm in ('getprop', 'callprop'):
            obj = self._pop()
            self._push(name=obj.get_value() + '.' + self._atom(p.get('idx', 0)))
        elif nm == 'setprop':
            val = self._pop(); obj = self._pop()
            aname = self._atom(p.get('idx', 0))
            val_str = val.get_value()
            if val.type == 'function':
                fv = str(val.value) if val.value is not None else ''
                if not fv.startswith('__L_'):
                    val_str = 'function(){ ' + val_str + ' }'
            self._push(tp='script',
                       script=f'{obj.get_value()}.{aname}={val_str}')
        elif nm == 'delprop':
            obj = self._pop()
            self._push(tp='script',
                       script=f'delete {obj.get_value()}.{self._atom(p.get("idx",0))}')
        elif nm in ('getelem', 'callelem', 'enumelem'):
            idx = self._pop(); obj = self._pop()
            self._push(name=f'{obj.get_value()}[{idx.get_value()}]')
        elif nm == 'setelem':
            val = self._pop(); idx = self._pop(); obj = self._pop()
            self._push(tp='script',
                       script=f'{obj.get_value()}[{idx.get_value()}]={val.get_value()}')
        elif nm == 'delelem':
            idx = self._pop(); obj = self._pop()
            self._push(tp='script',
                       script=f'delete {obj.get_value()}[{idx.get_value()}]')
        elif nm == 'length':
            obj = self._pop()
            self._push(tp='script', script=obj.get_value() + '.length')

        # name resolution
        elif nm in ('callname', 'callgname'):
            idx = p.get('idx', 0)
            name_val = self._atom(idx)
            self._push(name=name_val)
            # callname doesn't push thisArg separately; add a dummy
            self._push(tp='void', name=None, value=None)

        elif nm in ('name', 'bindname', 'implicitthis',
                    'getgname', 'callintrinsic',
                    'incname', 'decname', 'nameinc', 'namedec',
                    'incgname', 'decgname', 'gnameinc', 'gnamedec'):
            self._push(name=self._atom(p.get('idx', 0)))

        elif nm in ('setname', 'setgname', 'setconst'):
            val = self._pop()
            s = self._pop()
            name = s.name if s.name else self._atom(p.get('idx', 0))
            fn_body = ''
            if val.type == 'function':
                fv = str(val.value) if val.value is not None else ''
                if fv.startswith('__L_'):
                    fn_body = fv
                else:
                    fn_body = f'function(){{ {fv} }}'
            else:
                fn_body = val.get_value()
            self._push(tp='script', name=name, script=f'{name}={fn_body}')

        elif nm == 'delname':
            self._push(tp='script', script=f'delete {self._atom(p.get("idx",0))}')

        # variable declarations
        elif nm == 'defvar':
            self._w(o, 'var ' + self._atom(p.get('idx', 0)) + ';')
        elif nm == 'defconst':
            self._w(o, 'const ' + self._atom(p.get('idx', 0)) + ';')
        elif nm == 'deffun':
            idx = p.get('idx', 0)
            fname = self._atom(idx) if idx < len(self.atoms) else f'f{idx}'
            # Clean up function names: strip 'require ' prefix, remove path separators
            if fname.startswith('require '):
                fname = fname[8:]
            fname = fname.replace('/', '_').replace('\\', '_').replace('.', '_')
            # If name starts with # (out-of-bounds atom), use generic name
            if fname.startswith('#'):
                fname = f'f{idx}'
            self._w(o, f'function {fname}(__A_{idx}__) {{ __F_{idx}__ }}')
        elif nm == 'lambda':
            idx = p.get('idx', 0)
            self._push(tp='function', value=f'__L_{idx}__')
        elif nm == 'getfunns':
            self._push(tp='function', value=p.get('idx', 0))

        # args / locals
        elif nm == 'getarg' or nm == 'callarg':
            an = p.get('argno', 0)
            name = self.d.argvs[an] if an < len(self.d.argvs) else f'a{an}'
            self._push(name=name)
        elif nm == 'setarg':
            val = self._pop(); an = p.get('argno', 0)
            name = self.d.argvs[an] if an < len(self.d.argvs) else f'a{an}'
            self._push(tp='script', name=name, script=f'{name}={val.get_value()}')
        elif nm == 'getlocal' or nm == 'calllocal':
            ln = p.get('localno', 0)
            lv = self.d.local_vars.get(ln)
            if lv:
                self._push(name=lv.name)
            else:
                self._push(name=f'l{ln}')
        elif nm == 'setlocal':
            val = self._pop(); ln = p.get('localno', 0)
            name = f'l{ln}'
            item = StackItem(tp='script', name=name,
                             script=f'{name}={val.get_value()}')
            self.d.local_vars[ln] = item
            self._push(**item.copy())

        # inc/dec arg/local/prop/elem shortcuts
        # Prefix: incX, decX (e.g. incarg, declocal, incprop, incelem, incaliasedvar, decaiasedvar)
        # Postfix: Xinc, Xdec (e.g. arginc, localdec, propinc, eleminc, aliasedvarinc, aliasedvardec)
        elif nm in ('incarg', 'decarg', 'arginc', 'argdec',
                    'inclocal', 'declocal', 'localinc', 'localdec',
                    'incaliasedvar', 'decaiasedvar', 'aliasedvarinc', 'aliasedvardec',
                    'incprop', 'decprop', 'propinc', 'propdec',
                    'incelem', 'decelem', 'eleminc', 'elemdec'):
            is_prefix = nm.startswith('inc') or nm.startswith('dec')
            is_inc = 'inc' in nm and 'dec' not in nm
            op = '++' if is_inc else '--'

            if nm in ('incarg', 'decarg', 'arginc', 'argdec'):
                an = p.get('argno', 0)
                name = self.d.argvs[an] if an < len(self.d.argvs) else f'a{an}'
                if is_prefix:
                    self._push(tp='script', script=f'{op}{name}')
                else:
                    self._push(tp='script', script=f'{name}{op}')
            elif nm in ('inclocal', 'declocal', 'localinc', 'localdec'):
                ln = p.get('localno', 0)
                lv = self.d.local_vars.get(ln)
                name = lv.name if lv else f'l{ln}'
                if is_prefix:
                    self._push(tp='script', script=f'{op}{name}')
                else:
                    self._push(tp='script', script=f'{name}{op}')
            elif nm in ('incaliasedvar', 'decaiasedvar', 'aliasedvarinc', 'aliasedvardec'):
                if is_prefix:
                    self._push(tp='script', script=f'{op}_av')
                else:
                    self._push(tp='script', script=f'_av{op}')
            elif nm in ('incprop', 'decprop', 'propinc', 'propdec'):
                obj = self._pop()
                aname = self._atom(p.get('idx', 0))
                if is_prefix:
                    self._push(tp='script', script=f'{op}{obj.get_value()}.{aname}')
                else:
                    self._push(tp='script', script=f'{obj.get_value()}.{aname}{op}')
            elif nm in ('incelem', 'decelem', 'eleminc', 'elemdec'):
                idx = self._pop(); obj = self._pop()
                if is_prefix:
                    self._push(tp='script', script=f'{op}{obj.get_value()}[{idx.get_value()}]')
                else:
                    self._push(tp='script', script=f'{obj.get_value()}[{idx.get_value()}]{op}')

        elif nm == 'arguments':
            self._push(name='arguments')
        elif nm == 'rest':
            self._push(name='...rest')

        # aliased vars
        elif nm in ('getaliasedvar', 'callaliasedvar'):
            self._push(name='_av')
        elif nm == 'setaliasedvar':
            val = self._pop()
            self._push(tp='script', name='_av', script=f'_av={val.get_value()}')

        # literals
        elif nm == 'string':
            idx = p.get('atomIndex', p.get('idx', 0))
            self._push(tp='string', value=self._atom(idx))
        elif nm == 'double':
            idx = p.get('constIndex', p.get('idx', 0))
            if 0 <= idx < len(self.consts):
                self._push(tp='number', value=self.consts[idx][1])
            else:
                self._push(tp='number', value=0)
        elif nm == 'int8':
            self._push(tp='number', value=p.get('val', 0))
        elif nm in ('uint16', 'uint24'):
            self._push(tp='number', value=p.get('val', 0))
        elif nm == 'int32':
            self._push(tp='number', value=p.get('val', 0))
        elif nm == 'zero':
            self._push(tp='number', value=0)
        elif nm == 'one':
            self._push(tp='number', value=1)
        elif nm == 'null':
            self._push(tp='null', value='null')
        elif nm == 'true':
            self._push(tp='boolean', value=True)
        elif nm == 'false':
            self._push(tp='boolean', value=False)
        elif nm == 'undefined':
            self._push(tp='undefined', value='undefined')
        elif nm == 'void':
            self._pop()
            self._push(tp='undefined', value='undefined')
        elif nm == 'this':
            self._push(name='this')
        elif nm == 'hole':
            self._push(tp='void', value=None)
        elif nm == 'regexp':
            self._push(tp='regexp', value='/re/')

        # arithmetic / comparisons
        elif nm in IMAGE_OPS:
            r = self._pop(); l = self._pop()
            sym = IMAGE_OPS.get(nm, '?')
            self._push(tp='script', script=f'({l.get_value()} {sym} {r.get_value()})')
        elif nm in ('eq', 'ne', 'lt', 'le', 'gt', 'ge',
                    'stricteq', 'strictne', 'in', 'instanceof'):
            r = self._pop(); l = self._pop()
            sym_map = {
                'eq': '==', 'ne': '!=', 'lt': '<', 'le': '<=',
                'gt': '>', 'ge': '>=', 'stricteq': '===', 'strictne': '!==',
                'in': 'in', 'instanceof': 'instanceof',
            }
            self._push(tp='script',
                       script=f'({l.get_value()} {sym_map[nm]} {r.get_value()})')
        elif nm == 'not':
            v = self._pop()
            self._push(tp='script', script=f'(!{v.get_value()})')
        elif nm == 'bitnot':
            v = self._pop()
            self._push(tp='script', script=f'(~{v.get_value()})')
        elif nm == 'neg':
            v = self._pop()
            self._push(tp='script', script=f'(-{v.get_value()})')
        elif nm in ('typeof', 'typeofexpr'):
            self._push(tp='script', script='typeof ' + self._pop().get_value())

        # objects / arrays
        elif nm == 'newinit':
            kind = p.get('kind', 0)
            self._push(tp='object',
                       value={} if kind == 0 else {})
        elif nm == 'newarray':
            self._push(tp='array', value=[])
        elif nm in ('newobject', 'object'):
            self._push(tp='object', value={})
        elif nm == 'initprop':
            val = self._pop(); obj = self._pop()
            aname = self._atom(p.get('idx', 0))
            if isinstance(obj.value, dict):
                obj.value[aname] = val
            self._push(tp='object',
                       value=obj.value if isinstance(obj.value, dict) else {})
        elif nm in ('initelem', 'initelem_inc'):
            val = self._pop(); name = self._pop(); obj = self._pop()
            if isinstance(obj.value, dict):
                obj.value[name.get_value()] = val
            self._push(tp='object',
                       value=obj.value if isinstance(obj.value, dict) else {})
        elif nm == 'initelem_array':
            val = self._pop(); arr = self._pop()
            if isinstance(arr.value, list):
                arr.value.append(val)
            self._push(tp='array',
                       value=arr.value if isinstance(arr.value, list) else [])
        elif nm == 'arraypush':
            val = self._pop(); arr = self._pop()
            self._push(tp='array',
                       value=arr.value if isinstance(arr.value, list) else [])

        # try / catch
        elif nm == 'try':
            self._w(o, 'try {')
            self._block_depth += 1
        elif nm == 'throw':
            self._w(o, 'throw ' + self._pop().get_value() + ';')
        elif nm == 'throwing':
            self._pop()
        elif nm == 'exception':
            self._w(o, '} catch(e) {')
            self._push(name='e')
        elif nm == 'finally':
            self._w(o, '} finally {')
            self._push(tp='void', value=None)
            self._push(tp='void', value=None)
        elif nm == 'retsub':
            self._w(o, '}')
            if self._block_depth > 0:
                self._block_depth -= 1
            self._pop(); self._pop()
        elif nm in ('leaveblock', 'leaveblockexpr'):
            self._w(o, '}')
            if self._block_depth > 0:
                self._block_depth -= 1
            self._in_switch = False
            self._switch_labels = {}

        # switch
        elif nm == 'condswitch':
            v = self.d.stack[-1] if self.d.stack else StackItem()
            self._w(o, 'switch(' + v.get_value() + '){')
            self._block_depth += 1
            self._in_switch = True
            self._switch_labels = {}
            self._switch_ifs_start = len(self._open_ifs)
        elif nm == 'case':
            val = self._pop()  # pop case value; switch value stays on stack
            tgt = o + p.get('offset', 0)
            label_text = 'case ' + val.get_value() + ':'
            if tgt not in self._switch_labels:
                self._switch_labels[tgt] = []
            self._switch_labels[tgt].append(label_text)
        elif nm == 'default':
            if self.d.stack:
                self._pop()  # pop the switch value
            tgt = o + p.get('offset', 0)
            self._switch_default_target = tgt
            if tgt not in self._switch_labels:
                self._switch_labels[tgt] = []
            self._switch_labels[tgt].append('default:')

        # misc
        elif nm in ('spread', 'getxprop', 'getter', 'setter',
                    'enumconstelem', 'setintrinsic', 'bindgname',
                    'setcall', 'proxy', 'tableswitch',
                    'getintrinsic', 'bindintrinsic'):
            pass
        elif nm == 'iter':
            v = self._pop()
            self._push(**v.copy())
        elif nm == 'moreiter':
            v = self._pop()
            self._push(tp='void', value=None)
            self._push(tp='script', script=v.get_value())
        elif nm == 'iternext':
            self._push(name='_it')
        elif nm == 'enditer':
            self._pop()
        elif nm == 'yield':
            self._push(tp='script', script='yield ' + self._pop().get_value())

    # ────────────────────────────────────────────────────
    def emit(self):
        lines = []
        if self.d.source_path:
            lines.append('// source: ' + self.d.source_path)
        for k, v in sorted(self.script.items()):
            if v:
                lines.append(v)
        if self.d.dump_bytecode:
            lines.append('')
            lines.append('/* bytecode disassembly')
            for op in self.d.ops[:500]:
                nm = op['nm']; p = op['params']
                detail = ''
                if 'idx' in p:
                    detail = f" idx={p['idx']} '{self._atom(p['idx'])}'"
                elif 'atomIndex' in p:
                    detail = f" atom[{p['atomIndex']}]='{self._atom(p['atomIndex'])}'"
                elif p:
                    detail = ' ' + ' '.join(f'{k}={v}' for k, v in p.items())
                lines.append(f"  {op['off']:06x}: {nm}{detail}")
            if len(self.d.ops) > 500:
                lines.append(f"  ... {len(self.d.ops) - 500} more ops")
            lines.append('*/')
        return '\n'.join(lines)
