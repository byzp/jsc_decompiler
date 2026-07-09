"""Top-level decompiler: header → code → atoms → decompile."""
import struct
from .header import parse_header
from .codegen import parse_code
from .atoms import parse_atoms_consts, _scan_cocos_atoms
from .decompile import DecompileEngine
from .utils import u32le


class JSCDecompiler:
    def __init__(self, data, dump_bytecode=False, parent=None, source_path=None):
        self.data = data
        self.dump_bytecode = dump_bytecode
        self.parent = parent
        self._source_path = source_path
        self.hdr = {}
        self.code_start = 0; self.code_end = 0; self.off = 0
        self.ops = []; self.atoms = []; self.consts = []
        self.objects = []; self.regexps = []; self.argvs = []
        self.stack = []; self.local_vars = {}
        self.source_path = None
        self._is_cocos = False; self._is_nested = False
        self._func_name = ''; self._func_body = ''
        self.nested_funcs = []

    def run(self):
        parse_header(self)
        if self.hdr.get('codelen', 0) > 0:
            parse_code(self)
        parse_atoms_consts(self)

        if self._is_cocos and self.hdr.get('nobj', 0) > 0:
            try:
                self._cocos51_parse_objects()
            except Exception:
                pass

        engine = DecompileEngine(self)
        engine.run()
        self._func_body = engine.emit()
        return self._assemble_output()

    def _cocos51_parse_objects(self):
        d = self.data
        nobj = self.hdr.get('nobj', 0)
        if nobj <= 0 or nobj > 500:
            return

        # Object entries: tag(4) + sentinel(4) = 8 bytes each, then function data.
        # Search for tag=0 sentinel=0xFFFFFFFF from code_end+offset.
        # Then verify by reading the firstWord+codelen from the header.
        code_end = self.code_end
        objects = []
        o = code_end

        for obj_idx in range(nobj):
            # Find next tag=0 sentinel=0xFFFFFFFF
            found = False
            for search in range(o, min(o + (len(d) - o), len(d) - 12)):
                if u32le(d, search) == 0 and u32le(d, search + 4) == 0xFFFFFFFF:
                    o = search + 8
                    found = True
                    break
            if not found:
                break

            # Verify and parse function
            if o + 8 > len(d):
                break
            firstWord = u32le(d, o)
            has_atom = firstWord & 1
            o2 = o + 4  # after firstWord

            if has_atom:
                if o2 + 4 > len(d): break
                alen = u32le(d, o2); o2 += 4
                if alen == 0 or alen > 200: break
                o2 += alen * 2

            if o2 + 4 > len(d): break
            _flagsWord = u32le(d, o2); o2 += 4

            # sub_58AF5C header at o2: 13 words
            if o2 + 56 > len(d): break
            fields = [u32le(d, o2 + i*4) for i in range(13)]
            codelen = fields[1]
            natoms_f = fields[4]
            nobjects_f = fields[7]

            if not (1 <= codelen <= 50000) or natoms_f > 500 or nobjects_f > 500:
                # Skip this object but advance o to avoid desync
                # Try to advance past the header + variable slots + code
                skip_end = o2 + 52
                # Skip variable slots
                while skip_end + 4 <= len(d):
                    al = struct.unpack_from('<I', d, skip_end)[0]
                    if al <= 0 or al > 500: break
                    sz = al * 2
                    if skip_end + 4 + sz > len(d): break
                    try:
                        s = d[skip_end+4:skip_end+4+sz].decode('utf-16le')
                        if any(ord(c) > 0x7f for c in s): break
                    except: break
                    skip_end += 4 + sz
                # Skip 1 byte per slot + 16 bytes + code
                slot_cnt = (skip_end - (o2 + 52)) // 6  # rough estimate
                skip_end += slot_cnt + 16 + codelen
                if skip_end > o:
                    o = skip_end
                continue

            # Valid object found: create nested decompiler
            hdr_end = o2 + 52

            # After 13-word header: variable slot atoms + 1 byte each + 4 extra DWORDs
            # Read atoms sequentially from hdr_end until non-atom data
            var_slots_end = hdr_end
            slot_count = 0
            var_slot_names = []
            while var_slots_end + 4 <= len(d):
                al = struct.unpack_from('<I', d, var_slots_end)[0]
                if al <= 0 or al > 500: break
                sz = al * 2
                if var_slots_end + 4 + sz > len(d): break
                try:
                    s = d[var_slots_end+4:var_slots_end+4+sz].decode('utf-16le')
                    if any(ord(c) > 0x7f for c in s): break
                except: break
                var_slot_names.append(s)
                var_slots_end += 4 + sz
                slot_count += 1
                if slot_count > 100: break  # safety
            var_slots_end += slot_count  # skip 1 byte per slot
            code_start = var_slots_end + 16  # +4 extra DWORDs
            if code_start + codelen > len(d): break

            nargs = (fields[0] >> 16) & 0xFFFF
            argvs = var_slot_names[:nargs] if nargs > 0 and var_slot_names else []

            sub = JSCDecompiler(d, dump_bytecode=self.dump_bytecode, parent=self)
            sub.code_start = code_start
            sub.code_end = min(code_start + codelen, len(d))
            sub.hdr = {'nargs': 0, 'nbl': 0, 'nvars': 0, 'codelen': codelen,
                       'natoms': natoms_f, 'nsrc': fields[5], 'nconst': 0,
                       'nobj': nobjects_f, 'nreg': 0, 'ntry': 0, 'nblk': 0,
                       'sbits': fields[12]}
            sub._is_cocos = True
            sub.argvs = argvs
            sub.hdr['nargs'] = nargs
            sub.off = code_start
            parse_code(sub)
            # Atom table: nsrcnotes bytes after code, then atoms.
            # fields[5] may be slightly off; scan near the expected position.
            nsrc = sub.hdr.get('nsrc', 0)
            search_start = max(sub.code_end, sub.code_end + nsrc - 30)
            search_end = min(len(d) - 20, sub.code_end + nsrc + 50)
            atom_start = search_start
            best_start = atom_start; best_count = 0
            while atom_start < search_end:
                temp = atom_start; count = 0
                for _ in range(natoms_f + 2):  # allow extra iterations for zero-padding
                    # Skip zero-padding
                    while temp + 4 <= len(d) and struct.unpack_from('<I', d, temp)[0] == 0:
                        temp += 4
                    if temp + 4 > len(d): break
                    al = struct.unpack_from('<I', d, temp)[0]
                    if not (1 <= al <= 200): break
                    sz = al * 2
                    if temp + 4 + sz > len(d): break
                    try:
                        s = d[temp+4:temp+4+sz].decode('utf-16le')
                        if not all(ord(c) < 0x80 for c in s): break
                    except: break
                    count += 1; temp = temp + 4 + sz
                if count > best_count: best_count = count; best_start = atom_start
                if count >= 3: break
                atom_start += 1
            sub_atoms = []
            sub_off = best_start
            for _ in range(natoms_f):
                # Skip zero-padding words between atoms
                while sub_off + 4 <= len(d) and struct.unpack_from('<I', d, sub_off)[0] == 0:
                    sub_off += 4
                if sub_off + 4 > len(d): break
                al = struct.unpack_from('<I', d, sub_off)[0]; sub_off += 4
                if al <= 0 or al > 500: break
                # Stop if we hit a tag sentinel (0xFFFFFFFF after a zero)
                sz = al * 2
                if sub_off + sz > len(d): break
                try:
                    s = d[sub_off:sub_off + sz].decode('utf-16le')
                except:
                    s = ''
                sub_atoms.append(s)
                sub_off += sz
            sub.atoms = sub_atoms
            sub.consts = []

            if nobjects_f > 0:
                sub._cocos51_parse_objects()

            engine = DecompileEngine(sub)
            engine.run()
            sub._func_body = engine.emit()
            if sub.nested_funcs:
                sub._func_body = sub._assemble_output()
            sub._is_nested = True

            objects.append({'name': '', 'sub': sub, 'idx': obj_idx})

            # Advance past this object: move beyond code section
            # The tag search will skip over srcnotes/atoms/consts to find the next tag
            o = code_start + codelen

        if objects:
            self.objects = objects
            self.nested_funcs = [(i, obj) for i, obj in enumerate(objects) if obj.get('sub') and hasattr(obj['sub'], '_func_body')]

    def _assemble_output(self):
        result = self._func_body
        max_passes = 10
        for _ in range(max_passes):
            found = False
            for idx, entry in self.nested_funcs:
                sub = entry.get('sub') if isinstance(entry, dict) else entry
                if not sub or not hasattr(sub, '_func_body'):
                    continue
                body = sub._func_body.replace('\n// source:', '')
                body = body.strip()
                if body.endswith(';'):
                    body = body[:-1]
                args = ', '.join(sub.argvs) if hasattr(sub, 'argvs') and sub.argvs else ''

                # deffun: __F_N__ marker (body) and __A_N__ marker (args)
                marker_f = f'__F_{idx}__'
                if marker_f in result:
                    found = True
                    indent_body = '\n'.join('    ' + l for l in body.split('\n'))
                    result = result.replace(marker_f, indent_body)
                    result = result.replace(f'__A_{idx}__', args)

                # lambda: __L_N__ marker → wrap as function expression
                marker_l = f'__L_{idx}__'
                if marker_l in result:
                    found = True
                    wrapped = f'function({args}) {{\n{body}\n}}'
                    indent_fn = '\n'.join('    ' + l for l in wrapped.split('\n'))
                    result = result.replace(marker_l, indent_fn)

            if not found:
                break
        return result
