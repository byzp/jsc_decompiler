"""MozJS34 (0xB973C02C) nested object parser.

Objects are laid out flat in the file: parent, then its children, then next sibling.
Returns a list of DisasmFunc objects — no decompiler dependency.
"""
import struct
from ..utils import u32le
from ..codegen import parse_code
from .atoms import parse_atom
from disasm import DisasmFunc


def _find_code_start(d, fields_end, codelen, nsrc_f, natoms_f):
    search_start = fields_end + codelen + nsrc_f
    max_atom_bytes = natoms_f * 1004 + 200
    search_end = min(len(d) - 20, search_start + max_atom_bytes)
    atom_start = search_start
    best_start = atom_start
    best_count = 0
    while atom_start < search_end:
        temp = atom_start
        count = 0
        for _ in range(natoms_f + 4):
            if temp + 4 > len(d):
                break
            raw = struct.unpack_from('<I', d, temp)[0]
            if raw == 0:
                temp += 4
                continue
            is_lat = raw & 1
            length = raw >> 1
            if length == 0 or length > 200:
                break
            temp += 4
            if is_lat:
                if not all(32 <= b < 127 or b in (9, 10, 13) for b in d[temp:temp + length]):
                    break
                temp += length
            else:
                sz = length * 2
                try:
                    s = d[temp:temp + sz].decode('utf-16le')
                    if not s or not all(ch in '\t\r\n' or 32 <= ord(ch) <= 0x9fff for ch in s):
                        break
                except UnicodeDecodeError:
                    break
                temp += sz
            count += 1
        if count > best_count:
            best_count = count
            best_start = atom_start
        if count >= min(3, natoms_f):
            break
        atom_start += 1

    code_end = best_start - nsrc_f if best_count > 0 else fields_end + codelen
    code_start = code_end - codelen
    if code_start < fields_end or code_start < 0 or code_end > len(d):
        code_start = fields_end
        code_end = code_start + codelen
    return code_start, code_end, best_start, best_count


def _parse_var_slots(d, fields_end, code_start):
    var_slot_names = []
    vs_off = fields_end
    for _ in range(100):
        if vs_off >= code_start:
            break
        if vs_off + 4 > len(d):
            break
        raw = struct.unpack_from('<I', d, vs_off)[0]
        if raw == 0:
            var_slot_names.append('')
            vs_off += 4
            continue
        is_lat = raw & 1
        length = raw >> 1
        if is_lat and length == 0:
            var_slot_names.append('')
            vs_off += 4
            continue
        if not is_lat:
            var_slot_names.append('')
            vs_off += 4
            continue
        if length == 0 or length > 50:
            break
        s, new_off = parse_atom(d, vs_off)
        if not s or new_off > code_start:
            break
        var_slot_names.append(s)
        vs_off = new_off
    return var_slot_names


def _parse_consts_at(d, o, nconst_f):
    consts = []
    for _ in range(nconst_f):
        if o + 4 > len(d):
            break
        type_tag = struct.unpack_from('<I', d, o)[0]
        o += 4
        if type_tag == 0 and o + 4 <= len(d):
            consts.append(('int', struct.unpack_from('<I', d, o)[0]))
            o += 4
        elif type_tag == 1 and o + 8 <= len(d):
            consts.append(('double', struct.unpack('<d', d[o:o + 8])[0]))
            o += 8
        elif type_tag == 2:
            s, o = parse_atom(d, o)
            consts.append(('atom', s))
        elif type_tag == 3:
            consts.append(('bool', True))
        elif type_tag == 4:
            consts.append(('bool', False))
        elif type_tag == 5:
            consts.append(('null', None))
        elif type_tag == 7:
            consts.append(('void', None))
        else:
            consts.append(('unknown', type_tag))
    return consts, o


def parse_objects(data, start_off, nobj):
    d = data
    if nobj <= 0 or nobj > 2000:
        return []
    o = start_off
    if o <= 0 or o >= len(d):
        return []

    objects = []
    obj_idx = 0
    while obj_idx < nobj:
        sentinel_pos = None
        for s in range(o, min(o + 64, len(d) - 4)):
            if struct.unpack_from('<I', d, s)[0] == 0xFFFFFFFF:
                sentinel_pos = s
                break
        if sentinel_pos is None:
            break

        o = sentinel_pos + 4
        if o + 4 > len(d):
            break
        firstWord = u32le(d, o)
        has_atom = firstWord & 1
        o += 4

        atom_name = ''
        if has_atom:
            atom_name, o = parse_atom(d, o)

        if o + 4 > len(d):
            break
        o += 4  # flagsWord

        if o + 52 > len(d):
            break
        fields = [u32le(d, o + i * 4) for i in range(13)]
        o += 52

        codelen = fields[2]
        natoms_f = fields[5]
        nsrc_f = fields[6]
        nconst_f = fields[7]
        nobjects_f = fields[8]

        if not (1 <= codelen <= 50000) or natoms_f > 500:
            obj_idx += 1
            continue

        code_start, code_end, atom_start, best_count = _find_code_start(d, o, codelen, nsrc_f, natoms_f)
        var_slot_names = _parse_var_slots(d, o, code_start)

        nargs = (fields[0] >> 16) & 0xFFFF
        argvs = var_slot_names[:nargs] if nargs > 0 and var_slot_names else []

        func = DisasmFunc()
        func.name = atom_name
        func.nargs = nargs
        func.nvars = fields[1]
        func.codelen = codelen
        func.natoms = natoms_f
        func.nsrc = nsrc_f
        func.nconst = nconst_f
        func.nobj = nobjects_f
        func.nreg = fields[9]
        func.ntry = fields[10]
        func.nblk = fields[11]
        func.sbits = fields[12]
        func.argvs = argvs
        func.var_slot_names = var_slot_names
        func.is_cocos = False

        if codelen > 0:
            func.ops = parse_code(d, code_start, code_end, is_cocos=False)

        sub_atoms = []
        sub_off = atom_start if best_count > 0 else code_end + nsrc_f
        for _ in range(natoms_f):
            s, sub_off = parse_atom(d, sub_off)
            sub_atoms.append(s)
        func.atoms = sub_atoms
        func.consts, sub_off = _parse_consts_at(d, sub_off, nconst_f)

        if nobjects_f > 0:
            func.children = parse_objects(d, sub_off, nobjects_f)

        objects.append(func)
        o = sub_off
        obj_idx += 1

    return objects
