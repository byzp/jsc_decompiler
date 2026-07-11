"""Cocos51 (0xB973C051) parser — Cocos2d-x custom MozJS34 variant.

Handles: header parsing, code decoding, atom/const extraction,
nested object parsing. Returns DisasmFunc — no decompiler dependency.
"""

import struct
from ..utils import u32le
from .codegen import parse_code
from disasm import DisasmFunc


def parse(data):
    func, code_start, code_end = _parse_header(data)
    if func.codelen > 0:
        func.ops = parse_code(data, code_start, code_end)
    _parse_atoms(data, func, code_end)
    if func.nobj > 0:
        try:
            atoms_end = _find_atoms_end(data, func, code_end)
            consts_end = _find_consts_end(data, func, atoms_end)
            func.children = _parse_objects(data, consts_end, func.nobj)
            for _ch in func.children:
                if _ch is not None:
                    _ch.parent = func
        except Exception:
            pass
    return func


def _parse_header(data):
    func = DisasmFunc()
    func.is_cocos = True

    ver = u32le(data, 0)

    path_start = 60
    nul = data.find(b"\x00", path_start)
    if nul >= 0 and nul > path_start and (nul - path_start) < 512:
        func.source_path = data[path_start:nul].decode("utf-8", errors="replace")
    else:
        func.source_path = ""
        nul = path_start

    func.codelen = u32le(data, 8)
    func.nvars = u32le(data, 12)
    func.natoms = u32le(data, 20)
    func.nsrc = u32le(data, 24)
    func.nconst = u32le(data, 28)
    func.nobj = u32le(data, 32)
    func.nreg = u32le(data, 36)
    func.ntry = u32le(data, 40)
    func.nblk = u32le(data, 44)
    func.sbits = u32le(data, 56) if u32le(data, 56) < 0x10000 else 0

    meta_start = nul + 1
    while meta_start < len(data) and data[meta_start] == 0:
        meta_start += 1
    meta_start = min(meta_start, nul + 5)
    code_start = meta_start + 12
    code_end = min(code_start + func.codelen, len(data))

    return func, code_start, code_end


def _is_sentinel(d, o):
    """Check if offset o contains the object sentinel 0x00000000+0xFFFFFFFF."""
    return (
        o + 8 <= len(d)
        and struct.unpack_from("<I", d, o)[0] == 0
        and struct.unpack_from("<I", d, o + 4)[0] == 0xFFFFFFFF
    )


def _skip_zero_padding(d, o):
    """Skip 4-byte zero padding, but stop before a sentinel pattern."""
    while o + 8 <= len(d) and struct.unpack_from("<I", d, o)[0] == 0:
        if struct.unpack_from("<I", d, o + 4)[0] == 0xFFFFFFFF:
            break  # sentinel — don't consume
        o += 4
    return o


def _parse_atoms(data, func, code_end):
    d = data
    o = code_end

    nsrc = func.nsrc
    o += nsrc

    natoms = func.natoms
    atoms = []
    for _ in range(natoms):
        o = _skip_zero_padding(d, o)
        if o + 4 > len(d):
            break
        raw_len = struct.unpack_from("<I", d, o)[0]
        o += 4
        if raw_len <= 0 or raw_len > 500:
            atoms.append("")
            o -= 4
            continue
        sz = raw_len * 2
        if o + sz > len(d):
            break
        try:
            s = d[o : o + sz].decode("utf-16le")
            atoms.append(s)
        except UnicodeDecodeError:
            atoms.append("")
        o += sz
    func.atoms = atoms

    nconst = func.nconst
    consts = []
    for _ in range(nconst):
        if o >= len(d):
            break
        if _is_sentinel(d, o):
            break
        ct = d[o]
        o += 1
        if ct == 0 and o + 4 <= len(d):
            consts.append(("int", struct.unpack_from("<I", d, o)[0]))
            o += 4
        elif ct == 1 and o + 8 <= len(d):
            consts.append(("double", struct.unpack("<d", d[o : o + 8])[0]))
            o += 8
        elif ct == 2 and o + 5 <= len(d):
            rl = struct.unpack_from("<I", d, o)[0]
            o += 4
            sz = rl * 2
            if o + sz <= len(d):
                consts.append(
                    ("atom", d[o : o + sz].decode("utf-16le", errors="replace"))
                )
                o += sz
        elif ct in (3, 4, 5, 7):
            consts.append(("val", ct))
        else:
            consts.append(("unknown", ct))
    func.consts = consts


def _find_atoms_end(data, func, code_end):
    d = data
    o = code_end + func.nsrc
    for _ in range(func.natoms):
        o = _skip_zero_padding(d, o)
        if o + 4 > len(d):
            break
        raw_len = struct.unpack_from("<I", d, o)[0]
        o += 4
        if raw_len <= 0 or raw_len > 500:
            o -= 4
            continue
        o += raw_len * 2
    return o


def _find_consts_end(data, func, atoms_end):
    d = data
    o = atoms_end
    for _ in range(func.nconst):
        if o >= len(d):
            break
        # Stop if we've hit a sentinel (object separator)
        if _is_sentinel(d, o):
            break
        ct = d[o]
        o += 1
        if ct == 0:
            o += 4
        elif ct == 1:
            o += 8
        elif ct == 2:
            if o + 4 <= len(d):
                rl = struct.unpack_from("<I", d, o)[0]
                o += 4
                o += rl * 2
        elif ct in (3, 4, 5, 7):
            pass
        else:
            break
    return o


def _parse_objects(data, start_off, nobj):
    d = data
    if nobj <= 0 or nobj > 500:
        return []

    o = start_off
    objects = []

    for obj_idx in range(nobj):
        found = False
        for search in range(o, min(o + (len(d) - o), len(d) - 12)):
            if u32le(d, search) == 0 and u32le(d, search + 4) == 0xFFFFFFFF:
                o = search + 8
                found = True
                break
        if not found:
            break

        if o + 8 > len(d):
            break
        firstWord = u32le(d, o)
        has_atom = firstWord & 1
        o2 = o + 4

        atom_name = ""
        if has_atom:
            if o2 + 4 > len(d):
                break
            alen = u32le(d, o2)
            o2 += 4
            if alen == 0 or alen > 200:
                break
            if o2 + alen * 2 <= len(d):
                atom_name = d[o2 : o2 + alen * 2].decode("utf-16le", errors="replace")
            o2 += alen * 2

        if o2 + 4 > len(d):
            break
        o2 += 4  # flagsWord

        if o2 + 56 > len(d):
            break
        fields = [u32le(d, o2 + i * 4) for i in range(13)]
        codelen = fields[1]
        natoms_f = fields[4]
        nobjects_f = fields[7]

        if not (1 <= codelen <= 50000) or natoms_f > 500 or nobjects_f > 500:
            skip_end = o2 + 52
            while skip_end + 4 <= len(d):
                al = struct.unpack_from("<I", d, skip_end)[0]
                if al <= 0 or al > 500:
                    break
                sz = al * 2
                if skip_end + 4 + sz > len(d):
                    break
                try:
                    s = d[skip_end + 4 : skip_end + 4 + sz].decode("utf-16le")
                    if any(ord(c) > 0x7F for c in s):
                        break
                except:
                    break
                skip_end += 4 + sz
            slot_cnt = (skip_end - (o2 + 52)) // 6
            skip_end += slot_cnt + 16 + codelen
            if skip_end > o:
                o = skip_end
            continue

        hdr_end = o2 + 52
        var_slots_end = hdr_end
        slot_count = 0
        var_slot_names = []
        while var_slots_end + 4 <= len(d):
            al = struct.unpack_from("<I", d, var_slots_end)[0]
            if al <= 0 or al > 500:
                break
            sz = al * 2
            if var_slots_end + 4 + sz > len(d):
                break
            try:
                s = d[var_slots_end + 4 : var_slots_end + 4 + sz].decode("utf-16le")
                if any(ord(c) > 0x7F for c in s):
                    break
            except:
                break
            var_slot_names.append(s)
            var_slots_end += 4 + sz
            slot_count += 1
            if slot_count > 100:
                break
        var_slots_end += slot_count
        code_start = var_slots_end + 16
        if code_start + codelen > len(d):
            break

        nargs = (fields[0] >> 16) & 0xFFFF
        argvs = var_slot_names[:nargs] if nargs > 0 and var_slot_names else []

        func = DisasmFunc()
        func.name = atom_name
        func.nargs = nargs
        func.nvars = 0
        func.codelen = codelen
        func.natoms = natoms_f
        func.nsrc = fields[5]
        func.nconst = 0
        func.nobj = nobjects_f
        func.sbits = fields[12]
        func.argvs = argvs
        func.var_slot_names = var_slot_names
        func.is_cocos = True

        if codelen > 0:
            func.ops = parse_code(d, code_start, code_start + codelen)

        nsrc = func.nsrc
        search_start = max(code_start + codelen, code_start + codelen + nsrc - 30)
        max_atom_bytes = natoms_f * 1004 + 200
        search_end = min(
            len(d) - 20,
            max(
                code_start + codelen + nsrc + 50,
                code_start + codelen + nsrc + max_atom_bytes,
            ),
        )
        atom_start = search_start
        best_start = atom_start
        best_count = 0
        while atom_start < search_end:
            temp = atom_start
            count = 0
            for _ in range(natoms_f + 4):
                temp = _skip_zero_padding(d, temp)
                if temp + 4 > len(d):
                    break
                al = struct.unpack_from("<I", d, temp)[0]
                if not (1 <= al <= 200):
                    break
                sz = al * 2
                if temp + 4 + sz > len(d):
                    break
                try:
                    s = d[temp + 4 : temp + 4 + sz].decode("utf-16le")
                    if not s or len(s) != al:
                        break
                except:
                    break
                count += 1
                temp = temp + 4 + sz
            if count > best_count:
                best_count = count
                best_start = atom_start
            if count >= min(3, natoms_f):
                break
            atom_start += 1

        sub_atoms = []
        sub_off = best_start
        for _ in range(natoms_f):
            sub_off = _skip_zero_padding(d, sub_off)
            if sub_off + 4 > len(d):
                break
            al = struct.unpack_from("<I", d, sub_off)[0]
            sub_off += 4
            if al <= 0 or al > 500:
                sub_atoms.append("")
                sub_off -= 4
                continue
            sz = al * 2
            if sub_off + sz > len(d):
                break
            try:
                s = d[sub_off : sub_off + sz].decode("utf-16le")
            except:
                s = ""
            sub_atoms.append(s)
            sub_off += sz
        func.atoms = sub_atoms

        if nobjects_f > 0:
            func.children = _parse_objects(d, sub_off, nobjects_f)
            for _ch in func.children:
                if _ch is not None:
                    _ch.parent = func

        objects.append(func)
        o = code_start + codelen

    return objects
