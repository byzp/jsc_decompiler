"""MozJS34 (0xB973C02C) parser.

Prolog layout after the 16 x u32LE header fields (64 bytes):
  flag=0x00: [0x00] [metadata] [null-terminated ASCII path] [24-byte sub-header] [bytecode]...
  flag=0x01: [0x01] [0x00 pad] [u32LE srcCharCount] [3x0x00 pad] [UTF-16LE source]
             [metadata] [null-terminated ASCII path] [24-byte sub-header] [bytecode]...
"""

import struct
from ..utils import u32le
from ..codegen import parse_code
from disasm import DisasmFunc
from .atoms import parse_atom, parse_atoms_seq


def parse(data):
    func, code_start, code_end, atoms_end = _parse_header_and_atoms(data)
    if func.codelen > 0:
        func.ops = parse_code(data, code_start, code_end, is_cocos=False)
    _parse_consts(data, func, atoms_end)
    if func.nobj > 0:
        try:
            from .objects import parse_objects

            const_end = _find_const_end(data, func, atoms_end)
            func.children = parse_objects(data, const_end, func.nobj)
        except Exception:
            pass
    return func


def _parse_header_and_atoms(data):
    func = DisasmFunc()
    func.is_cocos = False

    o = 4
    nargs = struct.unpack_from("<H", data, o)[0]
    o += 2
    nbl = struct.unpack_from("<H", data, o)[0]
    o += 2
    nvars = u32le(data, o)
    o += 4
    clen = u32le(data, o)
    o += 4
    prolog = u32le(data, o)
    o += 4
    jsver = u32le(data, o)
    o += 4
    natoms = u32le(data, o)
    o += 4
    nsrc = u32le(data, o)
    o += 4
    nconst = u32le(data, o)
    o += 4
    nobj = u32le(data, o)
    o += 4
    nreg = u32le(data, o)
    o += 4
    ntry = u32le(data, o)
    o += 4
    nblk = u32le(data, o)
    o += 4
    nts = u32le(data, o)
    o += 4
    flen = u32le(data, o)
    o += 4
    sbits = u32le(data, o)
    o += 4

    func.nargs = nargs
    func.nvars = nvars
    func.codelen = clen
    func.natoms = natoms
    func.nsrc = nsrc
    func.nconst = nconst
    func.nobj = nobj
    func.nreg = nreg
    func.ntry = ntry
    func.nblk = nblk
    func.sbits = sbits

    o = 64
    flag = data[o] if o < len(data) else 0
    o += 1

    if flag == 0x01:
        o += 1
        src_chars = struct.unpack_from("<I", data, o)[0]
        o += 4 + 3
        src_start = o
        o += src_chars * 2
        func.source_text = data[src_start:o].decode("utf-16le", errors="replace")

    while o < len(data) and (data[o] < 0x20 or data[o] > 0x7E):
        o += 1

    nul = data.find(b"\x00", o)
    if nul < 0 or nul - o > 512:
        nul = o
    func.source_path = (
        data[o:nul].decode("latin-1", errors="replace") if nul > o else ""
    )
    sub_start = nul + 1
    code_start = sub_start + 24
    code_end = code_start + clen if clen > 0 else code_start

    atoms_start = code_end + nsrc
    atoms, atoms_end = parse_atoms_seq(data, atoms_start, natoms)
    func.atoms = atoms

    return func, code_start, code_end, atoms_end


def _parse_consts(data, func, start_off):
    o = start_off
    for _ in range(func.nconst):
        if o + 4 > len(data):
            break
        type_tag = struct.unpack_from("<I", data, o)[0]
        o += 4
        if type_tag == 0:
            v = struct.unpack_from("<I", data, o)[0] if o + 4 <= len(data) else 0
            o += 4
            func.consts.append(("int", v))
        elif type_tag == 1:
            v = struct.unpack("<d", data[o : o + 8])[0] if o + 8 <= len(data) else 0.0
            o += 8
            func.consts.append(("double", v))
        elif type_tag == 2:
            s, o = parse_atom(data, o)
            func.consts.append(("atom", s))
        elif type_tag == 3:
            func.consts.append(("bool", True))
        elif type_tag == 4:
            func.consts.append(("bool", False))
        elif type_tag == 5:
            func.consts.append(("null", None))
        elif type_tag == 7:
            func.consts.append(("void", None))
        else:
            func.consts.append(("unknown", type_tag))


def _find_const_end(data, func, atoms_end):
    o = atoms_end
    for _ in range(func.nconst):
        if o + 4 > len(data):
            break
        type_tag = struct.unpack_from("<I", data, o)[0]
        o += 4
        if type_tag == 0:
            o += 4
        elif type_tag == 1:
            o += 8
        elif type_tag == 2:
            _, o = parse_atom(data, o)
        elif type_tag in (3, 4, 5, 7):
            pass
        else:
            break
    return o
