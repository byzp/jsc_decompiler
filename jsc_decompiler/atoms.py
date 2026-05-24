"""Atom and constant extraction from JSC buffers."""
import struct
from .utils import r_le


def parse_atoms_consts(decompiler):
    """Extract atoms / constants into self.atoms / self.consts."""
    if decompiler._is_cocos:
        _parse_cocos51_sequential(decompiler)
    else:
        _parse_standard_atoms(decompiler)
        _parse_standard_consts(decompiler)


def _parse_cocos51_sequential(decompiler):
    """Sequential atom/const parsing for Cocos51 [u32 len][UTF-16LE].
    Advances decompiler.off to point after all atoms + consts, ready for objects."""
    d = decompiler.data
    o = decompiler.code_end

    # Skip source notes
    nsrc = decompiler.hdr.get('nsrc', 0)
    o += nsrc

    # Parse atoms
    natoms = decompiler.hdr.get('natoms', 0)
    atoms = []
    for _ in range(natoms):
        if o + 4 > len(d):
            break
        raw_len = struct.unpack_from('<I', d, o)[0]
        o += 4
        if raw_len <= 0 or raw_len > 500:
            o -= 4; break
        sz = raw_len * 2
        if o + sz > len(d):
            break
        try:
            s = d[o:o + sz].decode('utf-16le')
            atoms.append(s)
        except UnicodeDecodeError:
            atoms.append('')
        o += sz
    decompiler.atoms = atoms

    # Parse consts
    nconst = decompiler.hdr.get('nconst', 0)
    consts = []
    for _ in range(nconst):
        if o >= len(d):
            break
        ct = d[o]; o += 1
        if ct == 0 and o + 4 <= len(d):
            consts.append(('int', struct.unpack_from('<I', d, o)[0])); o += 4
        elif ct == 1 and o + 8 <= len(d):
            consts.append(('double', struct.unpack('<d', d[o:o+8])[0])); o += 8
        elif ct == 2 and o + 5 <= len(d):
            rl = struct.unpack_from('<I', d, o)[0]; o += 4
            sz = rl * 2
            if o + sz <= len(d):
                consts.append(('atom', d[o:o+sz].decode('utf-16le', errors='replace')))
                o += sz
        elif ct in (3, 4, 5, 7):
            consts.append(('val', ct))
        else:
            consts.append(('unknown', ct))
    decompiler.consts = consts
    decompiler.off = o


def _scan_cocos_atoms(d, code_end):
    """UTF-16LE atom scanner for Cocos2d-x .jscz files.

    Scans from code_end to end-of-buffer looking for
    length-prefixed UTF-16LE strings.
    """
    atoms = []
    seen = set()
    o = code_end
    end = max(0, len(d) - 8)
    while o < end:
        raw_len = struct.unpack_from('<I', d, o)[0]
        if raw_len <= 0 or raw_len > 500:
            o += 1
            continue
        start = o + 4
        size = raw_len * 2
        if start + size > len(d):
            o += 1
            continue
        raw = d[start:start + size]
        # Quick ASCII-ish check: high-bytes should be mostly zero
        if raw_len > 2 and raw[1::2].count(0) < max(1, raw_len // 4):
            o += 1
            continue
        try:
            s = raw.decode('utf-16le')
        except UnicodeDecodeError:
            o += 1
            continue
        if not s:
            o += 1
            continue
        # Validate: all chars printable or whitespace
        if not all(ch in '\t\r\n' or 32 <= ord(ch) <= 0x9fff for ch in s):
            o += 1
            continue
        if s in seen:
            o += 1
            continue
        # Single-char atoms must be valid identifiers
        if len(s) == 1 and not (s.isalpha() or s in '_$@'):
            o += 1
            continue
        seen.add(s)
        atoms.append(s)
        o = start + size
    return atoms


def _parse_standard_atoms(decompiler):
    d = decompiler.data
    o = decompiler.code_end + decompiler.hdr.get('nsrc', 0)
    for _ in range(decompiler.hdr.get('natoms', 0)):
        if o >= len(d):
            break
        enc, o = r_le(d, o, 1)
        hl = enc & 1
        al = enc >> 1
        if hl:
            s = d[o:o + al].decode('latin-1', errors='replace') if o + al <= len(d) else ''
            o += al
        else:
            s = ''
            for _ in range(al):
                if o + 1 < len(d):
                    s += chr(d[o] | (d[o + 1] << 8))
                    o += 2
        decompiler.atoms.append(s)


def _parse_standard_consts(decompiler):
    d = decompiler.data
    o = decompiler.off
    for _ in range(decompiler.hdr.get('nconst', 0)):
        if o >= len(d):
            break
        ct = d[o]; o += 1
        if ct == 0:
            v, o = r_le(d, o, 4)
            decompiler.consts.append(('int', v))
        elif ct == 1:
            if o + 8 <= len(d):
                v = struct.unpack('<d', d[o:o + 8])[0]
                o += 8
            else:
                v = 0.0
            decompiler.consts.append(('double', v))
        elif ct == 2:
            enc, o = r_le(d, o, 1)
            hl = enc & 1
            al = enc >> 1
            s = d[o:o + al].decode('latin-1', errors='replace') if o + al <= len(d) else ''
            o += al if hl else al * 2
            decompiler.consts.append(('atom', s))
        elif ct == 3:
            decompiler.consts.append(('bool', True))
        elif ct == 4:
            decompiler.consts.append(('bool', False))
        elif ct == 5:
            decompiler.consts.append(('null', None))
        elif ct == 7:
            decompiler.consts.append(('void', None))
        else:
            decompiler.consts.append(('unknown', ct))
    decompiler.off = o
