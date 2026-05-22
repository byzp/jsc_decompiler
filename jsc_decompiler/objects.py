"""Object parser for both standard and Cocos51 JSC files."""
import struct
from .utils import r_le, u32le


def parse_objects(decompiler):
    """Standard MozJS object parser (for non-Cocos files)."""
    pass  # already handled


def parse_cocos51_objects(decompiler):
    """Scan for function objects after the atom region in Cocos51 files."""
    d = decompiler.data
    nobj = decompiler.hdr.get('nobj', 0)
    if nobj <= 0:
        return

    # Find objects after all atom data
    o = decompiler.code_end
    # Count total atoms + their data
    for _ in range(decompiler.hdr.get('natoms', 10)):
        if o + 4 > len(d): break
        alen = struct.unpack_from('<I', d, o)[0]
        o += 4
        if alen <= 0 or alen > 500: break
        o += alen * 2
    # Skip some buffer/padding
    o += 8

    objects = []
    for obj_idx in range(nobj):
        if o + 8 > len(d): break
        tag = u32le(d, o)
        _sentinel = u32le(d, o + 4)
        o += 8
        if tag != 0:  # not CK_JSFunction, skip
            continue
    objects = []

    for obj_idx in range(nobj):
        # Find next tag+sentinel pair
        found = False
        for search in range(o, min(o + 200, len(d) - 12)):
            tag = u32le(d, search)
            sentinel = u32le(d, search + 4)
            if tag == 0 and sentinel == 0xFFFFFFFF:
                o = search + 8
                found = True
                break
        if not found:
            break

        # Parse function
        obj, o = _parse_cocos51_function(decompiler, d, o)
        if obj is None:
            o += 8
            continue
        objects.append(obj)

    decompiler.objects = objects
    decompiler.nested_funcs = [(i, obj) for i, obj in enumerate(objects) if obj.get('sub')]


def _scan_atoms_with_pos(d, code_end):
    """Yield (position, length, string) for UTF-16LE atoms."""
    o = code_end
    seen = set()
    while o < len(d) - 8:
        raw_len = struct.unpack_from('<I', d, o)[0]
        if raw_len <= 0 or raw_len > 500:
            o += 1; continue
        start = o + 4
        size = raw_len * 2
        if start + size > len(d):
            o += 1; continue
        try:
            s = d[start:start+size].decode('utf-16le')
        except:
            o += 1; continue
        if s in seen:
            o += 1; continue
        seen.add(s)
        yield (o, raw_len, s)
        o = start + size


def _parse_cocos51_function(decompiler, d, o):
    """Parse sub_4F1540 + sub_58AF5C data. Returns (obj_dict, new_o)."""
    if o + 4 > len(d):
        return None, o

    firstWord = u32le(d, o); o += 4
    has_atom = firstWord & 1
    is_lazy = firstWord & 4

    name = ''
    if has_atom:
        if o + 4 > len(d):
            return None, o
        alen = u32le(d, o); o += 4
        sz = alen * 2
        if o + sz > len(d):
            return None, o
        try:
            name = d[o:o + sz].decode('utf-16le')
        except:
            name = ''
        o += sz

    if o + 4 > len(d):
        return None, o
    flagsWord = u32le(d, o); o += 4

    # Parse sub_58AF5C header: 13 words
    if o + 52 > len(d):
        return None, o
    fields = [u32le(d, o + i * 4) for i in range(13)]
    lineno = fields[0]
    codelen = fields[1]
    natoms = fields[4]
    nsrcnotes = fields[5]
    nobjects = fields[7]
    flags = fields[12]

    hdr_end = o + 52

    # After header: skip var slots (if any) and 4 extra DWORDs
    # For the top-level nested function, assume 0 var slots
    code_start = hdr_end + 16  # skip 4 extra header DWORDs

    if code_start + codelen > len(d):
        return None, o

    # Create nested decompiler
    from .decompiler import JSCDecompiler
    from .codegen import parse_code
    from .atoms import _parse_cocos51_sequential
    from .decompile import DecompileEngine

    sub = JSCDecompiler(d, dump_bytecode=decompiler.dump_bytecode,
                       parent=decompiler)
    sub.code_start = code_start
    sub.code_end = min(code_start + codelen, len(d))
    sub.hdr = {
        'nargs': 0, 'nbl': 0, 'nvars': 0, 'codelen': codelen,
        'natoms': natoms, 'nsrc': nsrcnotes, 'nconst': 0,
        'nobj': nobjects, 'nreg': 0, 'ntry': 0, 'nblk': 0,
        'sbits': flags
    }
    sub._is_cocos = True
    sub.off = code_start
    parse_code(sub)
    # Use atom scanning for nested function
    from .atoms import _scan_cocos_atoms
    sub.atoms = _scan_cocos_atoms(d, code_start + codelen)
    sub.consts = []

    engine = DecompileEngine(sub)
    engine.run()
    sub._func_body = engine.emit()
    sub._is_nested = True

    # Estimate where this object ends
    o = code_start + codelen + nsrcnotes
    for atom_str in sub.atoms:
        o += 4 + len(atom_str) * 2

    obj = {
        'name': name,
        'contextIndex': len(decompiler.nested_funcs) + len(getattr(decompiler, 'nested_funcs', [])),
        'sub': sub,
    }
    return obj, o


def _skip_cocos51_object(d, o):
    """Skip CK_JSObject data, return new offset."""
    if o + 16 > len(d):
        return o + 16
    is_array = u32le(d, o); o += 4
    length_or_kind = u32le(d, o); o += 4
    capacity = u32le(d, o); o += 4
    initialized = u32le(d, o); o += 4
    for _ in range(min(initialized, 100)):
        if o >= len(d):
            break
        ct = d[o]; o += 1
        if ct == 0:
            o += 4
        elif ct == 1:
            o += 8
        elif ct == 2:
            if o + 5 <= len(d):
                rl = u32le(d, o); o += 4
                o += rl * 2
        elif ct == 3 or ct == 4 or ct == 5 or ct == 7:
            pass
    return o
