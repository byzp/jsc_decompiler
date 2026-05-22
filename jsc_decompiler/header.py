"""JSC / JSCZ header parsing."""
import struct
from .utils import u32le


def parse_header(decompiler):
    """Populate decompiler.hdr, code_start, code_end, source_path."""
    d = decompiler.data
    ver = u32le(d, 0)

    if ver == 0xB973C051:
        _parse_cocos51(decompiler, ver)
        decompiler._is_cocos = True
        return

    # Standard MozJS34 header (0xB973C02C etc.)
    o = 0
    o += 4  # version
    nargs = struct.unpack_from('<H', d, o)[0]; o += 2
    nbl = struct.unpack_from('<H', d, o)[0];   o += 2
    nvars = u32le(d, o);   o += 4
    clen = u32le(d, o);    o += 4
    prolog = u32le(d, o);  o += 4
    jsver = u32le(d, o);   o += 4
    natoms = u32le(d, o);  o += 4
    nsrc = u32le(d, o);    o += 4
    nconst = u32le(d, o);  o += 4
    nobj = u32le(d, o);    o += 4
    nreg = u32le(d, o);    o += 4
    ntry = u32le(d, o);    o += 4
    nblk = u32le(d, o);    o += 4
    nts = u32le(d, o);     o += 4
    flen = u32le(d, o);    o += 4
    sbits = u32le(d, o);   o += 4

    decompiler.hdr = {
        'ver': ver, 'nargs': nargs, 'nbl': nbl, 'nvars': nvars,
        'codelen': clen, 'prolog': prolog, 'jsver': jsver,
        'natoms': natoms, 'nsrc': nsrc, 'nconst': nconst,
        'nobj': nobj, 'nreg': nreg, 'ntry': ntry,
        'nblk': nblk, 'nts': nts, 'flen': flen, 'sbits': sbits,
    }
    decompiler.code_start = o
    decompiler.code_end = o + clen if clen > 0 else o
    decompiler.off = o
    decompiler._is_cocos = False


def _parse_cocos51(decompiler, ver):
    """Custom Cocos2d-x .jscz wrapper header (version 0xB973C051)."""
    d = decompiler.data
    decompiler.hdr['ver'] = ver

    # --- Extract source path at offset 60 ---
    path_start = 60
    nul = d.find(b'\x00', path_start)
    if nul >= 0 and nul > path_start and (nul - path_start) < 512:
        decompiler.source_path = d[path_start:nul].decode('utf-8', errors='replace')
    else:
        decompiler.source_path = ''
        nul = path_start

    # --- Read header fields from fixed offsets ---
    # Cocos51 field layout (0xB973C051):
    # Fields are shifted vs standard: codelen/nvars swapped at 8/12,
    # then from offset 20 onward shifted by -4.
    # Standard:       nvars@8,  codelen@12, prolog@16, ver@20, natoms@24, nsrc@28, nconst@32, nobj@36
    # Cocos51 actual: codelen@8, nvars@12,  prolog@16, ?@20,   natoms@20, ?@24,   nconst@28, nobj@32
    codelen = u32le(d, 8)
    nvars = u32le(d, 12)
    prolog = u32le(d, 16)
    natoms = u32le(d, 20)
    nsrcnotes = u32le(d, 24)  # not always reliable
    nconst = u32le(d, 28)
    nobj = u32le(d, 32)
    nreg = u32le(d, 36)
    ntry = u32le(d, 40)
    nblk = u32le(d, 44)
    nts = u32le(d, 48)
    sbits = u32le(d, 56) if u32le(d, 56) < 0x10000 else 0

    decompiler.hdr.update({
        'nargs': 0, 'nbl': 0, 'nvars': nvars, 'codelen': codelen,
        'prolog': prolog, 'jsver': 0, 'natoms': natoms, 'nsrc': nsrcnotes,
        'nconst': nconst, 'nobj': nobj, 'nreg': nreg, 'ntry': ntry,
        'nblk': nblk, 'nts': nts, 'flen': 0, 'sbits': sbits,
    })

    # --- Code start = after padding + source metadata ---
    meta_start = nul + 1
    while meta_start < len(d) and d[meta_start] == 0:
        meta_start += 1
    meta_start = min(meta_start, nul + 5)

    code_start = meta_start + 12

    decompiler.code_start = code_start
    decompiler.code_end = min(code_start + codelen, len(d))
    decompiler.off = code_start
