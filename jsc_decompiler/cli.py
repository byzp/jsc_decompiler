"""Command-line entry points: single file, batch mode, and refs analysis."""
import os
import sys
from .decompiler import JSCDecompiler


def main():
    if len(sys.argv) < 2:
        print(f'Usage: {sys.argv[0]} <input.jsc[z]> [output.js]')
        print(f'       {sys.argv[0]} --batch <input_dir> <output_dir>')
        print(f'       {sys.argv[0]} --refs <decompiled_dir> [--json|--inject]')
        print(f'       {sys.argv[0]} --imports <decompiled_dir>   # variable-based analysis')
        print(f'       add --dump-bytecode for disassembly comments')
        print(f'       add --ascii-escapes to emit \\\\uXXXX instead of raw Unicode')
        sys.exit(1)

    dump_bytecode = '--dump-bytecode' in sys.argv
    ascii_escapes = '--ascii-escapes' in sys.argv
    args = [a for a in sys.argv[1:] if a not in ('--dump-bytecode', '--ascii-escapes')]

    from . import stack
    stack.set_unicode_mode(ascii_escapes)

    if args[0] == '--refs':
        _refs_mode(args[1:])
    elif args[0] == '--imports':
        _imports_mode(args[1:])
    elif args[0] == '--batch':
        _batch_mode(args[1], args[2], dump_bytecode)
    else:
        _single_mode(args, dump_bytecode)


def _refs_mode(args):
    """Analyze references between decompiled JS files."""
    from .refs import cli_analyze
    decompiled_dir = args[0] if args else 'decompiled_scripts'
    fmt = 'text'
    if '--json' in args:
        fmt = 'json'
    if '--inject' in args:
        fmt = 'inject'
    out_file = None
    for a in args[1:]:
        if a not in ('--json', '--inject'):
            out_file = a
    cli_analyze(decompiled_dir, output_file=out_file, format=fmt)


def _imports_mode(args):
    """Analyze and inject variable-based imports."""
    from .var_analysis import cli_inject, cli_show_missing
    decompiled_dir = args[0] if args else 'decompiled_scripts'
    if '--show' in args:
        cli_show_missing(decompiled_dir)
    else:
        cli_inject(decompiled_dir)


def _single_mode(args, dump_bytecode):
    fn = args[0]
    with open(fn, 'rb') as f:
        data = f.read()
    dec = JSCDecompiler(data, dump_bytecode=dump_bytecode)
    result = dec.run()
    if len(args) > 1:
        ofn = args[1]
        with open(ofn, 'w', encoding='utf-8') as f:
            f.write(f'// Decompiled from: {os.path.basename(fn)}\n')
            f.write(f'// Version: 0x{dec.hdr["ver"]:08x}\n')
            f.write(result + '\n')
        print(f'Written to {ofn}')
    else:
        print(result)


def _batch_mode(indir, outdir, dump_bytecode, inject_refs=True):
    os.makedirs(outdir, exist_ok=True)
    count = 0
    errors = []
    for root, dirs, files in os.walk(indir):
        for fn in sorted(files):
            if not fn.endswith('.jscz') and not fn.endswith('.jsc'):
                continue
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, indir)
            ofn = os.path.join(outdir, rel.replace('.jscz', '.js').replace('.jsc', '.js'))
            os.makedirs(os.path.dirname(ofn), exist_ok=True)
            try:
                with open(fp, 'rb') as f:
                    data = f.read()
                if len(data) < 64:
                    print(f'  SKIP {rel}: too small')
                    continue
                dec = JSCDecompiler(data, dump_bytecode=dump_bytecode)
                result = dec.run()
                with open(ofn, 'w', encoding='utf-8') as f:
                    f.write(f'// Decompiled from: {os.path.basename(fn)}\n')
                    f.write(f'// Version: 0x{dec.hdr["ver"]:08x}\n')
                    f.write(f'// nargs={dec.hdr.get("nargs",0)} nvars={dec.hdr.get("nvars",0)}')
                    f.write(f' atoms={len(dec.atoms)} code={dec.hdr.get("codelen",0)}\n')
                    f.write(result + '\n')
                count += 1
            except Exception as e:
                errors.append((rel, str(e)))
                print(f'  ERR: {rel}: {e}')
    print(f'\nDone: {count} files decompiled')
    if errors:
        for rel, err in errors:
            print(f'  ERR: {rel}: {err}')

    # Inject variable-based references into decompiled files
    if inject_refs:
        from .var_analysis import inject_imports
        updated = inject_imports(outdir)
        print('Injected variable imports into {} files'.format(updated))


if __name__ == '__main__':
    main()
