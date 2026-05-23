"""Cross-file variable definition and usage analysis.

Finds which files define which globals, and which files use globals
that are defined elsewhere. Generates accurate require() statements.
"""
import os, re, json
from collections import Counter, defaultdict


def strip_comments_strings(content):
    """Remove comments and string literals from JS code."""
    c = re.sub(r'//.*$', ' ', content, flags=re.MULTILINE)
    c = re.sub(r'/\*.*?\*/', ' ', c, flags=re.DOTALL)
    c = re.sub(r'"[^"]*"', '""', c)
    c = re.sub(r"'[^']*'", "''", c)
    return c


def get_defines_uses(content):
    """Return (defined_set, used_set) of identifiers in code."""
    code = strip_comments_strings(content)
    defined = set()
    used = set()

    # var declarations
    for m in re.finditer(r'\bvar\s+(\w+)', code):
        defined.add(m.group(1))
    # function declarations
    for m in re.finditer(r'\bfunction\s+(\w+)', code):
        defined.add(m.group(1))
    # top-level assignments
    for m in re.finditer(r'(?<![,\{(.\[<!>=])\s*(\w{2,})\s*=', code):
        defined.add(m.group(1))
    # prototype assignments
    for m in re.finditer(r'(\w+)\.prototype\.(\w+)\s*=', code):
        defined.add(m.group(1))

    # all identifiers
    for m in re.finditer(r'\b([a-zA-Z_$][\w$]*)\b', code):
        name = m.group(1)
        if name in defined:
            continue
        if re.match(r'^l\d+$', name): continue
        if re.match(r'^a\d+$', name): continue
        if name.startswith('#a'): continue
        if name.startswith('__'): continue
        skip = {'true', 'false', 'null', 'undefined', 'this', 'if', 'else',
                'for', 'while', 'do', 'switch', 'case', 'default', 'break',
                'continue', 'return', 'throw', 'try', 'catch', 'finally',
                'new', 'typeof', 'instanceof', 'in', 'void', 'delete', 'var',
                'function', 'arguments', 'NaN', 'Infinity',
                'Array', 'Object', 'String', 'Number', 'Boolean', 'Date',
                'JSON', 'Math', 'Error', 'RegExp', 'parseInt', 'parseFloat',
                'isNaN', 'parseInt', 'parseFloat', 'isFinite',
                'constructor', 'prototype', 'length',
                'apply', 'call', 'bind', 'toString', 'valueOf'}
        if name in skip: continue
        if len(name) <= 1: continue
        # Skip comment keywords
        if name in ('nargs', 'nvars', 'code', 'ver', 'Version', 'Decompiled',
                    'jscz', 'source', 'atoms', 'from', 'References',
                    'Res_ref', 'Scripts', 'End'): continue
        used.add(name)

    # remove function params from used
    for m in re.finditer(r'function\s*\w*\s*\((.*?)\)', code):
        for arg in re.findall(r'\w+', m.group(1)):
            used.discard(arg)

    return defined, used


def build_global_map(decompiled_dir):
    """Build {filename: defined_globals} and {global_name: [defining_files]}."""
    file_defs = {}
    global_to_files = defaultdict(list)

    for root, dirs, filenames in os.walk(decompiled_dir):
        for fn in sorted(filenames):
            if not fn.endswith('.js'):
                continue
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, decompiled_dir).replace('\\', '/')
            try:
                with open(fp, encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except Exception:
                continue
            defined, used = get_defines_uses(content)

            # Only keep likely global exports (non-local names)
            exports = {d for d in defined
                       if not d.startswith('_') and len(d) > 1}
            if exports:
                file_defs[rel] = exports
                for d in exports:
                    global_to_files[d].append(rel)

    return file_defs, global_to_files


def find_missing_imports(decompiled_dir):
    file_defs, global_to_files = build_global_map(decompiled_dir)
    missing = {}

    for root, dirs, filenames in os.walk(decompiled_dir):
        for fn in sorted(filenames):
            if not fn.endswith('.js'):
                continue
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, decompiled_dir).replace('\\', '/')
            try:
                with open(fp, encoding='utf-8', errors='replace') as f:
                    content = f.read()
            except Exception:
                continue

            defined, used = get_defines_uses(content)
            local_defs = file_defs.get(rel, set())

            needed = []
            for name in sorted(used):
                if name in local_defs:
                    continue
                if name not in global_to_files:
                    continue
                def_files = [f for f in global_to_files[name] if f != rel]
                if not def_files:
                    continue
                # Only include if name is unique enough (<=2 defining files)
                # and name has reasonable length
                if len(name) <= 2:
                    continue
                if len(def_files) > 2:
                    continue  # too ambiguous
                # Skip names that look like local variables
                if re.match(r'^[a-z]{1,3}\d*$', name):
                    continue
                needed.append((name, def_files))

            if needed:
                missing[rel] = needed

    return missing, file_defs, global_to_files


def generate_imports(missing, decompiled_dir):
    """Generate require() calls for each file's missing globals."""
    imports = {}
    for rel, needed in sorted(missing.items()):
        cur_dir = os.path.dirname(rel)
        lines = []
        seen_files = set()

        # Group by defining file
        file_to_names = defaultdict(list)
        for name, def_files in needed:
            # Pick the best source file
            best = min(def_files, key=lambda f: _import_score(rel, f))
            file_to_names[best].append(name)

        for def_file, names in sorted(file_to_names.items()):
            if def_file in seen_files:
                continue
            seen_files.add(def_file)
            rel_path = os.path.relpath(def_file, cur_dir).replace('\\', '/')
            if not rel_path.startswith('.'):
                rel_path = './' + rel_path
            names_str = ', '.join(sorted(set(names))[:5])
            if len(names) > 5:
                names_str += ', ...'
            lines.append('// require("{}")  // provides: {}'.format(rel_path, names_str))

        if lines:
            imports[rel] = lines

    return imports


def _import_score(current, candidate):
    """Lower score = better import source."""
    cur_parts = current.split('/')
    cand_parts = candidate.split('/')
    i = 0
    while i < min(len(cur_parts), len(cand_parts)) and cur_parts[i] == cand_parts[i]:
        i += 1
    # Prefer files in same directory or nearby
    return len(cand_parts) - i


def inject_imports(decompiled_dir):
    """Inject require() comments into files based on missing globals."""
    missing, file_defs, global_to_files = find_missing_imports(decompiled_dir)
    imports = generate_imports(missing, decompiled_dir)

    updated = 0
    for rel, lines in sorted(imports.items()):
        fp = os.path.join(decompiled_dir, rel.replace('/', os.sep))
        try:
            with open(fp, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
        except Exception:
            continue

        # Remove old import section
        if content.startswith('// References:'):
            parts = content.split('\n// End References\n', 1)
            if len(parts) > 1:
                content = parts[1]

        header = '// References:\n'
        for line in lines:
            header += line + '\n'
        header += '// End References\n\n'
        new_content = header + content

        with open(fp, 'w', encoding='utf-8') as f:
            f.write(new_content)
        updated += 1

    return updated, imports


def cli_inject(decompiled_dir):
    """CLI: inject import comments."""
    updated, imports = inject_imports(decompiled_dir)
    print('Injected imports into {} files'.format(updated))
    for rel, lines in sorted(imports.items())[:10]:
        print('  {}: {} imports'.format(rel, len(lines)))


def cli_show_missing(decompiled_dir):
    """CLI: show missing imports by file."""
    missing, file_defs, global_to_files = find_missing_imports(decompiled_dir)
    imports = generate_imports(missing, decompiled_dir)
    for rel, lines in sorted(imports.items())[:20]:
        print('\n## {}'.format(rel))
        for line in lines:
            print('  {}'.format(line))
