#!/usr/bin/env python3
"""JSC bytecode decompiler - MozJS34 (0xB973C02C / 0xB973C051)

Unified entry-point. Real work lives in jsc_decompiler/.
Usage:
  python jsc2js.py <file.jscz> [output.js]
  python jsc2js.py --batch Scripts decompiled_scripts
  python jsc2js.py --batch Scripts decompiled_scripts --dump-bytecode
"""
from jsc_decompiler.cli import main

if __name__ == '__main__':
    main()
