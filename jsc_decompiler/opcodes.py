"""Opcode table from libCakeMania.so binary (Cocos2d-x custom MozJS build).

Extracted from js_opcode_str[] (names) and js_CodeSpec (lengths/use/def)
from the .rodata section of the binary.
"""
import os
from ._codespec import CODESPEC

# Binary opcode names (230 entries, 0x00-0xE5)
_BINARY_NAMES = {
    0x00:'nop',0x01:'undefined',0x02:'popv',0x03:'enterwith',0x04:'leavewith',
    0x05:'return',0x06:'goto',0x07:'ifeq',0x08:'ifne',0x09:'arguments',
    0x0A:'swap',0x0B:'popn',0x0C:'dup',0x0D:'dup2',0x0E:'setconst',
    0x0F:'bitor',0x10:'bitxor',0x11:'bitand',0x12:'eq',0x13:'ne',
    0x14:'lt',0x15:'le',0x16:'gt',0x17:'ge',0x18:'lsh',0x19:'rsh',
    0x1A:'ursh',0x1B:'add',0x1C:'sub',0x1D:'mul',0x1E:'div',0x1F:'mod',
    0x20:'not',0x21:'bitnot',0x22:'neg',0x23:'pos',0x24:'delname',
    0x25:'delprop',0x26:'delelem',0x27:'typeof',0x28:'void',
    0x29:'incname',0x2A:'incprop',0x2B:'incelem',0x2C:'decname',
    0x2D:'decprop',0x2E:'decelem',0x2F:'nameinc',0x30:'propinc',
    0x31:'eleminc',0x32:'namedec',0x33:'propdec',0x34:'elemdec',
    0x35:'getprop',0x36:'setprop',0x37:'getelem',0x38:'setelem',
    0x39:'callname',0x3A:'call',0x3B:'name',0x3C:'double',0x3D:'string',
    0x3E:'zero',0x3F:'one',0x40:'null',0x41:'this',0x42:'false',0x43:'true',
    0x44:'or',0x45:'and',0x46:'tableswitch',0x47:'unused47',0x48:'stricteq',
    0x49:'strictne',0x4A:'setcall',0x4B:'iter',0x4C:'moreiter',
    0x4D:'iternext',0x4E:'enditer',0x4F:'funapply',0x50:'object',
    0x51:'pop',0x52:'new',0x53:'spread',0x54:'getarg',0x55:'setarg',
    0x56:'getlocal',0x57:'setlocal',0x58:'uint16',0x59:'newinit',
    0x5A:'newarray',0x5B:'newobject',0x5C:'endinit',0x5D:'initprop',
    0x5E:'initelem',0x5F:'initelem_inc',0x60:'initelem_array',
    0x61:'incarg',0x62:'decarg',0x63:'arginc',0x64:'argdec',
    0x65:'inclocal',0x66:'declocal',0x67:'localinc',0x68:'localdec',
    0x69:'leaveforletin',0x6A:'label',0x6B:'unused107',0x6C:'funcall',
    0x6D:'loophead',0x6E:'bindname',0x6F:'setname',0x70:'throw',0x71:'in',
    0x72:'instanceof',0x73:'debugger',0x74:'gosub',0x75:'retsub',
    0x76:'exception',0x77:'lineno',0x78:'condswitch',0x79:'case',
    0x7A:'default',0x7B:'eval',0x7C:'enumelem',0x7D:'getter',0x7E:'setter',
    0x7F:'deffun',0x80:'defconst',0x81:'defvar',0x82:'lambda',0x83:'callee',
    0x84:'unused132',0x85:'pick',0x86:'try',0x87:'finally',
    0x88:'getaliasedvar',0x89:'callaliasedvar',0x8A:'setaliasedvar',
    0x8B:'incaliasedvar',0x8C:'decaiasedvar',0x8D:'aliasedvarinc',
    0x8E:'aliasedvardec',0x8F:'getintrinsic',0x90:'callintrinsic',
    0x91:'setintrinsic',0x92:'bindintrinsic',0x93:'unused147',
    0x94:'unused148',0x95:'backpatch',0x96:'unused150',0x97:'throwing',
    0x98:'setrval',0x99:'retrval',0x9A:'getgname',0x9B:'setgname',
    0x9C:'incgname',0x9D:'decgname',0x9E:'gnameinc',0x9F:'gnamedec',
    0xA0:'regexp',0xA1:'unused161',0xA2:'unused162',0xA3:'unused163',
    0xA4:'unused164',0xA5:'unused165',0xA6:'unused166',0xA7:'unused167',
    0xA8:'unused168',0xA9:'unused169',0xAA:'unused170',0xAB:'unused171',
    0xAC:'unused172',0xAD:'unused173',0xAE:'unused174',0xAF:'unused175',
    0xB0:'unused176',0xB1:'unused177',0xB2:'unused178',0xB3:'unused179',
    0xB4:'unused180',0xB5:'unused181',0xB6:'unused182',0xB7:'unused183',
    0xB8:'callprop',0xB9:'enterlet0',0xBA:'enterlet1',0xBB:'uint24',
    0xBC:'unused188',0xBD:'unused189',0xBE:'unused190',0xBF:'unused191',
    0xC0:'unused192',0xC1:'callelem',0xC2:'stop',0xC3:'getxprop',
    0xC4:'unused196',0xC5:'typeofexpr',0xC6:'enterblock',0xC7:'leaveblock',
    0xC8:'unused200',0xC9:'unused201',0xCA:'generator',0xCB:'yield',
    0xCC:'arraypush',0xCD:'getfunns',0xCE:'enumconstelem',
    0xCF:'leaveblockexpr',0xD0:'unused208',0xD1:'unused209',
    0xD2:'unused210',0xD3:'callgname',0xD4:'calllocal',0xD5:'callarg',
    0xD6:'bindgname',0xD7:'int8',0xD8:'int32',0xD9:'length',0xDA:'hole',
    0xDB:'unused219',0xDC:'unused220',0xDD:'unused221',0xDE:'unused222',
    0xDF:'unused223',0xE0:'rest',0xE1:'toid',0xE2:'implicitthis',
    0xE3:'loopentry',0xE4:'notearg',0xE5:'proxy',
}

# Lengths inferred from standard MozJS34 equivalents + semantic analysis
_BINARY_LENGTHS = {}
_IDX_NAMES = frozenset({
    'name','bindname','setname','getprop','setprop','callprop','string',
    'implicitthis','callname','defvar','defconst','delname','delprop',
    'getgname','setgname','bindgname','initprop','getintrinsic','setintrinsic',
    'bindintrinsic','callintrinsic','callgname',
    'incname','decname','nameinc','namedec','incprop','decprop','propinc','propdec',
    'deffun','lambda','newobject','object','regexp','setconst','double','getter','setter',
    'getxprop','getfunns','length','incgname','decgname','gnameinc','gnamedec',
    'enterlet0','enterlet1','enterblock',
})
_ALIASED_NAMES = frozenset({
    'getaliasedvar','setaliasedvar','callaliasedvar','incaliasedvar',
    'decaiasedvar','aliasedvarinc','aliasedvardec',
})
_JUMP_NAMES = frozenset({'goto','ifeq','ifne','or','and','label','case','default','gosub','backpatch'})
_CALL_NAMES = frozenset({'call','new','funcall','eval','funapply'})
_ARG_NAMES = frozenset({'getarg','setarg','callarg','incarg','decarg','arginc','argdec'})
_LOCAL_NAMES = frozenset({'getlocal','setlocal','calllocal','inclocal','declocal','localinc','localdec'})

def _get_default_len(name):
    """Return (length, use, push) for a binary opcode name."""
    ln = 1
    use = 0
    push = 0

    if name in _IDX_NAMES:
        ln = 5; push = 1
    elif name in _ALIASED_NAMES:
        ln = 5; push = 1
    elif name in _JUMP_NAMES:
        ln = 5
        if name not in ('label','gosub','backpatch'):
            use = 1; push = 1
    elif name in _CALL_NAMES:
        ln = 3
        use = -1; push = 1
    elif name in _ARG_NAMES:
        ln = 3; push = 1
    elif name in _LOCAL_NAMES:
        ln = 4; push = 1
    elif name == 'tableswitch':
        ln = -1; use = 1
    elif name == 'uint16':
        ln = 3; push = 1
    elif name == 'uint24':
        ln = 4; push = 1
    elif name == 'int8':
        ln = 2; push = 1
    elif name == 'int32':
        ln = 5; push = 1
    elif name == 'popn':
        ln = 3; use = -1
    elif name == 'pick':
        ln = 2
    elif name in ('pop','popv'):
        ln = 1; use = 1
    elif name == 'dup':
        ln = 1; use = 1; push = 2
    elif name == 'dup2':
        ln = 1; use = 2; push = 4
    elif name == 'swap':
        ln = 1; use = 2; push = 2
    elif name == 'newinit':
        ln = 5; push = 1
    elif name == 'newarray':
        ln = 4; push = 1
    elif name == 'initelem_array':
        ln = 4
    elif name == 'enumconstelem':
        ln = 4
    elif name == 'iter':
        ln = 2; use = 1; push = 1
    elif name == 'loopentry':
        ln = 2
    elif name in ('lineno',):
        ln = 3

    # Literals
    elif name in ('undefined','zero','one','null','this','false','true'):
        push = 1
    elif name == 'notearg':
        pass  # no-op
    elif name == 'callee':
        push = 1
    elif name == 'hole':
        push = 1
    elif name == 'stop':
        pass
    elif name in ('typeof','typeofexpr'):
        use = 1; push = 1
    elif name == 'void':
        use = 1; push = 1
    elif name == 'neg':
        use = 1; push = 1

    # Binary/unary ops
    elif name in ('add','sub','mul','div','mod','bitor','bitxor','bitand',
                  'lsh','rsh','ursh','eq','ne','lt','le','gt','ge',
                  'stricteq','strictne','in','instanceof'):
        use = 2; push = 1
    elif name in ('not','bitnot'):
        use = 1; push = 1

    # Set/elem ops
    elif name in ('setprop','initprop','setgname','setintrinsic','getter','setter'):
        use = 2; push = 1
    elif name in ('setelem',):
        use = 3; push = 1
    elif name in ('getprop','callprop','callelem','getelem','enumelem','getgname','getintrinsic','callgname','callintrinsic'):
        use = 1; push = 1
    elif name == 'length':
        use = 1; push = 1

    # Other
    elif name == 'rest':
        push = 1
    elif name == 'arguments':
        push = 1
    elif name in ('setrval','throwing'):
        use = 1
    elif name == 'yield':
        use = 1; push = 1
    elif name == 'throw':
        use = 1
    elif name == 'arraypush':
        use = 2
    elif name == 'finally':
        push = 2
    elif name == 'exception':
        push = 1
    elif name == 'spread':
        use = 3; push = 1

    return (ln, use, push)


def build_table():
    """Fill JSOP table from binary names + CodeSpec."""
    global JSOP
    for oc in range(0xE6):
        name = _BINARY_NAMES.get(oc, f'unused{oc}')
        if oc in CODESPEC:
            ln, use, push, prec, fmt = CODESPEC[oc]
        else:
            ln, use, push = 1, 0, 0
        JSOP[oc] = {
            'name': name,
            'image': None,
            'length': ln,
            'use': use,
            'push': push,
        }


JSOP = {}
SCRIPT_BITS = [
    'NoScriptRval', 'SavedCallerFun', 'Strict', 'ContainsDynamicNameAccess',
    'FunHasExtensibleScope', 'FunNeedsDeclEnvObject', 'FunHasAnyAliasedFormal',
    'ArgumentsHasVarBinding', 'NeedsArgsObj', 'IsGeneratorExp', 'IsLegacyGenerator',
    'IsStarGenerator', 'OwnSource', 'ExplicitUseStrict', 'SelfHosted', 'IsCompileAndGo',
    'HasSingleton', 'TreatAsRunOnce', 'HasLazyScript',
]

IMAGE_OPS = {
    'add': '+', 'sub': '-', 'mul': '*', 'div': '/',
    'mod': '%', 'bitor': '|', 'bitxor': '^', 'bitand': '&',
    'lsh': '<<', 'rsh': '>>', 'ursh': '>>>',
    'eq': '==', 'ne': '!=', 'lt': '<', 'le': '<=',
    'gt': '>', 'ge': '>=', 'stricteq': '===', 'strictne': '!==',
    'not': '!', 'bitnot': '~', 'neg': '-',
}

NOOP_NAMES = frozenset({
    'nop', 'endinit', 'retrval', 'loopentry',
    'lineno', 'goto', 'label', 'backpatch',
    'pos', 'setcall', 'callee',
    'gosub', 'toid', 'generator',
    'enterblock', 'debugger',
    'enterwith', 'leavewith',
    'notearg', 'loophead', 'stop', 'leaveforletin',
})


def get_op_info(op_byte, is_cocos=False):
    """Return {'name', 'length', 'use', 'push'} for a raw opcode byte."""
    info = JSOP.get(op_byte)
    if info:
        return info
    # Infer unknown opcodes as length 1 no-op
    return {
        'name': f'unk_{op_byte:02x}',
        'image': None,
        'length': 1,
        'use': 0,
        'push': 0,
    }


build_table()
