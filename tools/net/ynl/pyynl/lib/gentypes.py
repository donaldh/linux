# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
# pylint: disable=line-too-long, missing-class-docstring, missing-function-docstring
# pylint: disable=too-many-positional-arguments, too-many-arguments, too-many-statements
# pylint: disable=too-many-branches, too-many-locals, too-many-instance-attributes
# pylint: disable=too-many-nested-blocks, too-many-lines, too-few-public-methods
# pylint: disable=broad-exception-raised, broad-exception-caught, protected-access

"""
Codegen types derived from the YNL Spec* types
"""

import pathlib
import sys

# pylint: disable=no-name-in-module,wrong-import-position
sys.path.append(pathlib.Path(__file__).resolve().parent.as_posix())
from lib import SpecFamily, SpecAttrSet, SpecAttr, SpecOperation, SpecEnumSet, SpecEnumEntry
from lib import SpecSubMessage


scalars = {'u8', 'u16', 'u32', 'u64', 's8', 's16', 's32', 's64', 'uint', 'sint'}

_C_KW = {
    'auto',
    'bool',
    'break',
    'case',
    'char',
    'const',
    'continue',
    'default',
    'do',
    'double',
    'else',
    'enum',
    'extern',
    'float',
    'for',
    'goto',
    'if',
    'inline',
    'int',
    'long',
    'register',
    'return',
    'short',
    'signed',
    'sizeof',
    'static',
    'struct',
    'switch',
    'typedef',
    'union',
    'unsigned',
    'void',
    'volatile',
    'while'
}


direction_to_suffix = {
    'reply': '_rsp',
    'request': '_req',
    '': ''
}

op_mode_to_wrapper = {
    'do': '',
    'dump': '_list',
    'notify': '_ntf',
    'event': '',
}



def c_upper(name):
    return name.upper().replace('-', '_')


def c_lower(name):
    return name.lower().replace('-', '_')


def type_name(ri, direction, deref=False):
    return f"struct {op_prefix(ri, direction, deref=deref)}"


def limit_to_number(name):
    """
    Turn a string limit like u32-max or s64-min into its numerical value
    """
    if name[0] == 'u' and name.endswith('-min'):
        return 0
    width = int(name[1:-4])
    if name[0] == 's':
        width -= 1
    value = (1 << width) - 1
    if name[0] == 's' and name.endswith('-min'):
        value = -value - 1
    return value


def op_prefix(ri, direction, deref=False):
    suffix = f"_{ri.type_name}"

    if not ri.op_mode:
        pass
    elif ri.op_mode == 'do':
        suffix += f"{direction_to_suffix[direction]}"
    else:
        if direction == 'request':
            suffix += '_req'
            if not ri.type_oneside:
                suffix += '_dump'
        else:
            if ri.type_consistent:
                if deref:
                    suffix += f"{direction_to_suffix[direction]}"
                else:
                    suffix += op_mode_to_wrapper[ri.op_mode]
            else:
                suffix += '_rsp'
                suffix += '_dump' if deref else '_list'

    return f"{ri.family.c_name}{suffix}"


class BaseNlLib:
    def get_family_id(self):
        return 'ys->family_id'


class Type(SpecAttr):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.attr = attr
        self.attr_set = attr_set
        self.type = attr['type']
        self.checks = attr.get('checks', {})

        self.request = False
        self.reply = False

        self.is_selector = False

        if 'len' in attr:
            self.len = attr['len']

        if 'nested-attributes' in attr:
            nested = attr['nested-attributes']
        elif 'sub-message' in attr:
            nested = attr['sub-message']
        else:
            nested = None

        if nested:
            self.nested_attrs = nested
            if self.nested_attrs == family.name:
                self.nested_render_name = c_lower(f"{family.ident_name}")
            else:
                self.nested_render_name = c_lower(f"{family.ident_name}_{self.nested_attrs}")

            if self.nested_attrs in self.family.consts:
                self.nested_struct_type = 'struct ' + self.nested_render_name + '_'
            else:
                self.nested_struct_type = 'struct ' + self.nested_render_name

        self.c_name = c_lower(self.name)
        if self.c_name in _C_KW:
            self.c_name += '_'
        if self.c_name[0].isdigit():
            self.c_name = '_' + self.c_name

        # Added by resolve():
        self.enum_name = None
        delattr(self, "enum_name")

    def _get_real_attr(self):
        # if the attr is for a subset return the "real" attr (just one down, does not recurse)
        return self.family.attr_sets[self.attr_set.subset_of][self.name]

    def set_request(self):
        self.request = True
        if self.attr_set.subset_of:
            self._get_real_attr().set_request()

    def set_reply(self):
        self.reply = True
        if self.attr_set.subset_of:
            self._get_real_attr().set_reply()

    def get_limit(self, limit, default=None):
        value = self.checks.get(limit, default)
        if value is None:
            return value
        if isinstance(value, int):
            return value
        if value in self.family.consts:
            return self.family.consts[value]["value"]
        return limit_to_number(value)

    def get_limit_str(self, limit, default=None, suffix=''):
        value = self.checks.get(limit, default)
        if value is None:
            return ''
        if isinstance(value, int):
            return str(value) + suffix
        if value in self.family.consts:
            const = self.family.consts[value]
            if const.get('header'):
                return c_upper(value)
            return c_upper(f"{self.family['name']}-{value}")
        return c_upper(value)

    def resolve(self):
        if 'parent-sub-message' in self.attr:
            enum_name = self.attr['parent-sub-message'].enum_name
        elif 'name-prefix' in self.attr:
            enum_name = f"{self.attr['name-prefix']}{self.name}"
        else:
            enum_name = f"{self.attr_set.name_prefix}{self.name}"
        self.enum_name = c_upper(enum_name)

        if self.attr_set.subset_of:
            if self.checks != self._get_real_attr().checks:
                raise Exception("Overriding checks not supported by codegen, yet")

    def is_multi_val(self):
        return None

    def is_scalar(self):
        return self.type in {'u8', 'u16', 'u32', 'u64', 's32', 's64'}

    def is_recursive(self):
        return False

    def is_recursive_for_op(self, ri):
        return self.is_recursive() and not ri.op

    def presence_type(self):
        return 'present'

    def presence_member(self, space, type_filter):
        if self.presence_type() != type_filter:
            return ''

        if self.presence_type() == 'present':
            pfx = '__' if space == 'user' else ''
            return f"{pfx}u32 {self.c_name}:1;"

        if self.presence_type() in {'len', 'count'}:
            pfx = '__' if space == 'user' else ''
            return f"{pfx}u32 {self.c_name};"
        return ''

    def _complex_member_type(self, _ri):
        return None

    def free_needs_iter(self):
        return False

    def _free_lines(self, _ri, var, ref):
        if self.is_multi_val() or self.presence_type() in {'count', 'len'}:
            return [f'free({var}->{ref}{self.c_name});']
        return []

    def free(self, ri, var, ref):
        lines = self._free_lines(ri, var, ref)
        for line in lines:
            ri.cw.p(line)

    # pylint: disable=assignment-from-none
    def arg_member(self, ri):
        member = self._complex_member_type(ri)
        if member is not None:
            spc = ' ' if member[-1] != '*' else ''
            arg = [member + spc + '*' + self.c_name]
            if self.presence_type() == 'count':
                arg += ['unsigned int n_' + self.c_name]
            return arg
        raise Exception(f"Struct member not implemented for class type {self.type}")

    def struct_member(self, ri):
        member = self._complex_member_type(ri)
        if member is not None:
            ptr = '*' if self.is_multi_val() else ''
            if self.is_recursive_for_op(ri):
                ptr = '*'
            spc = ' ' if member[-1] != '*' else ''
            ri.cw.p(f"{member}{spc}{ptr}{self.c_name};")
            return
        members = self.arg_member(ri)
        for one in members:
            ri.cw.p(one + ';')

    def _attr_policy(self, policy):
        return '{ .type = ' + policy + ', }'

    def attr_policy(self, cw):
        policy = f'NLA_{c_upper(self.type)}'
        if self.attr.get('byte-order') == 'big-endian':
            if self.type in {'u16', 'u32'}:
                policy = f'NLA_BE{self.type[1:]}'

        spec = self._attr_policy(policy)
        cw.p(f"\t[{self.enum_name}] = {spec},")

    def _attr_typol(self):
        raise Exception(f"Type policy not implemented for class type {self.type}")

    def attr_typol(self, cw):
        typol = self._attr_typol()
        cw.p(f'[{self.enum_name}] = {"{"} .name = "{self.name}", {typol}{"}"},')

    def _attr_put_line(self, ri, var, line):
        presence = self.presence_type()
        if presence in {'present', 'len'}:
            ri.cw.p(f"if ({var}->_{presence}.{self.c_name})")
        ri.cw.p(f"{line};")

    def _attr_put_simple(self, ri, var, put_type):
        line = f"ynl_attr_put_{put_type}(nlh, {self.enum_name}, {var}->{self.c_name})"
        self._attr_put_line(ri, var, line)

    def attr_put(self, ri, var):
        raise Exception(f"Put not implemented for class type {self.type}")

    def _attr_get(self, ri, var):
        raise Exception(f"Attr get not implemented for class type {self.type}")

    def attr_get(self, ri, var, first):
        lines, init_lines, _ = self._attr_get(ri, var)
        if isinstance(lines, str):
            lines = [lines]
        if isinstance(init_lines, str):
            init_lines = [init_lines]

        kw = 'if' if first else 'else if'
        ri.cw.block_start(line=f"{kw} (type == {self.enum_name})")

        if not self.is_multi_val():
            ri.cw.p("if (ynl_attr_validate(yarg, attr))")
            ri.cw.p("return YNL_PARSE_CB_ERROR;")
            if self.presence_type() == 'present':
                ri.cw.p(f"{var}->_present.{self.c_name} = 1;")

        if init_lines:
            ri.cw.nl()
            for line in init_lines:
                ri.cw.p(line)

        for line in lines:
            ri.cw.p(line)
        ri.cw.block_end()
        return True

    def _setter_lines(self, ri, member, presence):
        raise Exception(f"Setter not implemented for class type {self.type}")

    def setter(self, ri, _space, direction, deref=False, ref=None, var="req"):
        ref = (ref if ref else []) + [self.c_name]
        member = f"{var}->{'.'.join(ref)}"

        local_vars = []
        if self.free_needs_iter():
            local_vars += ['unsigned int i;']

        code = []
        presence = ''
        # pylint: disable=consider-using-enumerate
        for i in range(0, len(ref)):
            presence = f"{var}->{'.'.join(ref[:i] + [''])}_present.{ref[i]}"
            # Every layer below last is a nest, so we know it uses bit presence
            # last layer is "self" and may be a complex type
            if i == len(ref) - 1 and self.presence_type() != 'present':
                presence = f"{var}->{'.'.join(ref[:i] + [''])}_{self.presence_type()}.{ref[i]}"
                continue
            code.append(presence + ' = 1;')
        ref_path = '.'.join(ref[:-1])
        if ref_path:
            ref_path += '.'
        code += self._free_lines(ri, var, ref_path)
        code += self._setter_lines(ri, member, presence)

        func_name = f"{op_prefix(ri, direction, deref=deref)}_set_{'_'.join(ref)}"
        free = bool([x for x in code if 'free(' in x])
        alloc = bool([x for x in code if 'alloc(' in x])
        if free and not alloc:
            func_name = '__' + func_name
        ri.cw.write_func('static inline void', func_name, local_vars=local_vars,
                         body=code,
                         args=[f'{type_name(ri, direction, deref=deref)} *{var}'] + self.arg_member(ri))


class TypeUnused(Type):
    def presence_type(self):
        return ''

    def arg_member(self, ri):
        return []

    def _attr_get(self, ri, var):
        return ['return YNL_PARSE_CB_ERROR;'], None, None

    def _attr_typol(self):
        return '.type = YNL_PT_REJECT, '

    def attr_policy(self, cw):
        pass

    def attr_put(self, ri, var):
        pass

    def attr_get(self, ri, var, first):
        pass

    def setter(self, ri, space, direction, deref=False, ref=None, var=None):
        pass


class TypePad(Type):
    def presence_type(self):
        return ''

    def arg_member(self, ri):
        return []

    def _attr_typol(self):
        return '.type = YNL_PT_IGNORE, '

    def attr_put(self, ri, var):
        pass

    def attr_get(self, ri, var, first):
        pass

    def attr_policy(self, cw):
        pass

    def setter(self, ri, space, direction, deref=False, ref=None, var=None):
        pass


class TypeScalar(Type):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.byte_order_comment = ''
        if 'byte-order' in attr:
            self.byte_order_comment = f" /* {attr['byte-order']} */"

        # Classic families have some funny enums, don't bother
        # computing checks, since we only need them for kernel policies
        if not family.is_classic():
            self._init_checks()

        # Added by resolve():
        self.is_bitfield = None
        delattr(self, "is_bitfield")
        self.type_name = None
        delattr(self, "type_name")

    def resolve(self):
        self.resolve_up(super())

        if 'enum-as-flags' in self.attr and self.attr['enum-as-flags']:
            self.is_bitfield = True
        elif 'enum' in self.attr:
            self.is_bitfield = self.family.consts[self.attr['enum']]['type'] == 'flags'
        else:
            self.is_bitfield = False

        if not self.is_bitfield and 'enum' in self.attr:
            self.type_name = self.family.consts[self.attr['enum']].user_type
        elif self.is_auto_scalar:
            self.type_name = '__' + self.type[0] + '64'
        else:
            self.type_name = '__' + self.type

    def _init_checks(self):
        if 'enum' in self.attr:
            enum = self.family.consts[self.attr['enum']]
            low, high = enum.value_range()
            if low is None and high is None:
                self.checks['sparse'] = True
            else:
                if 'min' not in self.checks:
                    if low != 0 or self.type[0] == 's':
                        self.checks['min'] = low
                if 'max' not in self.checks:
                    self.checks['max'] = high

        if 'min' in self.checks and 'max' in self.checks:
            if self.get_limit('min') > self.get_limit('max'):
                raise Exception(f'Invalid limit for "{self.name}" min: {self.get_limit("min")} max: {self.get_limit("max")}')
            self.checks['range'] = True

        low = min(self.get_limit('min', 0), self.get_limit('max', 0))
        high = max(self.get_limit('min', 0), self.get_limit('max', 0))
        if low < 0 and self.type[0] == 'u':
            raise Exception(f'Invalid limit for "{self.name}" negative limit for unsigned type')
        if low < -32768 or high > 32767:
            self.checks['full-range'] = True

    # pylint: disable=too-many-return-statements
    def _attr_policy(self, policy):
        if 'flags-mask' in self.checks or self.is_bitfield:
            if self.is_bitfield:
                enum = self.family.consts[self.attr['enum']]
                mask = enum.get_mask(as_flags=True)
            else:
                flags = self.family.consts[self.checks['flags-mask']]
                flag_cnt = len(flags['entries'])
                mask = (1 << flag_cnt) - 1
            return f"NLA_POLICY_MASK({policy}, 0x{mask:x})"
        if 'full-range' in self.checks:
            return f"NLA_POLICY_FULL_RANGE({policy}, &{c_lower(self.enum_name)}_range)"
        if 'range' in self.checks:
            return f"NLA_POLICY_RANGE({policy}, {self.get_limit_str('min')}, {self.get_limit_str('max')})"
        if 'min' in self.checks:
            return f"NLA_POLICY_MIN({policy}, {self.get_limit_str('min')})"
        if 'max' in self.checks:
            return f"NLA_POLICY_MAX({policy}, {self.get_limit_str('max')})"
        if 'sparse' in self.checks:
            return f"NLA_POLICY_VALIDATE_FN({policy}, &{c_lower(self.enum_name)}_validate)"
        return super()._attr_policy(policy)

    def _attr_typol(self):
        return f'.type = YNL_PT_U{c_upper(self.type[1:])}, '

    def arg_member(self, ri):
        return [f'{self.type_name} {self.c_name}{self.byte_order_comment}']

    def attr_put(self, ri, var):
        self._attr_put_simple(ri, var, self.type)

    def _attr_get(self, ri, var):
        return f"{var}->{self.c_name} = ynl_attr_get_{self.type}(attr);", None, None

    def _setter_lines(self, ri, member, presence):
        return [f"{member} = {self.c_name};"]


class TypeFlag(Type):
    def arg_member(self, ri):
        return []

    def _attr_typol(self):
        return '.type = YNL_PT_FLAG, '

    def attr_put(self, ri, var):
        self._attr_put_line(ri, var, f"ynl_attr_put(nlh, {self.enum_name}, NULL, 0)")

    def _attr_get(self, ri, var):
        return [], None, None

    def _setter_lines(self, ri, member, presence):
        return []


class TypeString(Type):
    def arg_member(self, ri):
        return [f"const char *{self.c_name}"]

    def presence_type(self):
        return 'len'

    def struct_member(self, ri):
        ri.cw.p(f"char *{self.c_name};")

    def _attr_typol(self):
        typol = '.type = YNL_PT_NUL_STR, '
        if self.is_selector:
            typol += '.is_selector = 1, '
        return typol

    def _attr_policy(self, policy):
        if 'exact-len' in self.checks:
            mem = 'NLA_POLICY_EXACT_LEN(' + self.get_limit_str('exact-len') + ')'
        else:
            mem = '{ .type = ' + policy
            if 'max-len' in self.checks:
                mem += ', .len = ' + self.get_limit_str('max-len')
            mem += ', }'
        return mem

    def attr_policy(self, cw):
        if self.checks.get('unterminated-ok', False):
            policy = 'NLA_STRING'
        else:
            policy = 'NLA_NUL_STRING'

        spec = self._attr_policy(policy)
        cw.p(f"\t[{self.enum_name}] = {spec},")

    def attr_put(self, ri, var):
        self._attr_put_simple(ri, var, 'str')

    def _attr_get(self, ri, var):
        len_mem = var + '->_len.' + self.c_name
        return [f"{len_mem} = len;",
                f"{var}->{self.c_name} = malloc(len + 1);",
                f"memcpy({var}->{self.c_name}, ynl_attr_get_str(attr), len);",
                f"{var}->{self.c_name}[len] = 0;"], \
               ['len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));'], \
               ['unsigned int len;']

    def _setter_lines(self, ri, member, presence):
        return [f"{presence} = strlen({self.c_name});",
                f"{member} = malloc({presence} + 1);",
                f'memcpy({member}, {self.c_name}, {presence});',
                f'{member}[{presence}] = 0;']


class TypeBinary(Type):
    def arg_member(self, ri):
        return [f"const void *{self.c_name}", 'size_t len']

    def presence_type(self):
        return 'len'

    def struct_member(self, ri):
        ri.cw.p(f"void *{self.c_name};")

    def _attr_typol(self):
        return '.type = YNL_PT_BINARY,'

    def _attr_policy(self, policy):
        if len(self.checks) == 0:
            pass
        elif len(self.checks) == 1:
            check_name = list(self.checks)[0]
            if check_name not in {'exact-len', 'min-len', 'max-len'}:
                raise Exception('Unsupported check for binary type: ' + check_name)
        else:
            raise Exception('More than one check for binary type not implemented, yet')

        if len(self.checks) == 0:
            mem = '{ .type = NLA_BINARY, }'
        elif 'exact-len' in self.checks:
            mem = 'NLA_POLICY_EXACT_LEN(' + self.get_limit_str('exact-len') + ')'
        elif 'min-len' in self.checks:
            mem = 'NLA_POLICY_MIN_LEN(' + self.get_limit_str('min-len') + ')'
        elif 'max-len' in self.checks:
            mem = 'NLA_POLICY_MAX_LEN(' + self.get_limit_str('max-len') + ')'
        else:
            raise Exception('Failed to process policy check for binary type')

        return mem

    def attr_put(self, ri, var):
        self._attr_put_line(ri, var, f"ynl_attr_put(nlh, {self.enum_name}, " +
                            f"{var}->{self.c_name}, {var}->_len.{self.c_name})")

    def _attr_get(self, ri, var):
        len_mem = var + '->_len.' + self.c_name
        return [f"{len_mem} = len;",
                f"{var}->{self.c_name} = malloc(len);",
                f"memcpy({var}->{self.c_name}, ynl_attr_data(attr), len);"], \
               ['len = ynl_attr_data_len(attr);'], \
               ['unsigned int len;']

    def _setter_lines(self, ri, member, presence):
        return [f"{presence} = len;",
                f"{member} = malloc({presence});",
                f'memcpy({member}, {self.c_name}, {presence});']


class TypeBinaryStruct(TypeBinary):
    def struct_member(self, ri):
        ri.cw.p(f'struct {c_lower(self.get("struct"))} *{self.c_name};')

    def _attr_get(self, ri, var):
        struct_sz = 'sizeof(struct ' + c_lower(self.get("struct")) + ')'
        len_mem = var + '->_' + self.presence_type() + '.' + self.c_name
        return [f"{len_mem} = len;",
                f"if (len < {struct_sz})",
                f"{var}->{self.c_name} = calloc(1, {struct_sz});",
                "else",
                f"{var}->{self.c_name} = malloc(len);",
                f"memcpy({var}->{self.c_name}, ynl_attr_data(attr), len);"], \
               ['len = ynl_attr_data_len(attr);'], \
               ['unsigned int len;']


class TypeBinaryScalarArray(TypeBinary):
    def arg_member(self, ri):
        return [f'__{self.get("sub-type")} *{self.c_name}', 'size_t count']

    def presence_type(self):
        return 'count'

    def struct_member(self, ri):
        ri.cw.p(f'__{self.get("sub-type")} *{self.c_name};')

    def attr_put(self, ri, var):
        presence = self.presence_type()
        ri.cw.block_start(line=f"if ({var}->_{presence}.{self.c_name})")
        ri.cw.p(f"i = {var}->_{presence}.{self.c_name} * sizeof(__{self.get('sub-type')});")
        ri.cw.p(f"ynl_attr_put(nlh, {self.enum_name}, " +
                f"{var}->{self.c_name}, i);")
        ri.cw.block_end()

    def _attr_get(self, ri, var):
        len_mem = var + '->_count.' + self.c_name
        return [f"{len_mem} = len / sizeof(__{self.get('sub-type')});",
                f"len = {len_mem} * sizeof(__{self.get('sub-type')});",
                f"{var}->{self.c_name} = malloc(len);",
                f"memcpy({var}->{self.c_name}, ynl_attr_data(attr), len);"], \
               ['len = ynl_attr_data_len(attr);'], \
               ['unsigned int len;']

    def _setter_lines(self, ri, member, presence):
        return [f"{presence} = count;",
                f"count *= sizeof(__{self.get('sub-type')});",
                f"{member} = malloc(count);",
                f'memcpy({member}, {self.c_name}, count);']


class TypeBitfield32(Type):
    def _complex_member_type(self, _ri):
        return "struct nla_bitfield32"

    def _attr_typol(self):
        return '.type = YNL_PT_BITFIELD32, '

    def _attr_policy(self, policy):
        if 'enum' not in self.attr:
            raise Exception('Enum required for bitfield32 attr')
        enum = self.family.consts[self.attr['enum']]
        mask = enum.get_mask(as_flags=True)
        return f"NLA_POLICY_BITFIELD32({mask})"

    def attr_put(self, ri, var):
        line = f"ynl_attr_put(nlh, {self.enum_name}, &{var}->{self.c_name}, sizeof(struct nla_bitfield32))"
        self._attr_put_line(ri, var, line)

    def _attr_get(self, ri, var):
        return f"memcpy(&{var}->{self.c_name}, ynl_attr_data(attr), sizeof(struct nla_bitfield32));", None, None

    def _setter_lines(self, ri, member, presence):
        return [f"memcpy(&{member}, {self.c_name}, sizeof(struct nla_bitfield32));"]


class TypeNest(Type):
    def is_recursive(self):
        return self.family.pure_nested_structs[self.nested_attrs].recursive

    def _complex_member_type(self, _ri):
        return self.nested_struct_type

    def _free_lines(self, ri, var, ref):
        lines = []
        at = '&'
        if self.is_recursive_for_op(ri):
            at = ''
            lines += [f'if ({var}->{ref}{self.c_name})']
        lines += [f'{self.nested_render_name}_free({at}{var}->{ref}{self.c_name});']
        return lines

    def _attr_typol(self):
        return f'.type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, '

    def _attr_policy(self, policy):
        return 'NLA_POLICY_NESTED(' + self.nested_render_name + '_nl_policy)'

    def attr_put(self, ri, var):
        at = '' if self.is_recursive_for_op(ri) else '&'
        self._attr_put_line(ri, var, f"{self.nested_render_name}_put(nlh, " +
                            f"{self.enum_name}, {at}{var}->{self.c_name})")

    def _attr_get(self, ri, var):
        pns = self.family.pure_nested_structs[self.nested_attrs]
        args = ["&parg", "attr"]
        for sel in pns.external_selectors():
            args.append(f'{var}->{sel.name}')
        get_lines = [f"if ({self.nested_render_name}_parse({', '.join(args)}))",
                     "return YNL_PARSE_CB_ERROR;"]
        init_lines = [f"parg.rsp_policy = &{self.nested_render_name}_nest;",
                      f"parg.data = &{var}->{self.c_name};"]
        return get_lines, init_lines, None

    def setter(self, ri, _space, direction, deref=False, ref=None, var="req"):
        ref = (ref if ref else []) + [self.c_name]

        for _, attr in ri.family.pure_nested_structs[self.nested_attrs].member_list():
            if attr.is_recursive():
                continue
            attr.setter(ri, self.nested_attrs, direction, deref=deref, ref=ref,
                        var=var)


class TypeMultiAttr(Type):
    def __init__(self, family, attr_set, attr, value, base_type):
        super().__init__(family, attr_set, attr, value)

        self.base_type = base_type

    def is_multi_val(self):
        return True

    def presence_type(self):
        return 'count'

    def _complex_member_type(self, ri):
        if 'type' not in self.attr or self.attr['type'] == 'nest':
            return self.nested_struct_type
        if self.attr['type'] == 'binary' and 'struct' in self.attr:
            return None  # use arg_member()
        if self.attr['type'] == 'string':
            return 'struct ynl_string *'
        if self.attr['type'] in scalars:
            scalar_pfx = '__' if ri.ku_space == 'user' else ''
            if self.is_auto_scalar:
                name = self.type[0] + '64'
            else:
                name = self.attr['type']
            return scalar_pfx + name
        raise Exception(f"Sub-type {self.attr['type']} not supported yet")

    def arg_member(self, ri):
        if self.type == 'binary' and 'struct' in self.attr:
            return [f'struct {c_lower(self.attr["struct"])} *{self.c_name}',
                    f'unsigned int n_{self.c_name}']
        return super().arg_member(ri)

    def free_needs_iter(self):
        return self.attr['type'] in {'nest', 'string'}

    def _free_lines(self, _ri, var, ref):
        lines = []
        if self.attr['type'] in scalars:
            lines += [f"free({var}->{ref}{self.c_name});"]
        elif self.attr['type'] == 'binary':
            lines += [f"free({var}->{ref}{self.c_name});"]
        elif self.attr['type'] == 'string':
            lines += [
                f"for (i = 0; i < {var}->{ref}_count.{self.c_name}; i++)",
                f"free({var}->{ref}{self.c_name}[i]);",
                f"free({var}->{ref}{self.c_name});",
            ]
        elif 'type' not in self.attr or self.attr['type'] == 'nest':
            lines += [
                f"for (i = 0; i < {var}->{ref}_count.{self.c_name}; i++)",
                f'{self.nested_render_name}_free(&{var}->{ref}{self.c_name}[i]);',
                f"free({var}->{ref}{self.c_name});",
            ]
        else:
            raise Exception(f"Free of MultiAttr sub-type {self.attr['type']} not supported yet")
        return lines

    def _attr_policy(self, policy):
        return self.base_type._attr_policy(policy)

    def _attr_typol(self):
        return self.base_type._attr_typol()

    def _attr_get(self, ri, var):
        return f'n_{self.c_name}++;', None, None

    def attr_put(self, ri, var):
        if self.attr['type'] in scalars:
            put_type = self.type
            ri.cw.p(f"for (i = 0; i < {var}->_count.{self.c_name}; i++)")
            ri.cw.p(f"ynl_attr_put_{put_type}(nlh, {self.enum_name}, {var}->{self.c_name}[i]);")
        elif self.attr['type'] == 'binary' and 'struct' in self.attr:
            ri.cw.p(f"for (i = 0; i < {var}->_count.{self.c_name}; i++)")
            ri.cw.p(f"ynl_attr_put(nlh, {self.enum_name}, &{var}->{self.c_name}[i], sizeof(struct {c_lower(self.attr['struct'])}));")
        elif self.attr['type'] == 'string':
            ri.cw.p(f"for (i = 0; i < {var}->_count.{self.c_name}; i++)")
            ri.cw.p(f"ynl_attr_put_str(nlh, {self.enum_name}, {var}->{self.c_name}[i]->str);")
        elif 'type' not in self.attr or self.attr['type'] == 'nest':
            ri.cw.p(f"for (i = 0; i < {var}->_count.{self.c_name}; i++)")
            self._attr_put_line(ri, var, f"{self.nested_render_name}_put(nlh, " +
                                f"{self.enum_name}, &{var}->{self.c_name}[i])")
        else:
            raise Exception(f"Put of MultiAttr sub-type {self.attr['type']} not supported yet")

    def _setter_lines(self, ri, member, presence):
        return [f"{member} = {self.c_name};",
                f"{presence} = n_{self.c_name};"]


class TypeIndexedArray(Type):
    def is_multi_val(self):
        return True

    def presence_type(self):
        return 'count'

    def _complex_member_type(self, ri):
        if 'sub-type' not in self.attr or self.attr['sub-type'] == 'nest':
            return self.nested_struct_type
        if self.attr['sub-type'] in scalars:
            scalar_pfx = '__' if ri.ku_space == 'user' else ''
            return scalar_pfx + self.attr['sub-type']
        if self.attr['sub-type'] == 'binary' and 'exact-len' in self.checks:
            return None  # use arg_member()
        raise Exception(f"Sub-type {self.attr['sub-type']} not supported yet")

    def arg_member(self, ri):
        if self.sub_type == 'binary' and 'exact-len' in self.checks:
            return [f'unsigned char (*{self.c_name})[{self.checks["exact-len"]}]',
                    f'unsigned int n_{self.c_name}']
        return super().arg_member(ri)

    def _attr_policy(self, policy):
        if self.attr['sub-type'] == 'nest':
            return f'NLA_POLICY_NESTED_ARRAY({self.nested_render_name}_nl_policy)'
        return super()._attr_policy(policy)

    def _attr_typol(self):
        if self.attr['sub-type'] in scalars:
            return f'.type = YNL_PT_U{c_upper(self.sub_type[1:])}, '
        if self.attr['sub-type'] == 'binary' and 'exact-len' in self.checks:
            return f'.type = YNL_PT_BINARY, .len = {self.checks["exact-len"]}, '
        if self.attr['sub-type'] == 'nest':
            return f'.type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, '
        raise Exception(f"Typol for IndexedArray sub-type {self.attr['sub-type']} not supported, yet")

    def _attr_get(self, ri, var):
        local_vars = ['const struct nlattr *attr2;']
        get_lines = [f'attr_{self.c_name} = attr;',
                     'ynl_attr_for_each_nested(attr2, attr) {',
                     '\tif (__ynl_attr_validate(yarg, attr2, type))',
                     '\t\treturn YNL_PARSE_CB_ERROR;',
                     f'\tn_{self.c_name}++;',
                     '}']
        return get_lines, None, local_vars

    def attr_put(self, ri, var):
        ri.cw.p(f'array = ynl_attr_nest_start(nlh, {self.enum_name});')
        if self.sub_type in scalars:
            put_type = self.sub_type
            ri.cw.block_start(line=f'for (i = 0; i < {var}->_count.{self.c_name}; i++)')
            ri.cw.p(f"ynl_attr_put_{put_type}(nlh, i, {var}->{self.c_name}[i]);")
            ri.cw.block_end()
        elif self.sub_type == 'binary' and 'exact-len' in self.checks:
            ri.cw.p(f'for (i = 0; i < {var}->_count.{self.c_name}; i++)')
            ri.cw.p(f"ynl_attr_put(nlh, i, {var}->{self.c_name}[i], {self.checks['exact-len']});")
        elif self.sub_type == 'nest':
            ri.cw.p(f'for (i = 0; i < {var}->_count.{self.c_name}; i++)')
            ri.cw.p(f"{self.nested_render_name}_put(nlh, i, &{var}->{self.c_name}[i]);")
        else:
            raise Exception(f"Put for IndexedArray sub-type {self.attr['sub-type']} not supported, yet")
        ri.cw.p('ynl_attr_nest_end(nlh, array);')

    def _setter_lines(self, ri, member, presence):
        return [f"{member} = {self.c_name};",
                f"{presence} = n_{self.c_name};"]

    def free_needs_iter(self):
        return self.sub_type == 'nest'

    def _free_lines(self, _ri, var, ref):
        lines = []
        if self.sub_type == 'nest':
            lines += [
                f"for (i = 0; i < {var}->{ref}_count.{self.c_name}; i++)",
                f'{self.nested_render_name}_free(&{var}->{ref}{self.c_name}[i]);',
            ]
        lines += (f"free({var}->{ref}{self.c_name});",)
        return lines

class TypeNestTypeValue(Type):
    def _complex_member_type(self, _ri):
        return self.nested_struct_type

    def _attr_typol(self):
        return f'.type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, '

    def _attr_get(self, ri, var):
        prev = 'attr'
        tv_args = ''
        get_lines = []
        local_vars = []
        init_lines = [f"parg.rsp_policy = &{self.nested_render_name}_nest;",
                      f"parg.data = &{var}->{self.c_name};"]
        if 'type-value' in self.attr:
            tv_names = [c_lower(x) for x in self.attr["type-value"]]
            local_vars += [f'const struct nlattr *attr_{", *attr_".join(tv_names)};']
            local_vars += [f'__u32 {", ".join(tv_names)};']
            for level in self.attr["type-value"]:
                level = c_lower(level)
                get_lines += [f'attr_{level} = ynl_attr_data({prev});']
                get_lines += [f'{level} = ynl_attr_type(attr_{level});']
                prev = 'attr_' + level

            tv_args = f", {', '.join(tv_names)}"

        get_lines += [f"{self.nested_render_name}_parse(&parg, {prev}{tv_args});"]
        return get_lines, init_lines, local_vars


class TypeSubMessage(TypeNest):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.selector = Selector(attr, attr_set)

    def _attr_typol(self):
        typol = f'.type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, '
        typol += '.is_submsg = 1, '
        # Reverse-parsing of the policy (ynl_err_walk() in ynl.c) does not
        # support external selectors. No family uses sub-messages with external
        # selector for requests so this is fine for now.
        if not self.selector.is_external():
            typol += f'.selector_type = {self.attr_set[self["selector"]].value} '
        return typol

    def _attr_get(self, ri, var):
        selector = self['selector']
        sel = c_lower(selector)
        if self.selector.is_external():
            sel_var = f"_sel_{sel}"
        else:
            sel_var = f"{var}->{sel}"
        get_lines = [f'if (!{sel_var})',
                     f'return ynl_submsg_failed(yarg, "{self.name}", "{selector}");',
                     f"if ({self.nested_render_name}_parse(&parg, {sel_var}, attr))",
                     "return YNL_PARSE_CB_ERROR;"]
        init_lines = [f"parg.rsp_policy = &{self.nested_render_name}_nest;",
                      f"parg.data = &{var}->{self.c_name};"]
        return get_lines, init_lines, None


class Selector:
    def __init__(self, msg_attr, attr_set):
        self.name = msg_attr["selector"]

        if self.name in attr_set:
            self.attr = attr_set[self.name]
            self.attr.is_selector = True
            self._external = False
        else:
            # The selector will need to get passed down thru the structs
            self.attr = None
            self._external = True

    def set_attr(self, attr):
        self.attr = attr

    def is_external(self):
        return self._external


class Struct:
    def __init__(self, family, space_name, type_list=None, fixed_header=None,
                 inherited=None, submsg=None):
        self.family = family
        self.space_name = space_name
        self.attr_set = family.attr_sets[space_name]
        # Use list to catch comparisons with empty sets
        self._inherited = inherited if inherited is not None else []
        self.inherited = []
        self.fixed_header = None
        if fixed_header:
            self.fixed_header = 'struct ' + c_lower(fixed_header)
        self.submsg = submsg

        self.nested = type_list is None
        if family.name == c_lower(space_name):
            self.render_name = c_lower(family.ident_name)
        else:
            self.render_name = c_lower(family.ident_name + '-' + space_name)
        self.struct_name = 'struct ' + self.render_name
        if self.nested and space_name in family.consts:
            self.struct_name += '_'
        self.ptr_name = self.struct_name + ' *'
        # All attr sets this one contains, directly or multiple levels down
        self.child_nests = set()

        self.request = False
        self.reply = False
        self.recursive = False
        self.in_multi_val = False  # used by a MultiAttr or and legacy arrays

        self.attr_list = []
        self.attrs = {}
        if type_list is not None:
            for t in type_list:
                self.attr_list.append((t, self.attr_set[t]),)
        else:
            for t in self.attr_set:
                self.attr_list.append((t, self.attr_set[t]),)

        max_val = 0
        self.attr_max_val = None
        for name, attr in self.attr_list:
            if attr.value >= max_val:
                max_val = attr.value
                self.attr_max_val = attr
            self.attrs[name] = attr

    def __iter__(self):
        yield from self.attrs

    def __getitem__(self, key):
        return self.attrs[key]

    def member_list(self):
        return self.attr_list

    def set_inherited(self, new_inherited):
        if self._inherited != new_inherited:
            raise Exception("Inheriting different members not supported")
        self.inherited = [c_lower(x) for x in sorted(self._inherited)]

    def external_selectors(self):
        sels = []
        for _name, attr in self.attr_list:
            if isinstance(attr, TypeSubMessage) and attr.selector.is_external():
                sels.append(attr.selector)
        return sels

    def free_needs_iter(self):
        for _, attr in self.attr_list:
            if attr.free_needs_iter():
                return True
        return False


class EnumEntry(SpecEnumEntry):
    def __init__(self, enum_set, yaml, prev, value_start):
        super().__init__(enum_set, yaml, prev, value_start)

        if prev:
            self.value_change = self.value != prev.value + 1
        else:
            self.value_change = self.value != 0
        self.value_change = self.value_change or self.enum_set['type'] == 'flags'

        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")

    def resolve(self):
        self.resolve_up(super())

        self.c_name = c_upper(self.enum_set.value_pfx + self.name)


class EnumSet(SpecEnumSet):
    def __init__(self, family, yaml):
        self.render_name = c_lower(family.ident_name + '-' + yaml['name'])

        if 'enum-name' in yaml:
            if yaml['enum-name']:
                self.enum_name = 'enum ' + c_lower(yaml['enum-name'])
                self.user_type = self.enum_name
            else:
                self.enum_name = None
        else:
            self.enum_name = 'enum ' + self.render_name

        if self.enum_name:
            self.user_type = self.enum_name
        else:
            self.user_type = 'int'

        self.value_pfx = yaml.get('name-prefix', f"{family.ident_name}-{yaml['name']}-")
        self.header = yaml.get('header', None)
        self.enum_cnt_name = yaml.get('enum-cnt-name', None)

        super().__init__(family, yaml)

    def new_entry(self, entry, prev_entry, value_start):
        return EnumEntry(self, entry, prev_entry, value_start)

    def value_range(self):
        low = min(x.value for x in self.entries.values())
        high = max(x.value for x in self.entries.values())

        if high - low + 1 != len(self.entries):
            return None, None

        return low, high


class AttrSet(SpecAttrSet):
    def __init__(self, family, yaml):
        super().__init__(family, yaml)

        if self.subset_of is None:
            if 'name-prefix' in yaml:
                pfx = yaml['name-prefix']
            elif self.name == family.name:
                pfx = family.ident_name + '-a-'
            else:
                pfx = f"{family.ident_name}-a-{self.name}-"
            self.name_prefix = c_upper(pfx)
            self.max_name = c_upper(self.yaml.get('attr-max-name', f"{self.name_prefix}max"))
            self.cnt_name = c_upper(self.yaml.get('attr-cnt-name', f"__{self.name_prefix}max"))
        else:
            self.name_prefix = family.attr_sets[self.subset_of].name_prefix
            self.max_name = family.attr_sets[self.subset_of].max_name
            self.cnt_name = family.attr_sets[self.subset_of].cnt_name

        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")

    def resolve(self):
        self.c_name = c_lower(self.name)
        if self.c_name in _C_KW:
            self.c_name += '_'
        if self.c_name == self.family.c_name:
            self.c_name = ''

    def new_attr(self, elem, value):
        if elem['type'] in scalars:
            t = TypeScalar(self.family, self, elem, value)
        elif elem['type'] == 'unused':
            t = TypeUnused(self.family, self, elem, value)
        elif elem['type'] == 'pad':
            t = TypePad(self.family, self, elem, value)
        elif elem['type'] == 'flag':
            t = TypeFlag(self.family, self, elem, value)
        elif elem['type'] == 'string':
            t = TypeString(self.family, self, elem, value)
        elif elem['type'] == 'binary':
            if 'struct' in elem:
                t = TypeBinaryStruct(self.family, self, elem, value)
            elif elem.get('sub-type') in scalars:
                t = TypeBinaryScalarArray(self.family, self, elem, value)
            else:
                t = TypeBinary(self.family, self, elem, value)
        elif elem['type'] == 'bitfield32':
            t = TypeBitfield32(self.family, self, elem, value)
        elif elem['type'] == 'nest':
            t = TypeNest(self.family, self, elem, value)
        elif elem['type'] == 'indexed-array' and 'sub-type' in elem:
            if elem["sub-type"] in ['binary', 'nest', 'u32']:
                t = TypeIndexedArray(self.family, self, elem, value)
            else:
                raise Exception(f'new_attr: unsupported sub-type {elem["sub-type"]}')
        elif elem['type'] == 'nest-type-value':
            t = TypeNestTypeValue(self.family, self, elem, value)
        elif elem['type'] == 'sub-message':
            t = TypeSubMessage(self.family, self, elem, value)
        else:
            raise Exception(f"No typed class for type {elem['type']}")

        if 'multi-attr' in elem and elem['multi-attr']:
            t = TypeMultiAttr(self.family, self, elem, value, t)

        return t


class Operation(SpecOperation):
    def __init__(self, family, yaml, req_value, rsp_value):
        # Fill in missing operation properties (for fixed hdr-only msgs)
        for mode in ['do', 'dump', 'event']:
            for direction in ['request', 'reply']:
                try:
                    yaml[mode][direction].setdefault('attributes', [])
                except KeyError:
                    pass

        super().__init__(family, yaml, req_value, rsp_value)

        self.render_name = c_lower(family.ident_name + '_' + self.name)

        self.dual_policy = ('do' in yaml and 'request' in yaml['do']) and \
                         ('dump' in yaml and 'request' in yaml['dump'])

        self.has_ntf = False

        # Added by resolve:
        self.enum_name = None
        delattr(self, "enum_name")

    def resolve(self):
        self.resolve_up(super())

        if not self.is_async:
            self.enum_name = self.family.op_prefix + c_upper(self.name)
        else:
            self.enum_name = self.family.async_op_prefix + c_upper(self.name)

    def mark_has_ntf(self):
        self.has_ntf = True


class SubMessage(SpecSubMessage):
    def __init__(self, family, yaml):
        super().__init__(family, yaml)

        self.render_name = c_lower(family.ident_name + '-' + yaml['name'])

    def resolve(self):
        self.resolve_up(super())


class Family(SpecFamily):
    def __init__(self, file_name, exclude_ops, fn_prefix):
        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")
        self.op_prefix = None
        delattr(self, "op_prefix")
        self.async_op_prefix = None
        delattr(self, "async_op_prefix")
        self.mcgrps = None
        delattr(self, "mcgrps")
        self.consts = None
        delattr(self, "consts")
        self.hooks = None
        delattr(self, "hooks")

        self.root_sets = {}
        self.pure_nested_structs = {}
        self.kernel_policy = None
        self.global_policy = None
        self.global_policy_set = None

        super().__init__(file_name, exclude_ops=exclude_ops)

        self.fam_key = c_upper(self.yaml.get('c-family-name', self.yaml["name"] + '_FAMILY_NAME'))
        self.ver_key = c_upper(self.yaml.get('c-version-name', self.yaml["name"] + '_FAMILY_VERSION'))

        if 'definitions' not in self.yaml:
            self.yaml['definitions'] = []

        if 'uapi-header' in self.yaml:
            self.uapi_header = self.yaml['uapi-header']
        else:
            self.uapi_header = f"linux/{self.ident_name}.h"
        if self.uapi_header.startswith("linux/") and self.uapi_header.endswith('.h'):
            self.uapi_header_name = self.uapi_header[6:-2]
        else:
            self.uapi_header_name = self.ident_name

        self.fn_prefix = fn_prefix if fn_prefix else f'{self.ident_name}-nl'

    def resolve(self):
        self.resolve_up(super())

        self.c_name = c_lower(self.ident_name)
        if 'name-prefix' in self.yaml['operations']:
            self.op_prefix = c_upper(self.yaml['operations']['name-prefix'])
        else:
            self.op_prefix = c_upper(self.yaml['name'] + '-cmd-')
        if 'async-prefix' in self.yaml['operations']:
            self.async_op_prefix = c_upper(self.yaml['operations']['async-prefix'])
        else:
            self.async_op_prefix = self.op_prefix

        self.mcgrps = self.yaml.get('mcast-groups', {'list': []})

        self.hooks = {}
        for when in ['pre', 'post']:
            self.hooks[when] = {}
            for op_mode in ['do', 'dump']:
                self.hooks[when][op_mode] = {}
                self.hooks[when][op_mode]['set'] = set()
                self.hooks[when][op_mode]['list'] = []

        # dict space-name -> 'request': set(attrs), 'reply': set(attrs)
        self.root_sets = {}
        # dict space-name -> Struct
        self.pure_nested_structs = {}

        self._mark_notify()
        self._mock_up_events()

        self._load_root_sets()
        self._load_nested_sets()
        self._load_attr_use()
        self._load_selector_passing()
        self._load_hooks()

        self.kernel_policy = self.yaml.get('kernel-policy', 'split')
        if self.kernel_policy == 'global':
            self._load_global_policy()

    def new_enum(self, elem):
        return EnumSet(self, elem)

    def new_attr_set(self, elem):
        return AttrSet(self, elem)

    def new_operation(self, elem, req_value, rsp_value):
        return Operation(self, elem, req_value, rsp_value)

    def new_sub_message(self, elem):
        return SubMessage(self, elem)

    def is_classic(self):
        return self.proto == 'netlink-raw'

    def _mark_notify(self):
        for op in self.msgs.values():
            if 'notify' in op:
                self.ops[op['notify']].mark_has_ntf()

    # Fake a 'do' equivalent of all events, so that we can render their response parsing
    def _mock_up_events(self):
        for op in self.yaml['operations']['list']:
            if 'event' in op:
                op['do'] = {
                    'reply': {
                        'attributes': op['event']['attributes']
                    }
                }

    def _load_root_sets(self):
        for _op_name, op in self.msgs.items():
            if 'attribute-set' not in op:
                continue

            req_attrs = set()
            rsp_attrs = set()
            for op_mode in ['do', 'dump']:
                if op_mode in op and 'request' in op[op_mode]:
                    req_attrs.update(set(op[op_mode]['request']['attributes']))
                if op_mode in op and 'reply' in op[op_mode]:
                    rsp_attrs.update(set(op[op_mode]['reply']['attributes']))
            if 'event' in op:
                rsp_attrs.update(set(op['event']['attributes']))

            if op['attribute-set'] not in self.root_sets:
                self.root_sets[op['attribute-set']] = {'request': req_attrs, 'reply': rsp_attrs}
            else:
                self.root_sets[op['attribute-set']]['request'].update(req_attrs)
                self.root_sets[op['attribute-set']]['reply'].update(rsp_attrs)

    def _sort_pure_types(self):
        # Try to reorder according to dependencies
        pns_key_list = list(self.pure_nested_structs.keys())
        pns_key_seen = set()
        rounds = len(pns_key_list) ** 2  # it's basically bubble sort
        for _ in range(rounds):
            if len(pns_key_list) == 0:
                break
            name = pns_key_list.pop(0)
            finished = True
            for _, spec in self.attr_sets[name].items():
                if 'nested-attributes' in spec:
                    nested = spec['nested-attributes']
                elif 'sub-message' in spec:
                    nested = spec.sub_message
                else:
                    continue

                # If the unknown nest we hit is recursive it's fine, it'll be a pointer
                if self.pure_nested_structs[nested].recursive:
                    continue
                if nested not in pns_key_seen:
                    # Dicts are sorted, this will make struct last
                    struct = self.pure_nested_structs.pop(name)
                    self.pure_nested_structs[name] = struct
                    finished = False
                    break
            if finished:
                pns_key_seen.add(name)
            else:
                pns_key_list.append(name)

    def _load_nested_set_nest(self, spec):
        inherit = set()
        nested = spec['nested-attributes']
        if nested not in self.root_sets:
            if nested not in self.pure_nested_structs:
                self.pure_nested_structs[nested] = \
                    Struct(self, nested, inherited=inherit,
                           fixed_header=spec.get('fixed-header'))
        else:
            raise Exception(f'Using attr set as root and nested not supported - {nested}')

        if 'type-value' in spec:
            if nested in self.root_sets:
                raise Exception("Inheriting members to a space used as root not supported")
            inherit.update(set(spec['type-value']))
        elif spec['type'] == 'indexed-array':
            inherit.add('idx')
        self.pure_nested_structs[nested].set_inherited(inherit)

        return nested

    def _load_nested_set_submsg(self, spec):
        # Fake the struct type for the sub-message itself
        # its not a attr_set but codegen wants attr_sets.
        submsg = self.sub_msgs[spec["sub-message"]]
        nested = submsg.name

        attrs = []
        for name, fmt in submsg.formats.items():
            attr = {
                "name": name,
                "parent-sub-message": spec,
            }
            if 'attribute-set' in fmt:
                attr |= {
                    "type": "nest",
                    "nested-attributes": fmt['attribute-set'],
                }
                if 'fixed-header' in fmt:
                    attr |= { "fixed-header": fmt["fixed-header"] }
            elif 'fixed-header' in fmt:
                attr |= {
                    "type": "binary",
                    "struct": fmt["fixed-header"],
                }
            else:
                attr["type"] = "flag"
            attrs.append(attr)

        self.attr_sets[nested] = AttrSet(self, {
            "name": nested,
            "name-pfx": self.name + '-' + spec.name + '-',
            "attributes": attrs
        })

        if nested not in self.pure_nested_structs:
            self.pure_nested_structs[nested] = Struct(self, nested, submsg=submsg)

        return nested

    def _load_nested_sets(self):
        attr_set_queue = list(self.root_sets.keys())
        attr_set_seen = set(self.root_sets.keys())

        while attr_set_queue:
            a_set = attr_set_queue.pop(0)
            for attr, spec in self.attr_sets[a_set].items():
                if 'nested-attributes' in spec:
                    nested = self._load_nested_set_nest(spec)
                elif 'sub-message' in spec:
                    nested = self._load_nested_set_submsg(spec)
                else:
                    continue

                if nested not in attr_set_seen:
                    attr_set_queue.append(nested)
                    attr_set_seen.add(nested)

        for root_set, rs_members in self.root_sets.items():
            for attr, spec in self.attr_sets[root_set].items():
                if 'nested-attributes' in spec:
                    nested = spec['nested-attributes']
                elif 'sub-message' in spec:
                    nested = spec.sub_message
                else:
                    nested = None

                if nested:
                    if attr in rs_members['request']:
                        self.pure_nested_structs[nested].request = True
                    if attr in rs_members['reply']:
                        self.pure_nested_structs[nested].reply = True

                    if spec.is_multi_val():
                        child = self.pure_nested_structs.get(nested)
                        child.in_multi_val = True

        self._sort_pure_types()

        # Propagate the request / reply / recursive
        for attr_set, struct in reversed(self.pure_nested_structs.items()):
            for _, spec in self.attr_sets[attr_set].items():
                if attr_set in struct.child_nests:
                    struct.recursive = True

                if 'nested-attributes' in spec:
                    child_name = spec['nested-attributes']
                elif 'sub-message' in spec:
                    child_name = spec.sub_message
                else:
                    continue

                struct.child_nests.add(child_name)
                child = self.pure_nested_structs.get(child_name)
                if child:
                    if not child.recursive:
                        struct.child_nests.update(child.child_nests)
                    child.request |= struct.request
                    child.reply |= struct.reply
                    if spec.is_multi_val():
                        child.in_multi_val = True

        self._sort_pure_types()

    def _load_attr_use(self):
        for _, struct in self.pure_nested_structs.items():
            if struct.request:
                for _, arg in struct.member_list():
                    arg.set_request()
            if struct.reply:
                for _, arg in struct.member_list():
                    arg.set_reply()

        for root_set, rs_members in self.root_sets.items():
            for attr, spec in self.attr_sets[root_set].items():
                if attr in rs_members['request']:
                    spec.set_request()
                if attr in rs_members['reply']:
                    spec.set_reply()

    def _load_selector_passing(self):
        def all_structs():
            for k, v in reversed(self.pure_nested_structs.items()):
                yield k, v
            for k, _ in self.root_sets.items():
                yield k, None  # we don't have a struct, but it must be terminal

        for attr_set, _struct in all_structs():
            for _, spec in self.attr_sets[attr_set].items():
                if 'nested-attributes' in spec:
                    child_name = spec['nested-attributes']
                elif 'sub-message' in spec:
                    child_name = spec.sub_message
                else:
                    continue

                child = self.pure_nested_structs.get(child_name)
                for selector in child.external_selectors():
                    if selector.name in self.attr_sets[attr_set]:
                        sel_attr = self.attr_sets[attr_set][selector.name]
                        selector.set_attr(sel_attr)
                    else:
                        raise Exception("Passing selector thru more than one layer not supported")

    def _load_global_policy(self):
        global_set = set()
        attr_set_name = None
        for _op_name, op in self.ops.items():
            if not op:
                continue
            if 'attribute-set' not in op:
                continue

            if attr_set_name is None:
                attr_set_name = op['attribute-set']
            if attr_set_name != op['attribute-set']:
                raise Exception('For a global policy all ops must use the same set')

            for op_mode in ['do', 'dump']:
                if op_mode in op:
                    req = op[op_mode].get('request')
                    if req:
                        global_set.update(req.get('attributes', []))

        self.global_policy = []
        self.global_policy_set = attr_set_name
        for attr in self.attr_sets[attr_set_name]:
            if attr in global_set:
                self.global_policy.append(attr)

    def _load_hooks(self):
        for op in self.ops.values():
            for op_mode in ['do', 'dump']:
                if op_mode not in op:
                    continue
                for when in ['pre', 'post']:
                    if when not in op[op_mode]:
                        continue
                    name = op[op_mode][when]
                    if name in self.hooks[when][op_mode]['set']:
                        continue
                    self.hooks[when][op_mode]['set'].add(name)
                    self.hooks[when][op_mode]['list'].append(name)


class RenderInfo:
    def __init__(self, cw, family, ku_space, op, op_mode, attr_set=None):
        self.family = family
        self.nl = cw.nlib
        self.ku_space = ku_space
        self.op_mode = op_mode
        self.op = op

        fixed_hdr = op.fixed_header if op else None
        self.fixed_hdr_len = 'ys->family->hdr_len'
        if op and op.fixed_header:
            if op.fixed_header != family.fixed_header:
                if family.is_classic():
                    self.fixed_hdr_len = f"sizeof(struct {c_lower(fixed_hdr)})"
                else:
                    raise Exception("Per-op fixed header not supported, yet")


        # 'do' and 'dump' response parsing is identical
        self.type_consistent = True
        self.type_oneside = False
        if op_mode != 'do' and 'dump' in op:
            if 'do' in op:
                if ('reply' in op['do']) != ('reply' in op["dump"]):
                    self.type_consistent = False
                elif 'reply' in op['do'] and op["do"]["reply"] != op["dump"]["reply"]:
                    self.type_consistent = False
            else:
                self.type_consistent = True
                self.type_oneside = True

        self.attr_set = attr_set
        if not self.attr_set:
            self.attr_set = op['attribute-set']

        self.type_name_conflict = False
        if op:
            self.type_name = c_lower(op.name)
        else:
            self.type_name = c_lower(attr_set)
            if attr_set in family.consts:
                self.type_name_conflict = True

        self.cw = cw

        self.struct = {}
        if op_mode == 'notify':
            op_mode = 'do' if 'do' in op else 'dump'
        for op_dir in ['request', 'reply']:
            if op:
                type_list = []
                if op_dir in op[op_mode]:
                    type_list = op[op_mode][op_dir]['attributes']
                self.struct[op_dir] = Struct(family, self.attr_set,
                                             fixed_header=fixed_hdr,
                                             type_list=type_list)
        if op_mode == 'event':
            self.struct['reply'] = Struct(family, self.attr_set,
                                          fixed_header=fixed_hdr,
                                          type_list=op['event']['attributes'])

    def type_empty(self, key):
        return len(self.struct[key].attr_list) == 0 and \
            self.struct['request'].fixed_header is None

    def needs_nlflags(self, direction):
        return self.op_mode == 'do' and direction == 'request' and self.family.is_classic()
