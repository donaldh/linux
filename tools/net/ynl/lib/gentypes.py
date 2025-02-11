# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

from lib import SpecAttr, SpecAttrSet, SpecEnumEntry, SpecEnumSet, SpecFamily, \
    SpecOperation, c_upper, c_lower


scalars = {'u8', 'u16', 'u32', 'u64', 's32', 's64'}

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


class BaseNlLib:
    def get_family_id(self):
        return 'ys->family_id'

    def parse_cb_run(self, cb, data, is_dump=False, indent=1):
        ind = '\n\t\t' + '\t' * indent + ' '
        if is_dump:
            return f"mnl_cb_run2(ys->rx_buf, len, 0, 0, {cb}, {data},{ind}ynl_cb_array, NLMSG_MIN_TYPE)"
        else:
            return f"mnl_cb_run2(ys->rx_buf, len, ys->seq, ys->portid,{ind}{cb}, {data},{ind}" + \
                   "ynl_cb_array, NLMSG_MIN_TYPE)"


class Type(SpecAttr):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.attr = attr
        self.attr_set = attr_set
        self.type = attr['type']
        self.checks = attr.get('checks', {})

        if 'len' in attr:
            self.len = attr['len']
        if 'nested-attributes' in attr:
            self.nested_attrs = attr['nested-attributes']
            if self.nested_attrs == family.name:
                self.nested_render_name = f"{family.name}"
            else:
                self.nested_render_name = f"{family.name}_{c_lower(self.nested_attrs)}"

            if self.nested_attrs in self.family.consts:
                self.nested_struct_type = 'struct ' + self.nested_render_name + '_'
            else:
                self.nested_struct_type = 'struct ' + self.nested_render_name

        self.c_name = c_lower(self.name)
        if self.c_name in _C_KW:
            self.c_name += '_'

        # Added by resolve():
        self.enum_name = None
        delattr(self, "enum_name")

    def resolve(self):
        if 'name-prefix' in self.attr:
            enum_name = f"{self.attr['name-prefix']}{self.name}"
        else:
            enum_name = f"{self.attr_set.name_prefix}{self.name}"
        self.enum_name = c_upper(enum_name)

    def is_multi_val(self):
        return None

    def is_scalar(self):
        return self.type in {'u8', 'u16', 'u32', 'u64', 's32', 's64'}

    def presence_type(self):
        return 'bit'

    def presence_member(self, space, type_filter):
        if self.presence_type() != type_filter:
            return

        if self.presence_type() == 'bit':
            pfx = '__' if space == 'user' else ''
            return f"{pfx}u32 {self.c_name}:1;"

        if self.presence_type() == 'len':
            pfx = '__' if space == 'user' else ''
            return f"{pfx}u32 {self.c_name}_len;"

    def _complex_member_type(self, ri):
        return None

    def free_needs_iter(self):
        return False

    def free(self, ri, var, ref):
        if self.is_multi_val() or self.presence_type() == 'len':
            ri.cw.p(f'free({var}->{ref}{self.c_name});')

    def arg_member(self, ri):
        member = self._complex_member_type(ri)
        if member:
            arg = [member + ' *' + self.c_name]
            if self.presence_type() == 'count':
                arg += ['unsigned int n_' + self.c_name]
            return arg
        raise Exception(f"Struct member not implemented for class type {self.type}")

    def struct_member(self, ri):
        if self.is_multi_val():
            ri.cw.p(f"unsigned int n_{self.c_name};")
        member = self._complex_member_type(ri)
        if member:
            ptr = '*' if self.is_multi_val() else ''
            ri.cw.p(f"{member} {ptr}{self.c_name};")
            return
        members = self.arg_member(ri)
        for one in members:
            ri.cw.p(one + ';')

    def _attr_policy(self, policy):
        return '{ .type = ' + policy + ', }'

    def attr_policy(self, cw):
        policy = c_upper('nla-' + self.attr['type'])

        spec = self._attr_policy(policy)
        cw.p(f"\t[{self.enum_name}] = {spec},")

    def _attr_typol(self):
        raise Exception(f"Type policy not implemented for class type {self.type}")

    def attr_typol(self, cw):
        typol = self._attr_typol()
        cw.p(f'[{self.enum_name}] = {"{"} .name = "{self.name}", {typol}{"}"},')

    def _attr_put_line(self, ri, var, line):
        if self.presence_type() == 'bit':
            ri.cw.p(f"if ({var}->_present.{self.c_name})")
        elif self.presence_type() == 'len':
            ri.cw.p(f"if ({var}->_present.{self.c_name}_len)")
        ri.cw.p(f"{line};")

    def _attr_put_simple(self, ri, var, put_type):
        line = f"mnl_attr_put_{put_type}(nlh, {self.enum_name}, {var}->{self.c_name})"
        self._attr_put_line(ri, var, line)

    def attr_put(self, ri, var):
        raise Exception(f"Put not implemented for class type {self.type}")

    def _attr_get(self, ri, var):
        raise Exception(f"Attr get not implemented for class type {self.type}")

    def attr_get(self, ri, var, first):
        lines, init_lines, local_vars = self._attr_get(ri, var)
        if type(lines) is str:
            lines = [lines]
        if type(init_lines) is str:
            init_lines = [init_lines]

        kw = 'if' if first else 'else if'
        ri.cw.block_start(line=f"{kw} (type == {self.enum_name})")
        if local_vars:
            for local in local_vars:
                ri.cw.p(local)
            ri.cw.nl()

        if not self.is_multi_val():
            ri.cw.p("if (ynl_attr_validate(yarg, attr))")
            ri.cw.p("return MNL_CB_ERROR;")
            if self.presence_type() == 'bit':
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

    def setter(self, ri, space, direction, deref=False, ref=None):
        ref = (ref if ref else []) + [self.c_name]
        var = "req"
        member = f"{var}->{'.'.join(ref)}"

        code = []
        presence = ''
        for i in range(0, len(ref)):
            presence = f"{var}->{'.'.join(ref[:i] + [''])}_present.{ref[i]}"
            if self.presence_type() == 'bit':
                code.append(presence + ' = 1;')
        code += self._setter_lines(ri, member, presence)

        func_name = f"{op_prefix(ri, direction, deref=deref)}_set_{'_'.join(ref)}"
        free = bool([x for x in code if 'free(' in x])
        alloc = bool([x for x in code if 'alloc(' in x])
        if free and not alloc:
            func_name = '__' + func_name
        ri.cw.write_func('static inline void', func_name, body=code,
                         args=[f'{type_name(ri, direction, deref=deref)} *{var}'] + self.arg_member(ri))


class TypeUnused(Type):
    def presence_type(self):
        return ''

    def arg_member(self, ri):
        return []

    def _attr_get(self, ri, var):
        return ['return MNL_CB_ERROR;'], None, None

    def _attr_typol(self):
        return '.type = YNL_PT_REJECT, '

    def attr_policy(self, cw):
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

    def setter(self, ri, space, direction, deref=False, ref=None):
        pass


class TypeScalar(Type):
    def __init__(self, family, attr_set, attr, value):
        super().__init__(family, attr_set, attr, value)

        self.byte_order_comment = ''
        if 'byte-order' in attr:
            self.byte_order_comment = f" /* {attr['byte-order']} */"

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

        maybe_enum = not self.is_bitfield and 'enum' in self.attr
        if maybe_enum and self.family.consts[self.attr['enum']].enum_name:
            self.type_name = f"enum {self.family.name}_{c_lower(self.attr['enum'])}"
        else:
            self.type_name = '__' + self.type

    def _mnl_type(self):
        t = self.type
        # mnl does not have a helper for signed types
        if t[0] == 's':
            t = 'u' + t[1:]
        return t

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
        elif 'min' in self.checks:
            return f"NLA_POLICY_MIN({policy}, {self.checks['min']})"
        elif 'enum' in self.attr:
            enum = self.family.consts[self.attr['enum']]
            low, high = enum.value_range()
            if low == 0:
                return f"NLA_POLICY_MAX({policy}, {high})"
            return f"NLA_POLICY_RANGE({policy}, {low}, {high})"
        return super()._attr_policy(policy)

    def _attr_typol(self):
        return f'.type = YNL_PT_U{self.type[1:]}, '

    def arg_member(self, ri):
        return [f'{self.type_name} {self.c_name}{self.byte_order_comment}']

    def attr_put(self, ri, var):
        self._attr_put_simple(ri, var, self._mnl_type())

    def _attr_get(self, ri, var):
        return f"{var}->{self.c_name} = mnl_attr_get_{self._mnl_type()}(attr);", None, None

    def _setter_lines(self, ri, member, presence):
        return [f"{member} = {self.c_name};"]


class TypeFlag(Type):
    def arg_member(self, ri):
        return []

    def _attr_typol(self):
        return '.type = YNL_PT_FLAG, '

    def attr_put(self, ri, var):
        self._attr_put_line(ri, var, f"mnl_attr_put(nlh, {self.enum_name}, 0, NULL)")

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
        return f'.type = YNL_PT_NUL_STR, '

    def _attr_policy(self, policy):
        mem = '{ .type = ' + policy
        if 'max-len' in self.checks:
            mem += ', .len = ' + str(self.checks['max-len'])
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
        self._attr_put_simple(ri, var, 'strz')

    def _attr_get(self, ri, var):
        len_mem = var + '->_present.' + self.c_name + '_len'
        return [f"{len_mem} = len;",
                f"{var}->{self.c_name} = malloc(len + 1);",
                f"memcpy({var}->{self.c_name}, mnl_attr_get_str(attr), len);",
                f"{var}->{self.c_name}[len] = 0;"], \
               ['len = strnlen(mnl_attr_get_str(attr), mnl_attr_get_payload_len(attr));'], \
               ['unsigned int len;']

    def _setter_lines(self, ri, member, presence):
        return [f"free({member});",
                f"{presence}_len = strlen({self.c_name});",
                f"{member} = malloc({presence}_len + 1);",
                f'memcpy({member}, {self.c_name}, {presence}_len);',
                f'{member}[{presence}_len] = 0;']


class TypeBinary(Type):
    def arg_member(self, ri):
        return [f"const void *{self.c_name}", 'size_t len']

    def presence_type(self):
        return 'len'

    def struct_member(self, ri):
        ri.cw.p(f"void *{self.c_name};")

    def _attr_typol(self):
        return f'.type = YNL_PT_BINARY,'

    def _attr_policy(self, policy):
        mem = '{ '
        if len(self.checks) == 1 and 'min-len' in self.checks:
            mem += '.len = ' + str(self.checks['min-len'])
        elif len(self.checks) == 0:
            mem += '.type = NLA_BINARY'
        else:
            raise Exception('One or more of binary type checks not implemented, yet')
        mem += ', }'
        return mem

    def attr_put(self, ri, var):
        self._attr_put_line(ri, var, f"mnl_attr_put(nlh, {self.enum_name}, " +
                            f"{var}->_present.{self.c_name}_len, {var}->{self.c_name})")

    def _attr_get(self, ri, var):
        len_mem = var + '->_present.' + self.c_name + '_len'
        return [f"{len_mem} = len;",
                f"{var}->{self.c_name} = malloc(len);",
                f"memcpy({var}->{self.c_name}, mnl_attr_get_payload(attr), len);"], \
               ['len = mnl_attr_get_payload_len(attr);'], \
               ['unsigned int len;']

    def _setter_lines(self, ri, member, presence):
        return [f"free({member});",
                f"{member} = malloc({presence}_len);",
                f'memcpy({member}, {self.c_name}, {presence}_len);']


class TypeBitfield32(Type):
    def _complex_member_type(self, ri):
        return "struct nla_bitfield32"

    def _attr_typol(self):
        return f'.type = YNL_PT_BITFIELD32, '

    def _attr_policy(self, policy):
        if not 'enum' in self.attr:
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
    def _complex_member_type(self, ri):
        return self.nested_struct_type

    def free(self, ri, var, ref):
        ri.cw.p(f'{self.nested_render_name}_free(&{var}->{ref}{self.c_name});')

    def _attr_typol(self):
        return f'.type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, '

    def _attr_policy(self, policy):
        return 'NLA_POLICY_NESTED(' + self.nested_render_name + '_nl_policy)'

    def attr_put(self, ri, var):
        self._attr_put_line(ri, var, f"{self.nested_render_name}_put(nlh, " +
                            f"{self.enum_name}, &{var}->{self.c_name})")

    def _attr_get(self, ri, var):
        get_lines = [f"if ({self.nested_render_name}_parse(&parg, attr))",
                     "return MNL_CB_ERROR;"]
        init_lines = [f"parg.rsp_policy = &{self.nested_render_name}_nest;",
                      f"parg.data = &{var}->{self.c_name};"]
        return get_lines, init_lines, None

    def setter(self, ri, space, direction, deref=False, ref=None):
        ref = (ref if ref else []) + [self.c_name]

        for _, attr in ri.family.pure_nested_structs[self.nested_attrs].member_list():
            attr.setter(ri, self.nested_attrs, direction, deref=deref, ref=ref)


class TypeMultiAttr(Type):
    def __init__(self, family, attr_set, attr, value, base_type):
        super().__init__(family, attr_set, attr, value)

        self.base_type = base_type

    def is_multi_val(self):
        return True

    def presence_type(self):
        return 'count'

    def _mnl_type(self):
        t = self.type
        # mnl does not have a helper for signed types
        if t[0] == 's':
            t = 'u' + t[1:]
        return t

    def _complex_member_type(self, ri):
        if 'type' not in self.attr or self.attr['type'] == 'nest':
            return self.nested_struct_type
        elif self.attr['type'] in scalars:
            scalar_pfx = '__' if ri.ku_space == 'user' else ''
            return scalar_pfx + self.attr['type']
        else:
            raise Exception(f"Sub-type {self.attr['type']} not supported yet")

    def free_needs_iter(self):
        return 'type' not in self.attr or self.attr['type'] == 'nest'

    def free(self, ri, var, ref):
        if self.attr['type'] in scalars:
            ri.cw.p(f"free({var}->{ref}{self.c_name});")
        elif 'type' not in self.attr or self.attr['type'] == 'nest':
            ri.cw.p(f"for (i = 0; i < {var}->{ref}n_{self.c_name}; i++)")
            ri.cw.p(f'{self.nested_render_name}_free(&{var}->{ref}{self.c_name}[i]);')
            ri.cw.p(f"free({var}->{ref}{self.c_name});")
        else:
            raise Exception(f"Free of MultiAttr sub-type {self.attr['type']} not supported yet")

    def _attr_policy(self, policy):
        return self.base_type._attr_policy(policy)

    def _attr_typol(self):
        return self.base_type._attr_typol()

    def _attr_get(self, ri, var):
        return f'n_{self.c_name}++;', None, None

    def attr_put(self, ri, var):
        if self.attr['type'] in scalars:
            put_type = self._mnl_type()
            ri.cw.p(f"for (unsigned int i = 0; i < {var}->n_{self.c_name}; i++)")
            ri.cw.p(f"mnl_attr_put_{put_type}(nlh, {self.enum_name}, {var}->{self.c_name}[i]);")
        elif 'type' not in self.attr or self.attr['type'] == 'nest':
            ri.cw.p(f"for (unsigned int i = 0; i < {var}->n_{self.c_name}; i++)")
            self._attr_put_line(ri, var, f"{self.nested_render_name}_put(nlh, " +
                                f"{self.enum_name}, &{var}->{self.c_name}[i])")
        else:
            raise Exception(f"Put of MultiAttr sub-type {self.attr['type']} not supported yet")

    def _setter_lines(self, ri, member, presence):
        # For multi-attr we have a count, not presence, hack up the presence
        presence = presence[:-(len('_present.') + len(self.c_name))] + "n_" + self.c_name
        return [f"free({member});",
                f"{member} = {self.c_name};",
                f"{presence} = n_{self.c_name};"]


class TypeArrayNest(Type):
    def is_multi_val(self):
        return True

    def presence_type(self):
        return 'count'

    def _complex_member_type(self, ri):
        if 'sub-type' not in self.attr or self.attr['sub-type'] == 'nest':
            return self.nested_struct_type
        elif self.attr['sub-type'] in scalars:
            scalar_pfx = '__' if ri.ku_space == 'user' else ''
            return scalar_pfx + self.attr['sub-type']
        else:
            raise Exception(f"Sub-type {self.attr['sub-type']} not supported yet")

    def _attr_typol(self):
        return f'.type = YNL_PT_NEST, .nest = &{self.nested_render_name}_nest, '

    def _attr_get(self, ri, var):
        local_vars = ['const struct nlattr *attr2;']
        get_lines = [f'attr_{self.c_name} = attr;',
                     'mnl_attr_for_each_nested(attr2, attr)',
                     f'\t{var}->n_{self.c_name}++;']
        return get_lines, None, local_vars


class TypeNestTypeValue(Type):
    def _complex_member_type(self, ri):
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
                get_lines += [f'attr_{level} = mnl_attr_get_payload({prev});']
                get_lines += [f'{level} = mnl_attr_get_type(attr_{level});']
                prev = 'attr_' + level

            tv_args = f", {', '.join(tv_names)}"

        get_lines += [f"{self.nested_render_name}_parse(&parg, {prev}{tv_args});"]
        return get_lines, init_lines, local_vars


class Struct:
    def __init__(self, family, space_name, type_list=None, inherited=None):
        self.family = family
        self.space_name = space_name
        self.attr_set = family.attr_sets[space_name]
        # Use list to catch comparisons with empty sets
        self._inherited = inherited if inherited is not None else []
        self.inherited = []

        self.nested = type_list is None
        if family.name == c_lower(space_name):
            self.render_name = f"{family.name}"
        else:
            self.render_name = f"{family.name}_{c_lower(space_name)}"
        self.struct_name = 'struct ' + self.render_name
        if self.nested and space_name in family.consts:
            self.struct_name += '_'
        self.ptr_name = self.struct_name + ' *'

        self.request = False
        self.reply = False

        self.attr_list = []
        self.attrs = dict()
        if type_list:
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


class EnumEntry(SpecEnumEntry):
    def __init__(self, enum_set, yaml, prev, value_start):
        super().__init__(enum_set, yaml, prev, value_start)

        if prev:
            self.value_change = (self.value != prev.value + 1)
        else:
            self.value_change = (self.value != 0)
        self.value_change = self.value_change or self.enum_set['type'] == 'flags'

        # Added by resolve:
        self.c_name = None
        delattr(self, "c_name")

    def resolve(self):
        self.resolve_up(super())

        self.c_name = c_upper(self.enum_set.value_pfx + self.name)


class EnumSet(SpecEnumSet):
    def __init__(self, family, yaml):
        self.render_name = c_lower(family.name + '-' + yaml['name'])

        if 'enum-name' in yaml:
            if yaml['enum-name']:
                self.enum_name = 'enum ' + c_lower(yaml['enum-name'])
            else:
                self.enum_name = None
        else:
            self.enum_name = 'enum ' + self.render_name

        self.value_pfx = yaml.get('name-prefix', f"{family.name}-{yaml['name']}-")

        super().__init__(family, yaml)

    def new_entry(self, entry, prev_entry, value_start):
        return EnumEntry(self, entry, prev_entry, value_start)

    def value_range(self):
        low = min([x.value for x in self.entries.values()])
        high = max([x.value for x in self.entries.values()])

        if high - low + 1 != len(self.entries):
            raise Exception("Can't get value range for a noncontiguous enum")

        return low, high


class AttrSet(SpecAttrSet):
    def __init__(self, family, yaml):
        super().__init__(family, yaml)

        if self.subset_of is None:
            if 'name-prefix' in yaml:
                pfx = yaml['name-prefix']
            elif self.name == family.name:
                pfx = family.name + '-a-'
            else:
                pfx = f"{family.name}-a-{self.name}-"
            self.name_prefix = c_upper(pfx)
            self.max_name = c_upper(self.yaml.get('attr-max-name', f"{self.name_prefix}max"))
        else:
            self.name_prefix = family.attr_sets[self.subset_of].name_prefix
            self.max_name = family.attr_sets[self.subset_of].max_name

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
            t = TypeBinary(self.family, self, elem, value)
        elif elem['type'] == 'nest':
            t = TypeNest(self.family, self, elem, value)
        elif elem['type'] == 'array-nest':
            t = TypeArrayNest(self.family, self, elem, value)
        elif elem['type'] == 'nest-type-value':
            t = TypeNestTypeValue(self.family, self, elem, value)
        else:
            raise Exception(f"No typed class for type {elem['type']}")

        if 'multi-attr' in elem and elem['multi-attr']:
            t = TypeMultiAttr(self.family, self, elem, value, t)

        return t


class Operation(SpecOperation):
    def __init__(self, family, yaml, req_value, rsp_value):
        super().__init__(family, yaml, req_value, rsp_value)

        self.render_name = family.name + '_' + c_lower(self.name)

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


class Family(SpecFamily):
    def __init__(self, file_name, exclude_ops):
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

        super().__init__(file_name, exclude_ops=exclude_ops)

        self.fam_key = c_upper(self.yaml.get('c-family-name', self.yaml["name"] + '_FAMILY_NAME'))
        self.ver_key = c_upper(self.yaml.get('c-version-name', self.yaml["name"] + '_FAMILY_VERSION'))

        if 'definitions' not in self.yaml:
            self.yaml['definitions'] = []

        if 'uapi-header' in self.yaml:
            self.uapi_header = self.yaml['uapi-header']
        else:
            self.uapi_header = f"linux/{self.name}.h"

    def resolve(self):
        self.resolve_up(super())

        if self.yaml.get('protocol', 'genetlink') not in {'genetlink', 'genetlink-c', 'genetlink-legacy'}:
            raise Exception("Codegen only supported for genetlink")

        self.c_name = c_lower(self.name)
        if 'name-prefix' in self.yaml['operations']:
            self.op_prefix = c_upper(self.yaml['operations']['name-prefix'])
        else:
            self.op_prefix = c_upper(self.yaml['name'] + '-cmd-')
        if 'async-prefix' in self.yaml['operations']:
            self.async_op_prefix = c_upper(self.yaml['operations']['async-prefix'])
        else:
            self.async_op_prefix = self.op_prefix

        self.mcgrps = self.yaml.get('mcast-groups', {'list': []})

        self.hooks = dict()
        for when in ['pre', 'post']:
            self.hooks[when] = dict()
            for op_mode in ['do', 'dump']:
                self.hooks[when][op_mode] = dict()
                self.hooks[when][op_mode]['set'] = set()
                self.hooks[when][op_mode]['list'] = []

        # dict space-name -> 'request': set(attrs), 'reply': set(attrs)
        self.root_sets = dict()
        # dict space-name -> set('request', 'reply')
        self.pure_nested_structs = dict()

        self._mark_notify()
        self._mock_up_events()

        self._load_root_sets()
        self._load_nested_sets()
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
        for op_name, op in self.msgs.items():
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

    def _load_nested_sets(self):
        attr_set_queue = list(self.root_sets.keys())
        attr_set_seen = set(self.root_sets.keys())

        while len(attr_set_queue):
            a_set = attr_set_queue.pop(0)
            for attr, spec in self.attr_sets[a_set].items():
                if 'nested-attributes' not in spec:
                    continue

                nested = spec['nested-attributes']
                if nested not in attr_set_seen:
                    attr_set_queue.append(nested)
                    attr_set_seen.add(nested)

                inherit = set()
                if nested not in self.root_sets:
                    if nested not in self.pure_nested_structs:
                        self.pure_nested_structs[nested] = Struct(self, nested, inherited=inherit)
                else:
                    raise Exception(f'Using attr set as root and nested not supported - {nested}')

                if 'type-value' in spec:
                    if nested in self.root_sets:
                        raise Exception("Inheriting members to a space used as root not supported")
                    inherit.update(set(spec['type-value']))
                elif spec['type'] == 'array-nest':
                    inherit.add('idx')
                self.pure_nested_structs[nested].set_inherited(inherit)

        for root_set, rs_members in self.root_sets.items():
            for attr, spec in self.attr_sets[root_set].items():
                if 'nested-attributes' in spec:
                    nested = spec['nested-attributes']
                    if attr in rs_members['request']:
                        self.pure_nested_structs[nested].request = True
                    if attr in rs_members['reply']:
                        self.pure_nested_structs[nested].reply = True

        # Try to reorder according to dependencies
        pns_key_list = list(self.pure_nested_structs.keys())
        pns_key_seen = set()
        rounds = len(pns_key_list)**2  # it's basically bubble sort
        for _ in range(rounds):
            if len(pns_key_list) == 0:
                break
            name = pns_key_list.pop(0)
            finished = True
            for _, spec in self.attr_sets[name].items():
                if 'nested-attributes' in spec:
                    if spec['nested-attributes'] not in pns_key_seen:
                        # Dicts are sorted, this will make struct last
                        struct = self.pure_nested_structs.pop(name)
                        self.pure_nested_structs[name] = struct
                        finished = False
                        break
            if finished:
                pns_key_seen.add(name)
            else:
                pns_key_list.append(name)
        # Propagate the request / reply
        for attr_set, struct in reversed(self.pure_nested_structs.items()):
            for _, spec in self.attr_sets[attr_set].items():
                if 'nested-attributes' in spec:
                    child = self.pure_nested_structs.get(spec['nested-attributes'])
                    if child:
                        child.request |= struct.request
                        child.reply |= struct.reply

    def _load_global_policy(self):
        global_set = set()
        attr_set_name = None
        for op_name, op in self.ops.items():
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
                    global_set.update(op[op_mode].get('request', []))

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

        # 'do' and 'dump' response parsing is identical
        self.type_consistent = True
        if op_mode != 'do' and 'dump' in op and 'do' in op:
            if ('reply' in op['do']) != ('reply' in op["dump"]):
                self.type_consistent = False
            elif 'reply' in op['do'] and op["do"]["reply"] != op["dump"]["reply"]:
                self.type_consistent = False

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

        self.struct = dict()
        if op_mode == 'notify':
            op_mode = 'do'
        for op_dir in ['request', 'reply']:
            if op and op_dir in op[op_mode]:
                self.struct[op_dir] = Struct(family, self.attr_set,
                                             type_list=op[op_mode][op_dir]['attributes'])
        if op_mode == 'event':
            self.struct['reply'] = Struct(family, self.attr_set, type_list=op['event']['attributes'])
