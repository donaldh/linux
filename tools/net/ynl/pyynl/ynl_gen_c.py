#!/usr/bin/env python3
# SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
#
# pylint: disable=line-too-long, missing-class-docstring, missing-function-docstring
# pylint: disable=too-many-positional-arguments, too-many-arguments, too-many-statements
# pylint: disable=too-many-branches, too-many-locals, too-many-instance-attributes
# pylint: disable=too-many-nested-blocks, too-many-lines, too-few-public-methods
# pylint: disable=broad-exception-raised, broad-exception-caught, protected-access

"""
ynl_gen_c

A YNL to C code generator for both kernel and userspace protocol stubs.
"""

import argparse
import pathlib
import os
import re
import sys
import yaml as pyyaml

# pylint: disable=no-name-in-module,wrong-import-position
sys.path.append(pathlib.Path(__file__).resolve().parent.as_posix())
from lib import c_lower, c_upper
from lib import CodeWriter, Family, BaseNlLib, Struct, RenderInfo, EnumSet, scalars
from lib import op_prefix, direction_to_suffix, type_name



def rdir(direction):
    if direction == 'reply':
        return 'request'
    if direction == 'request':
        return 'reply'
    return direction


def print_prototype(ri, direction, terminate=True, doc=None):
    suffix = ';' if terminate else ''

    fname = ri.op.render_name
    if ri.op_mode == 'dump':
        fname += '_dump'

    args = ['struct ynl_sock *ys']
    if 'request' in ri.op[ri.op_mode]:
        args.append(f"{type_name(ri, direction)} *" + f"{direction_to_suffix[direction][1:]}")

    ret = 'int'
    if 'reply' in ri.op[ri.op_mode]:
        ret = f"{type_name(ri, rdir(direction))} *"

    ri.cw.write_func_prot(ret, fname, args, doc=doc, suffix=suffix)


def print_req_prototype(ri):
    print_prototype(ri, "request", doc=ri.op['doc'])


def print_dump_prototype(ri):
    print_prototype(ri, "request")


def put_typol_submsg(cw, struct):
    cw.block_start(line=f'const struct ynl_policy_attr {struct.render_name}_policy[] =')

    i = 0
    for name, arg in struct.member_list():
        nest = ""
        if arg.type == 'nest':
            nest = f" .nest = &{arg.nested_render_name}_nest,"
        cw.p('[%d] = { .type = YNL_PT_SUBMSG, .name = "%s",%s },' %
             (i, name, nest))
        i += 1

    cw.block_end(line=';')
    cw.nl()

    cw.block_start(line=f'const struct ynl_policy_nest {struct.render_name}_nest =')
    cw.p(f'.max_attr = {i - 1},')
    cw.p(f'.table = {struct.render_name}_policy,')
    cw.block_end(line=';')
    cw.nl()


def put_typol_fwd(cw, struct):
    cw.p(f'extern const struct ynl_policy_nest {struct.render_name}_nest;')


def put_typol(cw, struct):
    if struct.submsg:
        put_typol_submsg(cw, struct)
        return

    type_max = struct.attr_set.max_name
    cw.block_start(line=f'const struct ynl_policy_attr {struct.render_name}_policy[{type_max} + 1] =')

    for _, arg in struct.member_list():
        arg.attr_typol(cw)

    cw.block_end(line=';')
    cw.nl()

    cw.block_start(line=f'const struct ynl_policy_nest {struct.render_name}_nest =')
    cw.p(f'.max_attr = {type_max},')
    cw.p(f'.table = {struct.render_name}_policy,')
    cw.block_end(line=';')
    cw.nl()


def _put_enum_to_str_helper(cw, render_name, map_name, arg_name, enum=None):
    args = [f'int {arg_name}']
    if enum:
        args = [enum.user_type + ' ' + arg_name]
    cw.write_func_prot('const char *', f'{render_name}_str', args)
    cw.block_start()
    if enum and enum.type == 'flags':
        cw.p(f'{arg_name} = ffs({arg_name}) - 1;')
    cw.p(f'if ({arg_name} < 0 || {arg_name} >= (int)YNL_ARRAY_SIZE({map_name}))')
    cw.p('return NULL;')
    cw.p(f'return {map_name}[{arg_name}];')
    cw.block_end()
    cw.nl()


def put_op_name_fwd(family, cw):
    cw.write_func_prot('const char *', f'{family.c_name}_op_str', ['int op'], suffix=';')


def put_op_name(family, cw):
    map_name = f'{family.c_name}_op_strmap'
    cw.block_start(line=f"static const char * const {map_name}[] =")
    for op_name, op in family.msgs.items():
        if op.rsp_value:
            # Make sure we don't add duplicated entries, if multiple commands
            # produce the same response in legacy families.
            if family.rsp_by_value[op.rsp_value] != op:
                cw.p(f'// skip "{op_name}", duplicate reply value')
                continue

            if op.req_value == op.rsp_value:
                cw.p(f'[{op.enum_name}] = "{op_name}",')
            else:
                cw.p(f'[{op.rsp_value}] = "{op_name}",')
    cw.block_end(line=';')
    cw.nl()

    _put_enum_to_str_helper(cw, family.c_name + '_op', map_name, 'op')


def put_enum_to_str_fwd(_family, cw, enum):
    args = [enum.user_type + ' value']
    cw.write_func_prot('const char *', f'{enum.render_name}_str', args, suffix=';')


def put_enum_to_str(_family, cw, enum):
    map_name = f'{enum.render_name}_strmap'
    cw.block_start(line=f"static const char * const {map_name}[] =")
    for entry in enum.entries.values():
        cw.p(f'[{entry.value}] = "{entry.name}",')
    cw.block_end(line=';')
    cw.nl()

    _put_enum_to_str_helper(cw, enum.render_name, map_name, 'value', enum=enum)


def put_local_vars(struct):
    local_vars = []
    has_array = False
    has_count = False
    for _, arg in struct.member_list():
        has_array |= arg.type == 'indexed-array'
        has_count |= arg.presence_type() == 'count'
    if has_array:
        local_vars.append('struct nlattr *array;')
    if has_count:
        local_vars.append('unsigned int i;')
    return local_vars


def put_req_nested_prototype(ri, struct, suffix=';'):
    func_args = ['struct nlmsghdr *nlh',
                 'unsigned int attr_type',
                 f'{struct.ptr_name}obj']

    ri.cw.write_func_prot('int', f'{struct.render_name}_put', func_args,
                          suffix=suffix)


def put_req_nested(ri, struct):
    local_vars = []
    init_lines = []

    if struct.submsg is None:
        local_vars.append('struct nlattr *nest;')
        init_lines.append("nest = ynl_attr_nest_start(nlh, attr_type);")
    if struct.fixed_header:
        local_vars.append('void *hdr;')
        struct_sz = f'sizeof({struct.fixed_header})'
        init_lines.append(f"hdr = ynl_nlmsg_put_extra_header(nlh, {struct_sz});")
        init_lines.append(f"memcpy(hdr, &obj->_hdr, {struct_sz});")

    local_vars += put_local_vars(struct)

    put_req_nested_prototype(ri, struct, suffix='')
    ri.cw.block_start()
    ri.cw.write_func_lvar(local_vars)

    for line in init_lines:
        ri.cw.p(line)

    for _, arg in struct.member_list():
        arg.attr_put(ri, "obj")

    if struct.submsg is None:
        ri.cw.p("ynl_attr_nest_end(nlh, nest);")

    ri.cw.nl()
    ri.cw.p('return 0;')
    ri.cw.block_end()
    ri.cw.nl()


def _multi_parse(ri, struct, init_lines, local_vars):
    if struct.fixed_header:
        local_vars += ['void *hdr;']
    if struct.nested:
        if struct.fixed_header:
            iter_line = f"ynl_attr_for_each_nested_off(attr, nested, sizeof({struct.fixed_header}))"
        else:
            iter_line = "ynl_attr_for_each_nested(attr, nested)"
    else:
        iter_line = "ynl_attr_for_each(attr, nlh, yarg->ys->family->hdr_len)"
        if ri.op.fixed_header != ri.family.fixed_header:
            if ri.family.is_classic():
                iter_line = f"ynl_attr_for_each(attr, nlh, sizeof({struct.fixed_header}))"
            else:
                raise Exception("Per-op fixed header not supported, yet")

    indexed_arrays = set()
    multi_attrs = set()
    needs_parg = False
    var_set = set()
    for arg, aspec in struct.member_list():
        if aspec['type'] == 'indexed-array' and 'sub-type' in aspec:
            if aspec["sub-type"] in {'binary', 'nest'}:
                local_vars.append(f'const struct nlattr *attr_{aspec.c_name} = NULL;')
                indexed_arrays.add(arg)
            elif aspec['sub-type'] in scalars:
                local_vars.append(f'const struct nlattr *attr_{aspec.c_name} = NULL;')
                indexed_arrays.add(arg)
            else:
                raise Exception(f'Not supported sub-type {aspec["sub-type"]}')
        if 'multi-attr' in aspec:
            multi_attrs.add(arg)
        needs_parg |= 'nested-attributes' in aspec
        needs_parg |= 'sub-message' in aspec

        try:
            _, _, l_vars = aspec._attr_get(ri, '')
            var_set |= set(l_vars) if l_vars else set()
        except Exception:
            pass  # _attr_get() not implemented by simple types, ignore
    local_vars += list(var_set)
    if indexed_arrays or multi_attrs:
        local_vars.append('int i;')
    if needs_parg:
        local_vars.append('struct ynl_parse_arg parg;')
        init_lines.append('parg.ys = yarg->ys;')

    all_multi = indexed_arrays | multi_attrs

    for arg in sorted(all_multi):
        local_vars.append(f"unsigned int n_{struct[arg].c_name} = 0;")

    ri.cw.block_start()
    ri.cw.write_func_lvar(local_vars)

    for line in init_lines:
        ri.cw.p(line)
    ri.cw.nl()

    for arg in struct.inherited:
        ri.cw.p(f'dst->{arg} = {arg};')

    if struct.fixed_header:
        if struct.nested:
            ri.cw.p('hdr = ynl_attr_data(nested);')
        elif ri.family.is_classic():
            ri.cw.p('hdr = ynl_nlmsg_data(nlh);')
        else:
            ri.cw.p('hdr = ynl_nlmsg_data_offset(nlh, sizeof(struct genlmsghdr));')
        ri.cw.p(f"memcpy(&dst->_hdr, hdr, sizeof({struct.fixed_header}));")
    for arg in sorted(all_multi):
        aspec = struct[arg]
        ri.cw.p(f"if (dst->{aspec.c_name})")
        ri.cw.p(f'return ynl_error_parse(yarg, "attribute already present ({struct.attr_set.name}.{aspec.name})");')

    ri.cw.nl()
    ri.cw.block_start(line=iter_line)
    ri.cw.p('unsigned int type = ynl_attr_type(attr);')
    ri.cw.nl()

    first = True
    for _, arg in struct.member_list():
        good = arg.attr_get(ri, 'dst', first=first)
        # First may be 'unused' or 'pad', ignore those
        first &= not good

    ri.cw.block_end()
    ri.cw.nl()

    for arg in sorted(indexed_arrays):
        aspec = struct[arg]

        ri.cw.block_start(line=f"if (n_{aspec.c_name})")
        ri.cw.p(f"dst->{aspec.c_name} = calloc(n_{aspec.c_name}, sizeof(*dst->{aspec.c_name}));")
        ri.cw.p(f"dst->_count.{aspec.c_name} = n_{aspec.c_name};")
        ri.cw.p('i = 0;')
        if 'nested-attributes' in aspec:
            ri.cw.p(f"parg.rsp_policy = &{aspec.nested_render_name}_nest;")
        ri.cw.block_start(line=f"ynl_attr_for_each_nested(attr, attr_{aspec.c_name})")
        if 'nested-attributes' in aspec:
            ri.cw.p(f"parg.data = &dst->{aspec.c_name}[i];")
            ri.cw.p(f"if ({aspec.nested_render_name}_parse(&parg, attr, ynl_attr_type(attr)))")
            ri.cw.p('return YNL_PARSE_CB_ERROR;')
        elif aspec.sub_type in scalars:
            ri.cw.p(f"dst->{aspec.c_name}[i] = ynl_attr_get_{aspec.sub_type}(attr);")
        elif aspec.sub_type == 'binary' and 'exact-len' in aspec.checks:
            # Length is validated by typol
            ri.cw.p(f'memcpy(dst->{aspec.c_name}[i], ynl_attr_data(attr), {aspec.checks["exact-len"]});')
        else:
            raise Exception(f"Nest parsing type not supported in {aspec['name']}")
        ri.cw.p('i++;')
        ri.cw.block_end()
        ri.cw.block_end()
    ri.cw.nl()

    for arg in sorted(multi_attrs):
        aspec = struct[arg]
        ri.cw.block_start(line=f"if (n_{aspec.c_name})")
        ri.cw.p(f"dst->{aspec.c_name} = calloc(n_{aspec.c_name}, sizeof(*dst->{aspec.c_name}));")
        ri.cw.p(f"dst->_count.{aspec.c_name} = n_{aspec.c_name};")
        ri.cw.p('i = 0;')
        if 'nested-attributes' in aspec:
            ri.cw.p(f"parg.rsp_policy = &{aspec.nested_render_name}_nest;")
        ri.cw.block_start(line=iter_line)
        ri.cw.block_start(line=f"if (ynl_attr_type(attr) == {aspec.enum_name})")
        if 'nested-attributes' in aspec:
            ri.cw.p(f"parg.data = &dst->{aspec.c_name}[i];")
            ri.cw.p(f"if ({aspec.nested_render_name}_parse(&parg, attr))")
            ri.cw.p('return YNL_PARSE_CB_ERROR;')
        elif aspec.type in scalars:
            ri.cw.p(f"dst->{aspec.c_name}[i] = ynl_attr_get_{aspec.type}(attr);")
        elif aspec.type == 'binary' and 'struct' in aspec:
            ri.cw.p('size_t len = ynl_attr_data_len(attr);')
            ri.cw.nl()
            ri.cw.p(f'if (len > sizeof(dst->{aspec.c_name}[0]))')
            ri.cw.p(f'len = sizeof(dst->{aspec.c_name}[0]);')
            ri.cw.p(f"memcpy(&dst->{aspec.c_name}[i], ynl_attr_data(attr), len);")
        elif aspec.type == 'string':
            ri.cw.p('unsigned int len;')
            ri.cw.nl()
            ri.cw.p('len = strnlen(ynl_attr_get_str(attr), ynl_attr_data_len(attr));')
            ri.cw.p(f'dst->{aspec.c_name}[i] = malloc(sizeof(struct ynl_string) + len + 1);')
            ri.cw.p(f"dst->{aspec.c_name}[i]->len = len;")
            ri.cw.p(f"memcpy(dst->{aspec.c_name}[i]->str, ynl_attr_get_str(attr), len);")
            ri.cw.p(f"dst->{aspec.c_name}[i]->str[len] = 0;")
        else:
            raise Exception(f'Nest parsing of type {aspec.type} not supported yet')
        ri.cw.p('i++;')
        ri.cw.block_end()
        ri.cw.block_end()
        ri.cw.block_end()
    ri.cw.nl()

    if struct.nested:
        ri.cw.p('return 0;')
    else:
        ri.cw.p('return YNL_PARSE_CB_OK;')
    ri.cw.block_end()
    ri.cw.nl()


def parse_rsp_submsg(ri, struct):
    parse_rsp_nested_prototype(ri, struct, suffix='')

    var = 'dst'
    local_vars = {'const struct nlattr *attr = nested;',
                  f'{struct.ptr_name}{var} = yarg->data;',
                  'struct ynl_parse_arg parg;'}

    for _, arg in struct.member_list():
        _, _, l_vars = arg._attr_get(ri, var)
        local_vars |= set(l_vars) if l_vars else set()

    ri.cw.block_start()
    ri.cw.write_func_lvar(list(local_vars))
    ri.cw.p('parg.ys = yarg->ys;')
    ri.cw.nl()

    first = True
    for name, arg in struct.member_list():
        kw = 'if' if first else 'else if'
        first = False

        ri.cw.block_start(line=f'{kw} (!strcmp(sel, "{name}"))')
        get_lines, init_lines, _ = arg._attr_get(ri, var)
        for line in init_lines or []:
            ri.cw.p(line)
        for line in get_lines:
            ri.cw.p(line)
        if arg.presence_type() == 'present':
            ri.cw.p(f"{var}->_present.{arg.c_name} = 1;")
        ri.cw.block_end()
    ri.cw.p('return 0;')
    ri.cw.block_end()
    ri.cw.nl()


def parse_rsp_nested_prototype(ri, struct, suffix=';'):
    func_args = ['struct ynl_parse_arg *yarg',
                 'const struct nlattr *nested']
    for sel in struct.external_selectors():
        func_args.append('const char *_sel_' + sel.name)
    if struct.submsg:
        func_args.insert(1, 'const char *sel')
    for arg in struct.inherited:
        func_args.append('__u32 ' + arg)

    ri.cw.write_func_prot('int', f'{struct.render_name}_parse', func_args,
                          suffix=suffix)


def parse_rsp_nested(ri, struct):
    if struct.submsg:
        parse_rsp_submsg(ri, struct)
        return

    parse_rsp_nested_prototype(ri, struct, suffix='')

    local_vars = ['const struct nlattr *attr;',
                  f'{struct.ptr_name}dst = yarg->data;']
    init_lines = []

    if struct.member_list():
        _multi_parse(ri, struct, init_lines, local_vars)
    else:
        # Empty nest
        ri.cw.block_start()
        ri.cw.p('return 0;')
        ri.cw.block_end()
        ri.cw.nl()


def parse_rsp_msg(ri, deref=False):
    if 'reply' not in ri.op[ri.op_mode] and ri.op_mode != 'event':
        return

    func_args = ['const struct nlmsghdr *nlh',
                 'struct ynl_parse_arg *yarg']

    local_vars = [f'{type_name(ri, "reply", deref=deref)} *dst;',
                  'const struct nlattr *attr;']
    init_lines = ['dst = yarg->data;']

    ri.cw.write_func_prot('int', f'{op_prefix(ri, "reply", deref=deref)}_parse', func_args)

    if ri.struct["reply"].member_list():
        _multi_parse(ri, ri.struct["reply"], init_lines, local_vars)
    else:
        # Empty reply
        ri.cw.block_start()
        ri.cw.p('return YNL_PARSE_CB_OK;')
        ri.cw.block_end()
        ri.cw.nl()


def print_req(ri):
    ret_ok = '0'
    ret_err = '-1'
    direction = "request"
    local_vars = ['struct ynl_req_state yrs = { .yarg = { .ys = ys, }, };',
                  'struct nlmsghdr *nlh;',
                  'int err;']

    if 'reply' in ri.op[ri.op_mode]:
        ret_ok = 'rsp'
        ret_err = 'NULL'
        local_vars += [f'{type_name(ri, rdir(direction))} *rsp;']

    if ri.struct["request"].fixed_header:
        local_vars += ['size_t hdr_len;',
                       'void *hdr;']

    local_vars += put_local_vars(ri.struct['request'])

    print_prototype(ri, direction, terminate=False)
    ri.cw.block_start()
    ri.cw.write_func_lvar(local_vars)

    if ri.family.is_classic():
        ri.cw.p(f"nlh = ynl_msg_start_req(ys, {ri.op.enum_name}, req->_nlmsg_flags);")
    else:
        ri.cw.p(f"nlh = ynl_gemsg_start_req(ys, {ri.nl.get_family_id()}, {ri.op.enum_name}, 1);")

    ri.cw.p(f"ys->req_policy = &{ri.struct['request'].render_name}_nest;")
    ri.cw.p(f"ys->req_hdr_len = {ri.fixed_hdr_len};")
    if 'reply' in ri.op[ri.op_mode]:
        ri.cw.p(f"yrs.yarg.rsp_policy = &{ri.struct['reply'].render_name}_nest;")
    ri.cw.nl()

    if ri.struct['request'].fixed_header:
        ri.cw.p("hdr_len = sizeof(req->_hdr);")
        ri.cw.p("hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);")
        ri.cw.p("memcpy(hdr, &req->_hdr, hdr_len);")
        ri.cw.nl()

    for _, attr in ri.struct["request"].member_list():
        attr.attr_put(ri, "req")
    ri.cw.nl()

    if 'reply' in ri.op[ri.op_mode]:
        ri.cw.p('rsp = calloc(1, sizeof(*rsp));')
        ri.cw.p('yrs.yarg.data = rsp;')
        ri.cw.p(f"yrs.cb = {op_prefix(ri, 'reply')}_parse;")
        if ri.op.value is not None:
            ri.cw.p(f'yrs.rsp_cmd = {ri.op.enum_name};')
        else:
            ri.cw.p(f'yrs.rsp_cmd = {ri.op.rsp_value};')
        ri.cw.nl()
    ri.cw.p("err = ynl_exec(ys, nlh, &yrs);")
    ri.cw.p('if (err < 0)')
    if 'reply' in ri.op[ri.op_mode]:
        ri.cw.p('goto err_free;')
    else:
        ri.cw.p('return -1;')
    ri.cw.nl()

    ri.cw.p(f"return {ret_ok};")
    ri.cw.nl()

    if 'reply' in ri.op[ri.op_mode]:
        ri.cw.p('err_free:')
        ri.cw.p(f"{call_free(ri, rdir(direction), 'rsp')}")
        ri.cw.p(f"return {ret_err};")

    ri.cw.block_end()


def print_dump(ri):
    direction = "request"
    print_prototype(ri, direction, terminate=False)
    ri.cw.block_start()
    local_vars = ['struct ynl_dump_state yds = {};',
                  'struct nlmsghdr *nlh;',
                  'int err;']

    if ri.struct['request'].fixed_header:
        local_vars += ['size_t hdr_len;',
                       'void *hdr;']

    if 'request' in ri.op[ri.op_mode]:
        local_vars += put_local_vars(ri.struct['request'])

    ri.cw.write_func_lvar(local_vars)

    ri.cw.p('yds.yarg.ys = ys;')
    ri.cw.p(f"yds.yarg.rsp_policy = &{ri.struct['reply'].render_name}_nest;")
    ri.cw.p("yds.yarg.data = NULL;")
    ri.cw.p(f"yds.alloc_sz = sizeof({type_name(ri, rdir(direction))});")
    ri.cw.p(f"yds.cb = {op_prefix(ri, 'reply', deref=True)}_parse;")
    if ri.op.value is not None:
        ri.cw.p(f'yds.rsp_cmd = {ri.op.enum_name};')
    else:
        ri.cw.p(f'yds.rsp_cmd = {ri.op.rsp_value};')
    ri.cw.nl()
    if ri.family.is_classic():
        ri.cw.p(f"nlh = ynl_msg_start_dump(ys, {ri.op.enum_name});")
    else:
        ri.cw.p(f"nlh = ynl_gemsg_start_dump(ys, {ri.nl.get_family_id()}, {ri.op.enum_name}, 1);")

    if ri.struct['request'].fixed_header:
        ri.cw.p("hdr_len = sizeof(req->_hdr);")
        ri.cw.p("hdr = ynl_nlmsg_put_extra_header(nlh, hdr_len);")
        ri.cw.p("memcpy(hdr, &req->_hdr, hdr_len);")
        ri.cw.nl()

    if "request" in ri.op[ri.op_mode]:
        ri.cw.p(f"ys->req_policy = &{ri.struct['request'].render_name}_nest;")
        ri.cw.p(f"ys->req_hdr_len = {ri.fixed_hdr_len};")
        ri.cw.nl()
        for _, attr in ri.struct["request"].member_list():
            attr.attr_put(ri, "req")
    ri.cw.nl()

    ri.cw.p('err = ynl_exec_dump(ys, nlh, &yds);')
    ri.cw.p('if (err < 0)')
    ri.cw.p('goto free_list;')
    ri.cw.nl()

    ri.cw.p('return yds.first;')
    ri.cw.nl()
    ri.cw.p('free_list:')
    ri.cw.p(call_free(ri, rdir(direction), 'yds.first'))
    ri.cw.p('return NULL;')
    ri.cw.block_end()


def call_free(ri, direction, var):
    return f"{op_prefix(ri, direction)}_free({var});"


def free_arg_name(direction):
    if direction:
        return direction_to_suffix[direction][1:]
    return 'obj'


def print_alloc_wrapper(ri, direction, struct=None):
    name = op_prefix(ri, direction)
    struct_name = name
    if ri.type_name_conflict:
        struct_name += '_'

    args = ["void"]
    cnt = "1"
    if struct and struct.in_multi_val:
        args = ["unsigned int n"]
        cnt = "n"

    ri.cw.write_func_prot(f'static inline struct {struct_name} *',
                          f"{name}_alloc", args)
    ri.cw.block_start()
    ri.cw.p(f'return calloc({cnt}, sizeof(struct {struct_name}));')
    ri.cw.block_end()


def print_free_prototype(ri, direction, suffix=';'):
    name = op_prefix(ri, direction)
    struct_name = name
    if ri.type_name_conflict:
        struct_name += '_'
    arg = free_arg_name(direction)
    ri.cw.write_func_prot('void', f"{name}_free", [f"struct {struct_name} *{arg}"], suffix=suffix)


def print_nlflags_set(ri, direction):
    name = op_prefix(ri, direction)
    ri.cw.write_func_prot('static inline void', f"{name}_set_nlflags",
                          [f"struct {name} *req", "__u16 nl_flags"])
    ri.cw.block_start()
    ri.cw.p('req->_nlmsg_flags = nl_flags;')
    ri.cw.block_end()
    ri.cw.nl()


def _print_type(ri, direction, struct):
    suffix = f'_{ri.type_name}{direction_to_suffix[direction]}'
    if not direction and ri.type_name_conflict:
        suffix += '_'

    if ri.op_mode == 'dump' and not ri.type_oneside:
        suffix += '_dump'

    ri.cw.block_start(line=f"struct {ri.family.c_name}{suffix}")

    if ri.needs_nlflags(direction):
        ri.cw.p('__u16 _nlmsg_flags;')
        ri.cw.nl()
    if struct.fixed_header:
        ri.cw.p(struct.fixed_header + ' _hdr;')
        ri.cw.nl()

    for type_filter in ['present', 'len', 'count']:
        meta_started = False
        for _, attr in struct.member_list():
            line = attr.presence_member(ri.ku_space, type_filter)
            if line:
                if not meta_started:
                    ri.cw.block_start(line="struct")
                    meta_started = True
                ri.cw.p(line)
        if meta_started:
            ri.cw.block_end(line=f'_{type_filter};')
    ri.cw.nl()

    for arg in struct.inherited:
        ri.cw.p(f"__u32 {arg};")

    for _, attr in struct.member_list():
        attr.struct_member(ri)

    ri.cw.block_end(line=';')
    ri.cw.nl()


def print_type(ri, direction):
    _print_type(ri, direction, ri.struct[direction])


def print_type_full(ri, struct):
    _print_type(ri, "", struct)

    if struct.request and struct.in_multi_val:
        print_alloc_wrapper(ri, "", struct)
        ri.cw.nl()
        free_rsp_nested_prototype(ri)
        ri.cw.nl()

        # Name conflicts are too hard to deal with with the current code base,
        # they are very rare so don't bother printing setters in that case.
        if ri.ku_space == 'user' and not ri.type_name_conflict:
            for _, attr in struct.member_list():
                attr.setter(ri, ri.attr_set, "", var="obj")
        ri.cw.nl()


def print_type_helpers(ri, direction, deref=False):
    print_free_prototype(ri, direction)
    ri.cw.nl()

    if ri.needs_nlflags(direction):
        print_nlflags_set(ri, direction)

    if ri.ku_space == 'user' and direction == 'request':
        for _, attr in ri.struct[direction].member_list():
            attr.setter(ri, ri.attr_set, direction, deref=deref)
    ri.cw.nl()


def print_req_type_helpers(ri):
    if ri.type_empty("request"):
        return
    print_alloc_wrapper(ri, "request")
    print_type_helpers(ri, "request")


def print_rsp_type_helpers(ri):
    if 'reply' not in ri.op[ri.op_mode]:
        return
    print_type_helpers(ri, "reply")


def print_parse_prototype(ri, direction, terminate=True):
    suffix = "_rsp" if direction == "reply" else "_req"
    term = ';' if terminate else ''

    ri.cw.write_func_prot('void', f"{ri.op.render_name}{suffix}_parse",
                          ['const struct nlattr **tb',
                           f"struct {ri.op.render_name}{suffix} *req"],
                          suffix=term)


def print_req_type(ri):
    if ri.type_empty("request"):
        return
    print_type(ri, "request")


def print_req_free(ri):
    if 'request' not in ri.op[ri.op_mode]:
        return
    _free_type(ri, 'request', ri.struct['request'])


def print_rsp_type(ri):
    if ri.op_mode in ('do', 'dump') and 'reply' in ri.op[ri.op_mode]:
        direction = 'reply'
    elif ri.op_mode == 'event':
        direction = 'reply'
    else:
        return
    print_type(ri, direction)


def print_wrapped_type(ri):
    ri.cw.block_start(line=f"{type_name(ri, 'reply')}")
    if ri.op_mode == 'dump':
        ri.cw.p(f"{type_name(ri, 'reply')} *next;")
    elif ri.op_mode in ('notify', 'event'):
        ri.cw.p('__u16 family;')
        ri.cw.p('__u8 cmd;')
        ri.cw.p('struct ynl_ntf_base_type *next;')
        ri.cw.p(f"void (*free)({type_name(ri, 'reply')} *ntf);")
    ri.cw.p(f"{type_name(ri, 'reply', deref=True)} obj __attribute__((aligned(8)));")
    ri.cw.block_end(line=';')
    ri.cw.nl()
    print_free_prototype(ri, 'reply')
    ri.cw.nl()


def _free_type_members_iter(ri, struct):
    if struct.free_needs_iter():
        ri.cw.p('unsigned int i;')
        ri.cw.nl()


def _free_type_members(ri, var, struct, ref=''):
    for _, attr in struct.member_list():
        attr.free(ri, var, ref)


def _free_type(ri, direction, struct):
    var = free_arg_name(direction)

    print_free_prototype(ri, direction, suffix='')
    ri.cw.block_start()
    _free_type_members_iter(ri, struct)
    _free_type_members(ri, var, struct)
    if direction:
        ri.cw.p(f'free({var});')
    ri.cw.block_end()
    ri.cw.nl()


def free_rsp_nested_prototype(ri):
    print_free_prototype(ri, "")


def free_rsp_nested(ri, struct):
    _free_type(ri, "", struct)


def print_rsp_free(ri):
    if 'reply' not in ri.op[ri.op_mode]:
        return
    _free_type(ri, 'reply', ri.struct['reply'])


def print_dump_type_free(ri):
    sub_type = type_name(ri, 'reply')

    print_free_prototype(ri, 'reply', suffix='')
    ri.cw.block_start()
    ri.cw.p(f"{sub_type} *next = rsp;")
    ri.cw.nl()
    ri.cw.block_start(line='while ((void *)next != YNL_LIST_END)')
    _free_type_members_iter(ri, ri.struct['reply'])
    ri.cw.p('rsp = next;')
    ri.cw.p('next = rsp->next;')
    ri.cw.nl()

    _free_type_members(ri, 'rsp', ri.struct['reply'], ref='obj.')
    ri.cw.p('free(rsp);')
    ri.cw.block_end()
    ri.cw.block_end()
    ri.cw.nl()


def print_ntf_type_free(ri):
    print_free_prototype(ri, 'reply', suffix='')
    ri.cw.block_start()
    _free_type_members_iter(ri, ri.struct['reply'])
    _free_type_members(ri, 'rsp', ri.struct['reply'], ref='obj.')
    ri.cw.p('free(rsp);')
    ri.cw.block_end()
    ri.cw.nl()


def print_req_policy_fwd(cw, struct, ri=None, terminate=True):
    if terminate and ri and policy_should_be_static(struct.family):
        return

    if terminate:
        prefix = 'extern '
    else:
        if ri and policy_should_be_static(struct.family):
            prefix = 'static '
        else:
            prefix = ''

    suffix = ';' if terminate else ' = {'

    max_attr = struct.attr_max_val
    if ri:
        name = ri.op.render_name
        if ri.op.dual_policy:
            name += '_' + ri.op_mode
    else:
        name = struct.render_name
    cw.p(f"{prefix}const struct nla_policy {name}_nl_policy[{max_attr.enum_name} + 1]{suffix}")


def print_req_policy(cw, struct, ri=None):
    if ri and ri.op:
        cw.ifdef_block(ri.op.get('config-cond', None))
    print_req_policy_fwd(cw, struct, ri=ri, terminate=False)
    for _, arg in struct.member_list():
        arg.attr_policy(cw)
    cw.p("};")
    cw.ifdef_block(None)
    cw.nl()


def kernel_can_gen_family_struct(family):
    return family.proto == 'genetlink'


def policy_should_be_static(family):
    return family.kernel_policy == 'split' or kernel_can_gen_family_struct(family)


def print_kernel_policy_ranges(family, cw):
    first = True
    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue

        for _, attr in attr_set.items():
            if not attr.request:
                continue
            if 'full-range' not in attr.checks:
                continue

            if first:
                cw.p('/* Integer value ranges */')
                first = False

            sign = '' if attr.type[0] == 'u' else '_signed'
            suffix = 'ULL' if attr.type[0] == 'u' else 'LL'
            cw.block_start(line=f'static const struct netlink_range_validation{sign} {c_lower(attr.enum_name)}_range =')
            members = []
            if 'min' in attr.checks:
                members.append(('min', attr.get_limit_str('min', suffix=suffix)))
            if 'max' in attr.checks:
                members.append(('max', attr.get_limit_str('max', suffix=suffix)))
            cw.write_struct_init(members)
            cw.block_end(line=';')
            cw.nl()


def print_kernel_policy_sparse_enum_validates(family, cw):
    first = True
    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue

        for _, attr in attr_set.items():
            if not attr.request:
                continue
            if not attr.enum_name:
                continue
            if 'sparse' not in attr.checks:
                continue

            if first:
                cw.p('/* Sparse enums validation callbacks */')
                first = False

            cw.write_func_prot('static int', f'{c_lower(attr.enum_name)}_validate',
                               ['const struct nlattr *attr', 'struct netlink_ext_ack *extack'])
            cw.block_start()
            cw.block_start(line=f'switch (nla_get_{attr["type"]}(attr))')
            enum = family.consts[attr['enum']]
            first_entry = True
            for entry in enum.entries.values():
                if first_entry:
                    first_entry = False
                else:
                    cw.p('fallthrough;')
                cw.p(f'case {entry.c_name}:')
            cw.p('return 0;')
            cw.block_end()
            cw.p('NL_SET_ERR_MSG_ATTR(extack, attr, "invalid enum value");')
            cw.p('return -EINVAL;')
            cw.block_end()
            cw.nl()


def print_kernel_op_table_fwd(family, cw, terminate):
    exported = not kernel_can_gen_family_struct(family)

    if not terminate or exported:
        cw.p(f"/* Ops table for {family.ident_name} */")

        pol_to_struct = {'global': 'genl_small_ops',
                         'per-op': 'genl_ops',
                         'split': 'genl_split_ops'}
        struct_type = pol_to_struct[family.kernel_policy]

        if not exported:
            cnt = ""
        elif family.kernel_policy == 'split':
            cnt = 0
            for op in family.ops.values():
                if 'do' in op:
                    cnt += 1
                if 'dump' in op:
                    cnt += 1
        else:
            cnt = len(family.ops)

        qual = 'static const' if not exported else 'const'
        line = f"{qual} struct {struct_type} {family.c_name}_nl_ops[{cnt}]"
        if terminate:
            cw.p(f"extern {line};")
        else:
            cw.block_start(line=line + ' =')

    if not terminate:
        return

    cw.nl()
    for name in family.hooks['pre']['do']['list']:
        cw.write_func_prot('int', c_lower(name),
                           ['const struct genl_split_ops *ops',
                            'struct sk_buff *skb', 'struct genl_info *info'], suffix=';')
    for name in family.hooks['post']['do']['list']:
        cw.write_func_prot('void', c_lower(name),
                           ['const struct genl_split_ops *ops',
                            'struct sk_buff *skb', 'struct genl_info *info'], suffix=';')
    for name in family.hooks['pre']['dump']['list']:
        cw.write_func_prot('int', c_lower(name),
                           ['struct netlink_callback *cb'], suffix=';')
    for name in family.hooks['post']['dump']['list']:
        cw.write_func_prot('int', c_lower(name),
                           ['struct netlink_callback *cb'], suffix=';')

    cw.nl()

    for op_name, op in family.ops.items():
        if op.is_async:
            continue

        if 'do' in op:
            name = c_lower(f"{family.fn_prefix}-{op_name}-doit")
            cw.write_func_prot('int', name,
                               ['struct sk_buff *skb', 'struct genl_info *info'], suffix=';')

        if 'dump' in op:
            name = c_lower(f"{family.fn_prefix}-{op_name}-dumpit")
            cw.write_func_prot('int', name,
                               ['struct sk_buff *skb', 'struct netlink_callback *cb'], suffix=';')
    cw.nl()


def print_kernel_op_table_hdr(family, cw):
    print_kernel_op_table_fwd(family, cw, terminate=True)


def print_kernel_op_table(family, cw):
    print_kernel_op_table_fwd(family, cw, terminate=False)
    if family.kernel_policy in ('global', 'per-op'):
        for op_name, op in family.ops.items():
            if op.is_async:
                continue

            cw.ifdef_block(op.get('config-cond', None))
            cw.block_start()
            members = [('cmd', op.enum_name)]
            if 'dont-validate' in op:
                members.append(('validate',
                                ' | '.join([c_upper('genl-dont-validate-' + x)
                                            for x in op['dont-validate']])), )
            for op_mode in ['do', 'dump']:
                if op_mode in op:
                    name = c_lower(f"{family.fn_prefix}-{op_name}-{op_mode}it")
                    members.append((op_mode + 'it', name))
            if family.kernel_policy == 'per-op':
                struct = Struct(family, op['attribute-set'],
                                type_list=op['do']['request']['attributes'])

                name = c_lower(f"{family.ident_name}-{op_name}-nl-policy")
                members.append(('policy', name))
                members.append(('maxattr', struct.attr_max_val.enum_name))
            if 'flags' in op:
                members.append(('flags', ' | '.join([c_upper('genl-' + x) for x in op['flags']])))
            cw.write_struct_init(members)
            cw.block_end(line=',')
    elif family.kernel_policy == 'split':
        cb_names = {'do':   {'pre': 'pre_doit', 'post': 'post_doit'},
                    'dump': {'pre': 'start', 'post': 'done'}}

        for op_name, op in family.ops.items():
            for op_mode in ['do', 'dump']:
                if op.is_async or op_mode not in op:
                    continue

                cw.ifdef_block(op.get('config-cond', None))
                cw.block_start()
                members = [('cmd', op.enum_name)]
                if 'dont-validate' in op:
                    dont_validate = []
                    for x in op['dont-validate']:
                        if op_mode == 'do' and x in ['dump', 'dump-strict']:
                            continue
                        if op_mode == "dump" and x == 'strict':
                            continue
                        dont_validate.append(x)

                    if dont_validate:
                        members.append(('validate',
                                        ' | '.join([c_upper('genl-dont-validate-' + x)
                                                    for x in dont_validate])), )
                name = c_lower(f"{family.fn_prefix}-{op_name}-{op_mode}it")
                if 'pre' in op[op_mode]:
                    members.append((cb_names[op_mode]['pre'], c_lower(op[op_mode]['pre'])))
                members.append((op_mode + 'it', name))
                if 'post' in op[op_mode]:
                    members.append((cb_names[op_mode]['post'], c_lower(op[op_mode]['post'])))
                if 'request' in op[op_mode]:
                    struct = Struct(family, op['attribute-set'],
                                    type_list=op[op_mode]['request']['attributes'])

                    if op.dual_policy:
                        name = c_lower(f"{family.ident_name}-{op_name}-{op_mode}-nl-policy")
                    else:
                        name = c_lower(f"{family.ident_name}-{op_name}-nl-policy")
                    members.append(('policy', name))
                    members.append(('maxattr', struct.attr_max_val.enum_name))
                flags = (op['flags'] if 'flags' in op else []) + ['cmd-cap-' + op_mode]
                members.append(('flags', ' | '.join([c_upper('genl-' + x) for x in flags])))
                cw.write_struct_init(members)
                cw.block_end(line=',')
    cw.ifdef_block(None)

    cw.block_end(line=';')
    cw.nl()


def print_kernel_mcgrp_hdr(family, cw):
    if not family.mcgrps['list']:
        return

    cw.block_start('enum')
    for grp in family.mcgrps['list']:
        grp_id = c_upper(f"{family.ident_name}-nlgrp-{grp['name']},")
        cw.p(grp_id)
    cw.block_end(';')
    cw.nl()


def print_kernel_mcgrp_src(family, cw):
    if not family.mcgrps['list']:
        return

    cw.block_start('static const struct genl_multicast_group ' + family.c_name + '_nl_mcgrps[] =')
    for grp in family.mcgrps['list']:
        name = grp['name']
        grp_id = c_upper(f"{family.ident_name}-nlgrp-{name}")
        cw.p('[' + grp_id + '] = { "' + name + '", },')
    cw.block_end(';')
    cw.nl()


def print_kernel_family_struct_hdr(family, cw):
    if not kernel_can_gen_family_struct(family):
        return

    cw.p(f"extern struct genl_family {family.c_name}_nl_family;")
    cw.nl()
    if 'sock-priv' in family.kernel_family:
        cw.p(f'void {family.c_name}_nl_sock_priv_init({family.kernel_family["sock-priv"]} *priv);')
        cw.p(f'void {family.c_name}_nl_sock_priv_destroy({family.kernel_family["sock-priv"]} *priv);')
        cw.nl()


def print_kernel_family_struct_src(family, cw):
    if not kernel_can_gen_family_struct(family):
        return

    if 'sock-priv' in family.kernel_family:
        # Generate "trampolines" to make CFI happy
        cw.write_func("static void", f"__{family.c_name}_nl_sock_priv_init",
                      [f"{family.c_name}_nl_sock_priv_init(priv);"],
                      ["void *priv"])
        cw.nl()
        cw.write_func("static void", f"__{family.c_name}_nl_sock_priv_destroy",
                      [f"{family.c_name}_nl_sock_priv_destroy(priv);"],
                      ["void *priv"])
        cw.nl()

    cw.block_start(f"struct genl_family {family.ident_name}_nl_family __ro_after_init =")
    cw.p('.name\t\t= ' + family.fam_key + ',')
    cw.p('.version\t= ' + family.ver_key + ',')
    cw.p('.netnsok\t= true,')
    cw.p('.parallel_ops\t= true,')
    cw.p('.module\t\t= THIS_MODULE,')
    if family.kernel_policy == 'per-op':
        cw.p(f'.ops\t\t= {family.c_name}_nl_ops,')
        cw.p(f'.n_ops\t\t= ARRAY_SIZE({family.c_name}_nl_ops),')
    elif family.kernel_policy == 'split':
        cw.p(f'.split_ops\t= {family.c_name}_nl_ops,')
        cw.p(f'.n_split_ops\t= ARRAY_SIZE({family.c_name}_nl_ops),')
    if family.mcgrps['list']:
        cw.p(f'.mcgrps\t\t= {family.c_name}_nl_mcgrps,')
        cw.p(f'.n_mcgrps\t= ARRAY_SIZE({family.c_name}_nl_mcgrps),')
    if 'sock-priv' in family.kernel_family:
        cw.p(f'.sock_priv_size\t= sizeof({family.kernel_family["sock-priv"]}),')
        cw.p(f'.sock_priv_init\t= __{family.c_name}_nl_sock_priv_init,')
        cw.p(f'.sock_priv_destroy = __{family.c_name}_nl_sock_priv_destroy,')
    cw.block_end(';')


def uapi_enum_start(family, cw, obj, ckey='', enum_name='enum-name'):
    start_line = 'enum'
    if enum_name in obj:
        if obj[enum_name]:
            start_line = 'enum ' + c_lower(obj[enum_name])
    elif ckey and ckey in obj:
        start_line = 'enum ' + family.c_name + '_' + c_lower(obj[ckey])
    cw.block_start(line=start_line)


def render_uapi_unified(family, cw, max_by_define, separate_ntf):
    max_name = c_upper(family.get('cmd-max-name', f"{family.op_prefix}MAX"))
    cnt_name = c_upper(family.get('cmd-cnt-name', f"__{family.op_prefix}MAX"))
    max_value = f"({cnt_name} - 1)"

    uapi_enum_start(family, cw, family['operations'], 'enum-name')
    val = 0
    for op in family.msgs.values():
        if separate_ntf and ('notify' in op or 'event' in op):
            continue

        suffix = ','
        if op.value != val:
            suffix = f" = {op.value},"
            val = op.value
        cw.p(op.enum_name + suffix)
        val += 1
    cw.nl()
    cw.p(cnt_name + ('' if max_by_define else ','))
    if not max_by_define:
        cw.p(f"{max_name} = {max_value}")
    cw.block_end(line=';')
    if max_by_define:
        cw.p(f"#define {max_name} {max_value}")
    cw.nl()


def render_uapi_directional(family, cw, max_by_define):
    max_name = f"{family.op_prefix}USER_MAX"
    cnt_name = f"__{family.op_prefix}USER_CNT"
    max_value = f"({cnt_name} - 1)"

    cw.block_start(line='enum')
    cw.p(c_upper(f'{family.name}_MSG_USER_NONE = 0,'))
    val = 0
    for op in family.msgs.values():
        if 'do' in op and 'event' not in op:
            suffix = ','
            if op.value and op.value != val:
                suffix = f" = {op.value},"
                val = op.value
            cw.p(op.enum_name + suffix)
            val += 1
    cw.nl()
    cw.p(cnt_name + ('' if max_by_define else ','))
    if not max_by_define:
        cw.p(f"{max_name} = {max_value}")
    cw.block_end(line=';')
    if max_by_define:
        cw.p(f"#define {max_name} {max_value}")
    cw.nl()

    max_name = f"{family.op_prefix}KERNEL_MAX"
    cnt_name = f"__{family.op_prefix}KERNEL_CNT"
    max_value = f"({cnt_name} - 1)"

    cw.block_start(line='enum')
    cw.p(c_upper(f'{family.name}_MSG_KERNEL_NONE = 0,'))
    val = 0
    for op in family.msgs.values():
        if ('do' in op and 'reply' in op['do']) or 'notify' in op or 'event' in op:
            enum_name = op.enum_name
            if 'event' not in op and 'notify' not in op:
                enum_name = f'{enum_name}_REPLY'

            suffix = ','
            if op.value and op.value != val:
                suffix = f" = {op.value},"
                val = op.value
            cw.p(enum_name + suffix)
            val += 1
    cw.nl()
    cw.p(cnt_name + ('' if max_by_define else ','))
    if not max_by_define:
        cw.p(f"{max_name} = {max_value}")
    cw.block_end(line=';')
    if max_by_define:
        cw.p(f"#define {max_name} {max_value}")
    cw.nl()


def render_uapi(family, cw):
    hdr_prot = f"_UAPI_LINUX_{c_upper(family.uapi_header_name)}_H"
    hdr_prot = hdr_prot.replace('/', '_')
    cw.p('#ifndef ' + hdr_prot)
    cw.p('#define ' + hdr_prot)
    cw.nl()

    defines = [(family.fam_key, family["name"]),
               (family.ver_key, family.get('version', 1))]
    cw.writes_defines(defines)
    cw.nl()

    defines = []
    for const in family['definitions']:
        if const.get('header'):
            continue

        if const['type'] != 'const':
            cw.writes_defines(defines)
            defines = []
            cw.nl()

        # Write kdoc for enum and flags (one day maybe also structs)
        if const['type'] == 'enum' or const['type'] == 'flags':
            enum = family.consts[const['name']]

            if enum.header:
                continue

            if enum.has_doc():
                if enum.has_entry_doc():
                    cw.p('/**')
                    doc = ''
                    if 'doc' in enum:
                        doc = ' - ' + enum['doc']
                    cw.write_doc_line(enum.enum_name + doc)
                else:
                    cw.p('/*')
                    cw.write_doc_line(enum['doc'], indent=False)
                for entry in enum.entries.values():
                    if entry.has_doc():
                        doc = '@' + entry.c_name + ': ' + entry['doc']
                        cw.write_doc_line(doc)
                cw.p(' */')

            uapi_enum_start(family, cw, const, 'name')
            name_pfx = const.get('name-prefix', f"{family.ident_name}-{const['name']}-")
            for entry in enum.entries.values():
                suffix = ','
                if entry.value_change:
                    suffix = f" = {entry.user_value()}" + suffix
                cw.p(entry.c_name + suffix)

            if const.get('render-max', False):
                cw.nl()
                cw.p('/* private: */')
                if const['type'] == 'flags':
                    max_name = c_upper(name_pfx + 'mask')
                    max_val = f' = {enum.get_mask()},'
                    cw.p(max_name + max_val)
                else:
                    cnt_name = enum.enum_cnt_name
                    max_name = c_upper(name_pfx + 'max')
                    if not cnt_name:
                        cnt_name = '__' + name_pfx + 'max'
                    cw.p(c_upper(cnt_name) + ',')
                    cw.p(max_name + ' = (' + c_upper(cnt_name) + ' - 1)')
            cw.block_end(line=';')
            cw.nl()
        elif const['type'] == 'const':
            name_pfx = const.get('name-prefix', f"{family.ident_name}-")
            defines.append([c_upper(family.get('c-define-name',
                                               f"{name_pfx}{const['name']}")),
                            const['value']])

    if defines:
        cw.writes_defines(defines)
        cw.nl()

    max_by_define = family.get('max-by-define', False)

    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue

        max_value = f"({attr_set.cnt_name} - 1)"

        val = 0
        uapi_enum_start(family, cw, attr_set.yaml, 'enum-name')
        for _, attr in attr_set.items():
            suffix = ','
            if attr.value != val:
                suffix = f" = {attr.value},"
                val = attr.value
            val += 1
            cw.p(attr.enum_name + suffix)
        if attr_set.items():
            cw.nl()
        cw.p(attr_set.cnt_name + ('' if max_by_define else ','))
        if not max_by_define:
            cw.p(f"{attr_set.max_name} = {max_value}")
        cw.block_end(line=';')
        if max_by_define:
            cw.p(f"#define {attr_set.max_name} {max_value}")
        cw.nl()

    # Commands
    separate_ntf = 'async-prefix' in family['operations']

    if family.msg_id_model == 'unified':
        render_uapi_unified(family, cw, max_by_define, separate_ntf)
    elif family.msg_id_model == 'directional':
        render_uapi_directional(family, cw, max_by_define)
    else:
        raise Exception(f'Unsupported message enum-model {family.msg_id_model}')

    if separate_ntf:
        uapi_enum_start(family, cw, family['operations'], enum_name='async-enum')
        for op in family.msgs.values():
            if separate_ntf and not ('notify' in op or 'event' in op):
                continue

            suffix = ','
            if 'value' in op:
                suffix = f" = {op['value']},"
            cw.p(op.enum_name + suffix)
        cw.block_end(line=';')
        cw.nl()

    # Multicast
    defines = []
    for grp in family.mcgrps['list']:
        name = grp['name']
        defines.append([c_upper(grp.get('c-define-name', f"{family.ident_name}-mcgrp-{name}")),
                        f'{name}'])
    cw.nl()
    if defines:
        cw.writes_defines(defines)
        cw.nl()

    cw.p(f'#endif /* {hdr_prot} */')


def _render_user_ntf_entry(ri, op):
    if not ri.family.is_classic():
        ri.cw.block_start(line=f"[{op.enum_name}] = ")
    else:
        crud_op = ri.family.req_by_value[op.rsp_value]
        ri.cw.block_start(line=f"[{crud_op.enum_name}] = ")
    ri.cw.p(f".alloc_sz\t= sizeof({type_name(ri, 'event')}),")
    ri.cw.p(f".cb\t\t= {op_prefix(ri, 'reply', deref=True)}_parse,")
    ri.cw.p(f".policy\t\t= &{ri.struct['reply'].render_name}_nest,")
    ri.cw.p(f".free\t\t= (void *){op_prefix(ri, 'notify')}_free,")
    ri.cw.block_end(line=',')


def render_user_family(family, cw, prototype):
    symbol = f'const struct ynl_family ynl_{family.c_name}_family'
    if prototype:
        cw.p(f'extern {symbol};')
        return

    if family.ntfs:
        cw.block_start(line=f"static const struct ynl_ntf_info {family.c_name}_ntf_info[] = ")
        for ntf_op_name, ntf_op in family.ntfs.items():
            if 'notify' in ntf_op:
                op = family.ops[ntf_op['notify']]
                ri = RenderInfo(cw, family, "user", op, "notify")
            elif 'event' in ntf_op:
                ri = RenderInfo(cw, family, "user", ntf_op, "event")
            else:
                raise Exception('Invalid notification ' + ntf_op_name)
            _render_user_ntf_entry(ri, ntf_op)
        for _op_name, op in family.ops.items():
            if 'event' not in op:
                continue
            ri = RenderInfo(cw, family, "user", op, "event")
            _render_user_ntf_entry(ri, op)
        cw.block_end(line=";")
        cw.nl()

    cw.block_start(f'{symbol} = ')
    cw.p(f'.name\t\t= "{family.c_name}",')
    if family.is_classic():
        cw.p('.is_classic\t= true,')
        cw.p(f'.classic_id\t= {family.get("protonum")},')
    if family.is_classic():
        if family.fixed_header:
            cw.p(f'.hdr_len\t= sizeof(struct {c_lower(family.fixed_header)}),')
    elif family.fixed_header:
        cw.p(f'.hdr_len\t= sizeof(struct genlmsghdr) + sizeof(struct {c_lower(family.fixed_header)}),')
    else:
        cw.p('.hdr_len\t= sizeof(struct genlmsghdr),')
    if family.ntfs:
        cw.p(f".ntf_info\t= {family.c_name}_ntf_info,")
        cw.p(f".ntf_info_size\t= YNL_ARRAY_SIZE({family.c_name}_ntf_info),")
    cw.block_end(line=';')


def family_contains_bitfield32(family):
    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue
        for _, attr in attr_set.items():
            if attr.type == "bitfield32":
                return True
    return False


def find_kernel_root(full_path):
    sub_path = ''
    while True:
        sub_path = os.path.join(os.path.basename(full_path), sub_path)
        full_path = os.path.dirname(full_path)
        maintainers = os.path.join(full_path, "MAINTAINERS")
        if os.path.exists(maintainers):
            return full_path, sub_path[:-1]


def main():
    parser = argparse.ArgumentParser(description='Netlink simple parsing generator')
    parser.add_argument('--mode', dest='mode', type=str, required=True,
                        choices=('user', 'kernel', 'uapi'))
    parser.add_argument('--spec', dest='spec', type=str, required=True)
    parser.add_argument('--header', dest='header', action='store_true', default=None)
    parser.add_argument('--source', dest='header', action='store_false')
    parser.add_argument('--user-header', nargs='+', default=[])
    parser.add_argument('--cmp-out', action='store_true', default=None,
                        help='Do not overwrite the output file if the new output is identical to the old')
    parser.add_argument('--exclude-op', action='append', default=[])
    parser.add_argument('-o', dest='out_file', type=str, default=None)
    parser.add_argument('--function-prefix', dest='fn_prefix', type=str)
    args = parser.parse_args()

    if args.header is None:
        parser.error("--header or --source is required")

    exclude_ops = [re.compile(expr) for expr in args.exclude_op]

    try:
        parsed = Family(args.spec, exclude_ops, args.fn_prefix)
        if parsed.license != '((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)':
            print('Spec license:', parsed.license)
            print('License must be: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)')
            os.sys.exit(1)
    except pyyaml.YAMLError as exc:
        print(exc)
        os.sys.exit(1)

    cw = CodeWriter(BaseNlLib(), args.out_file, overwrite=not args.cmp_out)

    _, spec_kernel = find_kernel_root(args.spec)
    if args.mode == 'uapi' or args.header:
        cw.p(f'/* SPDX-License-Identifier: {parsed.license} */')
    else:
        cw.p(f'// SPDX-License-Identifier: {parsed.license}')
    cw.p("/* Do not edit directly, auto-generated from: */")
    cw.p(f"/*\t{spec_kernel} */")
    cw.p(f"/* YNL-GEN {args.mode} {'header' if args.header else 'source'} */")
    if args.exclude_op or args.user_header or args.fn_prefix:
        line = ''
        if args.user_header:
            line += ' --user-header '.join([''] + args.user_header)
        if args.exclude_op:
            line += ' --exclude-op '.join([''] + args.exclude_op)
        if args.fn_prefix:
            line += f' --function-prefix {args.fn_prefix}'
        cw.p(f'/* YNL-ARG{line} */')
    cw.p('/* To regenerate run: tools/net/ynl/ynl-regen.sh */')
    cw.nl()

    if args.mode == 'uapi':
        render_uapi(parsed, cw)
        return

    hdr_prot = f"_LINUX_{parsed.c_name.upper()}_GEN_H"
    if args.header:
        cw.p('#ifndef ' + hdr_prot)
        cw.p('#define ' + hdr_prot)
        cw.nl()

    if args.out_file:
        hdr_file = os.path.basename(args.out_file[:-2]) + ".h"
    else:
        hdr_file = "generated_header_file.h"

    if args.mode == 'kernel':
        cw.p('#include <net/netlink.h>')
        cw.p('#include <net/genetlink.h>')
        cw.nl()
        if not args.header:
            if args.out_file:
                cw.p(f'#include "{hdr_file}"')
            cw.nl()
        headers = ['uapi/' + parsed.uapi_header]
        headers += parsed.kernel_family.get('headers', [])
    else:
        cw.p('#include <stdlib.h>')
        cw.p('#include <string.h>')
        if args.header:
            cw.p('#include <linux/types.h>')
            if family_contains_bitfield32(parsed):
                cw.p('#include <linux/netlink.h>')
        else:
            cw.p(f'#include "{hdr_file}"')
            cw.p('#include "ynl.h"')
        headers = []
    for definition in parsed['definitions'] + parsed['attribute-sets']:
        if 'header' in definition:
            headers.append(definition['header'])
    if args.mode == 'user':
        headers.append(parsed.uapi_header)
    seen_header = []
    for one in headers:
        if one not in seen_header:
            cw.p(f"#include <{one}>")
            seen_header.append(one)
    cw.nl()

    if args.mode == "user":
        if not args.header:
            cw.p("#include <linux/genetlink.h>")
            cw.nl()
            for one in args.user_header:
                cw.p(f'#include "{one}"')
        else:
            cw.p('struct ynl_sock;')
            cw.nl()
            render_user_family(parsed, cw, True)
        cw.nl()

    if args.mode == "kernel":
        if args.header:
            for _, struct in sorted(parsed.pure_nested_structs.items()):
                if struct.request:
                    cw.p('/* Common nested types */')
                    break
            for attr_set, struct in sorted(parsed.pure_nested_structs.items()):
                if struct.request:
                    print_req_policy_fwd(cw, struct)
            cw.nl()

            if parsed.kernel_policy == 'global':
                cw.p(f"/* Global operation policy for {parsed.name} */")

                struct = Struct(parsed, parsed.global_policy_set, type_list=parsed.global_policy)
                print_req_policy_fwd(cw, struct)
                cw.nl()

            if parsed.kernel_policy in {'per-op', 'split'}:
                for _op_name, op in parsed.ops.items():
                    if 'do' in op and 'event' not in op:
                        ri = RenderInfo(cw, parsed, args.mode, op, "do")
                        print_req_policy_fwd(cw, ri.struct['request'], ri=ri)
                        cw.nl()

            print_kernel_op_table_hdr(parsed, cw)
            print_kernel_mcgrp_hdr(parsed, cw)
            print_kernel_family_struct_hdr(parsed, cw)
        else:
            print_kernel_policy_ranges(parsed, cw)
            print_kernel_policy_sparse_enum_validates(parsed, cw)

            for _, struct in sorted(parsed.pure_nested_structs.items()):
                if struct.request:
                    cw.p('/* Common nested types */')
                    break
            for attr_set, struct in sorted(parsed.pure_nested_structs.items()):
                if struct.request:
                    print_req_policy(cw, struct)
            cw.nl()

            if parsed.kernel_policy == 'global':
                cw.p(f"/* Global operation policy for {parsed.name} */")

                struct = Struct(parsed, parsed.global_policy_set, type_list=parsed.global_policy)
                print_req_policy(cw, struct)
                cw.nl()

            for _op_name, op in parsed.ops.items():
                if parsed.kernel_policy in {'per-op', 'split'}:
                    for op_mode in ['do', 'dump']:
                        if op_mode in op and 'request' in op[op_mode]:
                            cw.p(f"/* {op.enum_name} - {op_mode} */")
                            ri = RenderInfo(cw, parsed, args.mode, op, op_mode)
                            print_req_policy(cw, ri.struct['request'], ri=ri)
                            cw.nl()

            print_kernel_op_table(parsed, cw)
            print_kernel_mcgrp_src(parsed, cw)
            print_kernel_family_struct_src(parsed, cw)

    if args.mode == "user":
        if args.header:
            cw.p('/* Enums */')
            put_op_name_fwd(parsed, cw)

            for name, const in parsed.consts.items():
                if isinstance(const, EnumSet):
                    put_enum_to_str_fwd(parsed, cw, const)
            cw.nl()

            cw.p('/* Common nested types */')
            for attr_set, struct in parsed.pure_nested_structs.items():
                ri = RenderInfo(cw, parsed, args.mode, "", "", attr_set)
                print_type_full(ri, struct)

            for _op_name, op in parsed.ops.items():
                cw.p(f"/* ============== {op.enum_name} ============== */")

                if 'do' in op and 'event' not in op:
                    cw.p(f"/* {op.enum_name} - do */")
                    ri = RenderInfo(cw, parsed, args.mode, op, "do")
                    print_req_type(ri)
                    print_req_type_helpers(ri)
                    cw.nl()
                    print_rsp_type(ri)
                    print_rsp_type_helpers(ri)
                    cw.nl()
                    print_req_prototype(ri)
                    cw.nl()

                if 'dump' in op:
                    cw.p(f"/* {op.enum_name} - dump */")
                    ri = RenderInfo(cw, parsed, args.mode, op, 'dump')
                    print_req_type(ri)
                    print_req_type_helpers(ri)
                    if not ri.type_consistent or ri.type_oneside:
                        print_rsp_type(ri)
                    print_wrapped_type(ri)
                    print_dump_prototype(ri)
                    cw.nl()

                if op.has_ntf:
                    cw.p(f"/* {op.enum_name} - notify */")
                    ri = RenderInfo(cw, parsed, args.mode, op, 'notify')
                    if not ri.type_consistent:
                        raise Exception(f'Only notifications with consistent types supported ({op.name})')
                    print_wrapped_type(ri)

            for _op_name, op in parsed.ntfs.items():
                if 'event' in op:
                    ri = RenderInfo(cw, parsed, args.mode, op, 'event')
                    cw.p(f"/* {op.enum_name} - event */")
                    print_rsp_type(ri)
                    cw.nl()
                    print_wrapped_type(ri)
            cw.nl()
        else:
            cw.p('/* Enums */')
            put_op_name(parsed, cw)

            for name, const in parsed.consts.items():
                if isinstance(const, EnumSet):
                    put_enum_to_str(parsed, cw, const)
            cw.nl()

            has_recursive_nests = False
            cw.p('/* Policies */')
            for struct in parsed.pure_nested_structs.values():
                if struct.recursive:
                    put_typol_fwd(cw, struct)
                    has_recursive_nests = True
            if has_recursive_nests:
                cw.nl()
            for struct in parsed.pure_nested_structs.values():
                put_typol(cw, struct)
            for name in parsed.root_sets:
                struct = Struct(parsed, name)
                put_typol(cw, struct)

            cw.p('/* Common nested types */')
            if has_recursive_nests:
                for attr_set, struct in parsed.pure_nested_structs.items():
                    ri = RenderInfo(cw, parsed, args.mode, "", "", attr_set)
                    free_rsp_nested_prototype(ri)
                    if struct.request:
                        put_req_nested_prototype(ri, struct)
                    if struct.reply:
                        parse_rsp_nested_prototype(ri, struct)
                cw.nl()
            for attr_set, struct in parsed.pure_nested_structs.items():
                ri = RenderInfo(cw, parsed, args.mode, "", "", attr_set)

                free_rsp_nested(ri, struct)
                if struct.request:
                    put_req_nested(ri, struct)
                if struct.reply:
                    parse_rsp_nested(ri, struct)

            for _op_name, op in parsed.ops.items():
                cw.p(f"/* ============== {op.enum_name} ============== */")
                if 'do' in op and 'event' not in op:
                    cw.p(f"/* {op.enum_name} - do */")
                    ri = RenderInfo(cw, parsed, args.mode, op, "do")
                    print_req_free(ri)
                    print_rsp_free(ri)
                    parse_rsp_msg(ri)
                    print_req(ri)
                    cw.nl()

                if 'dump' in op:
                    cw.p(f"/* {op.enum_name} - dump */")
                    ri = RenderInfo(cw, parsed, args.mode, op, "dump")
                    if not ri.type_consistent or ri.type_oneside:
                        parse_rsp_msg(ri, deref=True)
                    print_req_free(ri)
                    print_dump_type_free(ri)
                    print_dump(ri)
                    cw.nl()

                if op.has_ntf:
                    cw.p(f"/* {op.enum_name} - notify */")
                    ri = RenderInfo(cw, parsed, args.mode, op, 'notify')
                    if not ri.type_consistent:
                        raise Exception(f'Only notifications with consistent types supported ({op.name})')
                    print_ntf_type_free(ri)

            for _op_name, op in parsed.ntfs.items():
                if 'event' in op:
                    cw.p(f"/* {op.enum_name} - event */")

                    ri = RenderInfo(cw, parsed, args.mode, op, "do")
                    parse_rsp_msg(ri)

                    ri = RenderInfo(cw, parsed, args.mode, op, "event")
                    print_ntf_type_free(ri)
            cw.nl()
            render_user_family(parsed, cw, False)

    if args.header:
        cw.p(f'#endif /* {hdr_prot} */')


if __name__ == "__main__":
    main()
