#!/usr/bin/env python3
# SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
#
# pylint: disable=too-many-branches, too-many-statements, missing-function-docstring
# pylint: disable=too-many-locals


"""
ynl_gen_strace.py

A code generator for creating strace modules to decode netlink families.
"""

import argparse
import os
import yaml

from lib import c_upper, c_lower, TypeUnused, TypeNest, TypeIndexedArray, \
    TypeFlag, TypeString, TypeBinary, TypeScalar, CodeWriter, Family, \
    BaseNlLib


def render_strace(family, cw):

    xlat_headers = []

    # xlat for definitions

    defines = []
    for const in family['definitions']:
        if const['type'] != 'const':
            cw.writes_defines(defines)
            defines = []
            cw.nl()

        if const['type'] == 'enum' or const['type'] == 'flags':
            enum = family.consts[const['name']]

            xlat_name = f"{family.name}_{c_lower(const['name'])}"
            xlat_headers.append(xlat_name)

            cw.p(f"// For src/xlat/{xlat_name}.in")
            cw.p('#unconditional')
            if const['type'] == 'enum':
                cw.p('#value_indexed')

            name_pfx = const.get('name-prefix', f"{family.name}-{const['name']}-")
            for entry in enum.entries.values():
                cw.p(entry.c_name)

            cw.nl()
        elif const['type'] == 'const':
            defines.append([c_upper(family.get('c-define-name',
                                               f"{family.name}-{const['name']}")),
                            const['value']])

    if defines:
        cw.writes_defines(defines)
        cw.nl()

    # xlat for attrs

    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue

        xlat_name = c_lower(attr_set.yaml['enum-name'])
        xlat_headers.append(xlat_name)

        cw.p(f"// For src/xlat/{xlat_name}.in")
        cw.p('#unconditional')
        cw.p('#value_indexed')

        for _, attr in attr_set.items():
            cw.p(attr.enum_name)
        cw.nl()

    # xlat for commands

    separate_ntf = 'async-prefix' in family['operations']

    xlat_name = f"{family.name}_cmds"
    xlat_headers.append(xlat_name)

    cw.p(f"// For src/xlat/{xlat_name}.in")
    cw.p('#unconditional')
    cw.p('#value_indexed')

    for op in family.msgs.values():
        if separate_ntf and ('notify' in op or 'event' in op):
            continue

        cw.p(op.enum_name)
    cw.nl()

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

    cw.nl()
    if defines:
        cw.writes_defines(defines)
        cw.nl()

    # Bind into netlink_generic.(c|h)

    cw.p('// Add to src/netlink_generic.h')
    cw.p(f"extern DECL_NETLINK_GENERIC_DECODER(decode_{family.name}_msg);")
    cw.nl()

    cw.p('// Add to src/netlink_generic.c in genl_decoders[]')
    cw.p(f"""\t{{ "{family.name}", decode_{family.name}_msg }},""")
    cw.nl()

    # strace Makefile

    cw.p('// Add to src/Makefile.am in libstrace_a_SOURCES')
    cw.p(f"\t{family.name}.c \\")
    cw.nl()

    # Start of C source file

    cw.p(f"// For src/{family.name}.c")
    cw.nl()

    cw.p('#include "defs.h"')
    cw.p('#include "netlink.h"')
    cw.p('#include "nlattr.h"')
    cw.p('#include <linux/genetlink.h>')
    cw.p(f"#include <{family['uapi-header']}>")
    cw.p('#include "netlink_generic.h"')
    for h in xlat_headers:
        cw.p(f"#include \"xlat/{h}.h\"")
    cw.nl()

    # C code for flags, enum and struct decoders

    for defn in family['definitions']:
        if defn['type'] in [ 'flags', 'enum' ]:
            prefix = defn.get('name-prefix', f"{family.name}-{defn['name']}-")

            cw.p('static bool')
            cw.p(f"decode_{c_lower(defn['name'])}(struct tcb *const tcp,")
            cw.p("\t\tconst kernel_ulong_t addr,")
            cw.p("\t\tconst unsigned int len,")
            cw.p("\t\tconst void *const opaque_data)")
            cw.block_start()
            cw.block_start("static const struct decode_nla_xlat_opts opts =")
            cw.p(f"""{family.name}_{c_lower(defn['name'])}, "{c_upper(prefix)}???", .size = 4""")
            cw.block_end(';')
            decoder = 'xval' if defn['type'] == 'enum' else 'flags'
            cw.p(f"return decode_nla_{decoder}(tcp, addr, len, &opts);")
            cw.block_end()

        elif defn['type'] == 'struct':
            struct_name = c_lower(defn['enum-name'] if 'enum-name' in defn else defn['name'])
            var_name = c_lower(defn['name'])

            cw.p('static bool')
            cw.p(f"decode_{struct_name}(struct tcb *const tcp,")
            cw.p("\t\tconst kernel_ulong_t addr,")
            cw.p("\t\tconst unsigned int len,")
            cw.p("\t\tconst void *const opaque_data)")
            cw.block_start()

            cw.p(f"struct {struct_name} {var_name};")
            cw.p(f"umove_or_printaddr(tcp, addr, &{var_name});")
            cw.nl()

            for m in defn['members']:
                if m['name'].startswith('pad'):
                    continue
                cw.p(f"PRINT_FIELD_U({var_name}, {c_lower(m['name'])});")
                cw.p('tprint_struct_next();')

            cw.p('return true;')
            cw.block_end()

        cw.nl()

    # C code for attribute set decoders

    for _, attr_set in family.attr_sets.items():
        if attr_set.subset_of:
            continue

        # Emit nested attr decoders before referencing them

        for _, attr in attr_set.items():
            if type(attr) in [ TypeNest, TypeIndexedArray ]:
                decoder = f"decode_{c_lower(attr.enum_name)}"
                nested_set = family.attr_sets[attr['nested-attributes']]
                nested_attrs = f"{c_lower(nested_set.yaml['enum-name'])}"
                name_prefix = nested_set.yaml.get('name-prefix',
                                                  f"{family.name}-{nested_set.name}-")
                attr_prefix = f"{c_upper(name_prefix)}"
                decoder_array = f"{c_lower(nested_set.name)}_attr_decoders"
                array_nest = "_item" if type(attr) == TypeIndexedArray else ""

                cw.p('static bool')
                cw.p(f"{decoder}{array_nest}(struct tcb *const tcp,")
                cw.p("\tconst kernel_ulong_t addr,")
                cw.p("\tconst unsigned int len,")
                cw.p("\tconst void *const opaque_data)")
                cw.block_start()
                cw.p(f"decode_nlattr(tcp, addr, len, {nested_attrs},")
                cw.p(f"\t\"{attr_prefix}???\",")
                cw.p(f"\tARRSZ_PAIR({decoder_array}),")
                cw.p("\tNULL);")
                cw.p('return true;')
                cw.block_end()
                cw.nl()

            if type(attr) == TypeIndexedArray:
                cw.p('static bool')
                cw.p(f"{decoder}(struct tcb *const tcp,")
                cw.p("\tconst kernel_ulong_t addr,")
                cw.p("\tconst unsigned int len,")
                cw.p("\tconst void *const opaque_data)")
                cw.block_start()
                cw.p(f"nla_decoder_t decoder = &{decoder}_item;")
                cw.p('decode_nlattr(tcp, addr, len, NULL, NULL, &decoder, 0, NULL);')
                cw.p('return true;')
                cw.block_end()
                cw.nl()

        # Then emit the decoders array

        cw.block_start(f"static const nla_decoder_t {c_lower(attr_set.name)}_attr_decoders[] =")
        for _, attr in attr_set.items():
            if type(attr) in [ TypeUnused, TypeFlag ]:
                decoder = 'NULL'
            elif type(attr) == TypeString:
                decoder = 'decode_nla_str'
            elif type(attr) == TypeBinary:
                decoder = 'NULL'
                if 'struct' in attr.yaml:
                    defn = family.consts[attr.yaml['struct']]
                    enum_name = c_lower(defn.get('enum-name', defn.name))
                    decoder = f"decode_{enum_name}"
            elif type(attr) == TypeNest:
                decoder = f"decode_{c_lower(attr.enum_name)}"
            elif type(attr) == TypeScalar and 'enum' in attr:
                decoder = f"decode_{c_lower(attr['enum'])}"
            else:
                decoder = f"decode_nla_{attr.type}"

            cw.p(f"[{attr.enum_name}] = {decoder},")
        cw.block_end(';')
        cw.nl()

    # C code for top-level decoder

    for op in family.msgs.values():
        cmd_prefix = c_upper(family.yaml['operations']['name-prefix'])
        attr_set_name = op.yaml['attribute-set']
        attr_set = family.attr_sets[attr_set_name]
        name_prefix = c_upper(attr_set.yaml.get('name-prefix', attr_set_name))
        enum_name = c_lower(attr_set.yaml['enum-name'])

        cw.block_start(f"DECL_NETLINK_GENERIC_DECODER(decode_{family.name}_msg)")

        if op.fixed_header:
            defn = family.consts[op.fixed_header]
            header_name = c_lower(defn['name'])
            cw.p(f"struct {header_name} header;")
            cw.p(f"size_t offset = sizeof(struct {header_name});")
            cw.nl()

        cw.p('tprint_struct_begin();')
        cw.p(f"""PRINT_FIELD_XVAL(*genl, cmd, {family.name}_cmds, "{cmd_prefix}???");""")
        cw.p('tprint_struct_next();')
        cw.p('PRINT_FIELD_U(*genl, version);')
        cw.p('tprint_struct_next();')

        if op.fixed_header:
            cw.p('if (umove_or_printaddr(tcp, addr, &header))')
            cw.p('return;')
            for m in defn.members:
                cw.p(f"PRINT_FIELD_U(header, {c_lower(m.name)});")
                cw.p('tprint_struct_next();')
            cw.nl()
            cw.p(f"decode_nlattr(tcp, addr + offset, len - offset,")
        else:
            cw.p(f"decode_nlattr(tcp, addr, len,")

        cw.p(f"\t{enum_name},")
        cw.p(f"\t\"{name_prefix}???\",")
        cw.p(f"\tARRSZ_PAIR({c_lower(attr_set_name)}_attr_decoders),")
        cw.p("\tNULL);")
        cw.p('tprint_struct_end();')
        cw.block_end()
        break


def main():
    parser = argparse.ArgumentParser(description='Netlink strace parsing generator')
    parser.add_argument('--spec', dest='spec', type=str, required=True)
    parser.add_argument('-o', dest='out_file', type=str)
    args = parser.parse_args()

    out_file = open(args.out_file, 'w+') if args.out_file else os.sys.stdout

    try:
        parsed = Family(args.spec, [], "")
        if parsed.license != '((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)':
            print('Spec license:', parsed.license)
            print('License must be: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)')
            os.sys.exit(1)
    except yaml.YAMLError as exc:
        print(exc)
        os.sys.exit(1)

    cw = CodeWriter(BaseNlLib(), out_file)

    render_strace(parsed, cw)


if __name__ == "__main__":
    main()
