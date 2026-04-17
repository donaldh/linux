# SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#
# pylint: disable=missing-class-docstring, missing-function-docstring
# pylint: disable=too-many-arguments, too-many-instance-attributes
# pylint: disable=too-many-positional-arguments

"""
CodeWriter: A code emitter for C-like code generatiob
"""

import filecmp
import os
import pathlib
import shutil
import sys
import tempfile

# pylint: disable=no-name-in-module,wrong-import-position
sys.path.append(pathlib.Path(__file__).resolve().parent.as_posix())


class CodeWriter:
    def __init__(self, nlib, out_file=None, overwrite=True):
        self.nlib = nlib
        self._overwrite = overwrite

        self._nl = False
        self._block_end = False
        self._silent_block = False
        self._ind = 0
        self._ifdef_block = None
        if out_file is None:
            self._out = os.sys.stdout
        else:
            # pylint: disable=consider-using-with
            self._out = tempfile.NamedTemporaryFile('w+')
            self._out_file = out_file

    def __del__(self):
        self.close_out_file()

    def close_out_file(self):
        if self._out == os.sys.stdout:
            return
        # Avoid modifying the file if contents didn't change
        self._out.flush()
        if not self._overwrite and os.path.isfile(self._out_file):
            if filecmp.cmp(self._out.name, self._out_file, shallow=False):
                return
        with open(self._out_file, 'w+', encoding='utf-8') as out_file:
            self._out.seek(0)
            shutil.copyfileobj(self._out, out_file)
            self._out.close()
        self._out = os.sys.stdout

    @classmethod
    def _is_cond(cls, line):
        return line.startswith('if') or line.startswith('while') or line.startswith('for')

    def p(self, line, add_ind=0):
        if self._block_end:
            self._block_end = False
            if line.startswith('else'):
                line = '} ' + line
            else:
                self._out.write('\t' * self._ind + '}\n')

        if self._nl:
            self._out.write('\n')
            self._nl = False

        ind = self._ind
        if line[-1] == ':':
            ind -= 1
        if self._silent_block:
            ind += 1
        self._silent_block = line.endswith(')') and CodeWriter._is_cond(line)
        self._silent_block |= line.strip() == 'else'
        if line[0] == '#':
            ind = 0
        if add_ind:
            ind += add_ind
        self._out.write('\t' * ind + line + '\n')

    def nl(self):
        self._nl = True

    def block_start(self, line=''):
        if line:
            line = line + ' '
        self.p(line + '{')
        self._ind += 1

    def block_end(self, line=''):
        if line and line[0] not in {';', ','}:
            line = ' ' + line
        self._ind -= 1
        self._nl = False
        if not line:
            # Delay printing closing bracket in case "else" comes next
            if self._block_end:
                self._out.write('\t' * (self._ind + 1) + '}\n')
            self._block_end = True
        else:
            self.p('}' + line)

    def write_doc_line(self, doc, indent=True):
        words = doc.split()
        line = ' *'
        for word in words:
            if len(line) + len(word) >= 79:
                self.p(line)
                line = ' *'
                if indent:
                    line += '  '
            line += ' ' + word
        self.p(line)

    def write_func_prot(self, qual_ret, name, args=None, doc=None, suffix=''):
        if not args:
            args = ['void']

        if doc:
            self.p('/*')
            self.p(' * ' + doc)
            self.p(' */')

        oneline = qual_ret
        if qual_ret[-1] != '*':
            oneline += ' '
        oneline += f"{name}({', '.join(args)}){suffix}"

        if len(oneline) < 80:
            self.p(oneline)
            return

        v = qual_ret
        if len(v) > 3:
            self.p(v)
            v = ''
        elif qual_ret[-1] != '*':
            v += ' '
        v += name + '('
        ind = '\t' * (len(v) // 8) + ' ' * (len(v) % 8)
        delta_ind = len(v) - len(ind)
        v += args[0]
        i = 1
        while i < len(args):
            next_len = len(v) + len(args[i])
            if v[0] == '\t':
                next_len += delta_ind
            if next_len > 76:
                self.p(v + ',')
                v = ind
            else:
                v += ', '
            v += args[i]
            i += 1
        self.p(v + ')' + suffix)

    def write_func_lvar(self, local_vars):
        if not local_vars:
            return

        if isinstance(local_vars, str):
            local_vars = [local_vars]

        local_vars.sort(key=len, reverse=True)
        for var in local_vars:
            self.p(var)
        self.nl()

    def write_func(self, qual_ret, name, body, args=None, local_vars=None):
        self.write_func_prot(qual_ret=qual_ret, name=name, args=args)
        self.block_start()
        self.write_func_lvar(local_vars=local_vars)

        for line in body:
            self.p(line)
        self.block_end()

    def writes_defines(self, defines):
        longest = 0
        for define in defines:
            longest = max(len(define[0]), longest)
        longest = ((longest + 8) // 8) * 8
        for define in defines:
            line = '#define ' + define[0]
            line += '\t' * ((longest - len(define[0]) + 7) // 8)
            if isinstance(define[1], int):
                line += str(define[1])
            elif isinstance(define[1], str):
                line += '"' + define[1] + '"'
            self.p(line)

    def write_struct_init(self, members):
        longest = max(len(x[0]) for x in members)
        longest += 1  # because we prepend a .
        longest = ((longest + 8) // 8) * 8
        for one in members:
            line = '.' + one[0]
            line += '\t' * ((longest - len(one[0]) - 1 + 7) // 8)
            line += '= ' + str(one[1]) + ','
            self.p(line)

    def ifdef_block(self, config):
        config_option = None
        if config:
            config_option = 'CONFIG_' + c_upper(config)
        if self._ifdef_block == config_option:
            return

        if self._ifdef_block:
            self.p('#endif /* ' + self._ifdef_block + ' */')
        if config_option:
            self.p('#ifdef ' + config_option)
        self._ifdef_block = config_option
