# PacXplorer - IDA plugin to find code cross references to virtual functions using PAC codes
#    Copyright (C) 2019, 2020 Cellebrite DI LTD

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

from __future__ import print_function
import mmap
import idaapi
import idc
import idautils
from netnode import Netnode
from idaapi import Choose
from collections import namedtuple
from functools import wraps, partial
import os
import struct
import sys

PYTHON3 = sys.version_info.major == 3
if PYTHON3:
    import pickle

    def iterkeys(dct):
        return iter(dct.keys())

    def iteritems(dct):
        return iter(dct.items())
else:
    import cPickle as pickle

    iterkeys = dict.iterkeys
    iteritems = dict.iteritems

NETNODE = "$ pacxplorer"

DEBUG_VTABLE_SIZES = False
FORCE_ORIG_BYTES_FROM_INPUT_FILE = False
DEBUG_PATCHED_BYTES = False
DEBUG_MULTIPLE_INHERITANCE = False


class PickleNetNode(Netnode):
    @staticmethod
    def _encode(data):
        return pickle.dumps(data)

    @staticmethod
    def _decode(data):
        return pickle.loads(data)

    @staticmethod
    def cached(cache_key):
        """Decorator for returning cached values from self.cache[cache_key] for method with no arguments"""
        def decorator(method):
            @wraps(method)
            def wrapper(self):
                if hasattr(self, 'log'):
                    log = self.log.info
                else:
                    log = print

                cached_val = self.cache.get(cache_key)
                if cached_val is not None:
                    log("Using cached value for %s" % cache_key)
                    return cached_val
                log("No cached value for %s, generating..." % cache_key)
                result = method(self)
                self.cache[cache_key] = result
                log("Value for %s generated" % cache_key)
                return result
            return wrapper
        return decorator


VtableXrefTuple = namedtuple('VtableXrefTuple', ['xref_to', 'vtable_addr', 'vtable_entry_addr', 'offset', 'pac'])


class VtableAnalyzer(object):
    class PatchedBytesIDB(object):
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            pass

        def get_original_qword(self, ea):
            return idaapi.get_original_qword(ea)

    class PatchedBytesFile(object):
        def __init__(self, filename):
            self.filename = filename
            self.mapping = None

        def __enter__(self):
            assert self.mapping is None
            with open(self.filename, 'rb') as f:
                # the mmap object dup()s the file descriptor
                self.mapping = mmap.mmap(f.fileno(), 0, mmap.MAP_PRIVATE, mmap.PROT_READ)

            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.mapping.close()
            self.mapping = None

        def get_original_qword(self, ea):
            assert self.mapping is not None

            file_offset = idaapi.get_fileregion_offset(ea)
            try:
                if file_offset == -1:
                    raise IndexError()
                return struct.unpack_from("<Q", self.mapping, file_offset)[0]
            except IndexError:
                if DEBUG_PATCHED_BYTES:
                    print("pacxplorer: get_original_qword(0x%x) - bad file offset" % ea)
                return None

    def __init__(self, cache):
        self.cache = cache  # cache for analyzed data
        if DEBUG_VTABLE_SIZES:
            self.vtable_struct_sizes = None  # {symbol_name: size} for all vtables in idb
        self.vtable_eas = None  # {ea: symbol_name} for all vtables in the idb
        self.funcs_by_code_dict = None  # {}
        self.codes_by_func_dict = None  # {}

        self.use_patched_bytes = self._patched_bytes_in_idb()
        self.file_to_open = None

    def analyze(self):
        if not self.use_patched_bytes and self.file_to_open is None:
            raise RuntimeError("no patched bytes in IDB and backing file not set")

        if DEBUG_VTABLE_SIZES:
            self.vtable_struct_sizes = self.collect_all_vtable_struct_sizes()

        self.vtable_eas = self.collect_all_vtable_eas()
        self.funcs_by_code_dict, self.codes_by_func_dict = self.generate_pac_xrefs()
        print('VtableAnalyzer analysis done')

    def can_xref_from_ea(self, ea):
        if ea in self.codes_by_func_dict:
            return ea
        else:
            refs = list(idautils.DataRefsFrom(idc.get_item_head(ea)))
            if len(refs) != 1:
                return None
            else:
                func_addr = refs[0]
                return func_addr if func_addr in self.codes_by_func_dict else None

    def func_from_pac_tuple(self, pac_tuple):
        return self.funcs_by_code_dict.get(pac_tuple, [])

    def codes_from_func_addr(self, ea):
        codes_dict = self.codes_by_func_dict.get(ea)
        return list(iterkeys(codes_dict)) if codes_dict else None

    # Taken from ida_kernelcache.symbol, to remove the dependency
    @staticmethod
    def _mangle_name(scopes):
        symbol = ''
        if len(scopes) > 1:
            symbol += 'N'
        for name in scopes:
            if len(name) == 0:
                return None
            symbol += '{}{}'.format(len(name), name)
        if len(scopes) > 1:
            symbol += 'E'
        return symbol

    # Taken from ida_kernelcache.symbol, to remove the dependency
    @classmethod
    def vtable_symbol_for_class(cls, classname):
        """Get the mangled symbol name for the vtable for the given class name.

        Arguments:
            classname: The name of the C++ class.

        Returns:
            The symbol name, or None if the classname is invalid.
        """
        name = cls._mangle_name(classname.split('::'))
        if not name:
            return None
        return '__ZTV' + name

    VTABLE_SUFFIX = '::vtable'
    SUFFIX_LEN = len(VTABLE_SUFFIX)

    @PickleNetNode.cached('vtable_struct_sizes')
    def collect_all_vtable_struct_sizes(self):
        """
        Generate a disctionary of <symbol name>:<size> for all the vtables, based on defined structs.
        Iterates all structs with names that end with ::vtable (generated by ida_kernelcache).
        """
        sizes = {self.vtable_symbol_for_class(name[:-self.SUFFIX_LEN]): idaapi.get_struc_size(struct_id)
                 for _, struct_id, name in idautils.Structs() if name.endswith(self.VTABLE_SUFFIX)}
        return sizes

    @staticmethod
    def iter_name_ea(names):
        for name in names:
            yield name, idc.get_name_ea_simple(name)

    @PickleNetNode.cached('vtable_eas2')
    def collect_all_vtable_eas(self):
        """Generate a dictionary of <ea>:<symbol name> for all the vtables whose sizes we know"""
        vtables = {}
        for ea, name in idautils.Names():
            if ea == idc.BADADDR or name is None:
                continue
            if name.startswith('__ZTV') or name.startswith('_ZTV'):
                demangled = idaapi.demangle_name(name, idaapi.inf_get_short_demnames())
                if not demangled or not demangled.startswith("`vtable for'"):
                    print("pacxplorer: warning, name %s, demangled %s, does not seem to be a vtable" %
                          (name, repr(demangled)))
                    continue
                vtables[ea] = name

        if DEBUG_VTABLE_SIZES:
            printed = False
            for name, ea in self.iter_name_ea(self.vtable_struct_sizes):
                if ea == idc.BADADDR:
                    continue
                if ea not in vtables:
                    print("pacxplorer: warning, vtable %s @ 0x%x is only found using the legacy method" %
                          (name, ea))
                    printed = True
            if not printed:
                print("all legacy vtables were accounted for using new method")

        return vtables

    # Based on https://github.com/Synacktiv-contrib/kernelcache-laundering/blob/master/ios12_kernel_cache_helper.py
    @staticmethod
    def get_pac(decorated_addr):
        """Return MOVK pac code from decorated pointer"""
        if decorated_addr & 0x4000000000000000 != 0:
            return None
        if decorated_addr & 0x8000000000000000 == 0:
            return None
        return (decorated_addr >> 32) & 0xFFFF

    @staticmethod
    def _patched_bytes_in_idb():
        if FORCE_ORIG_BYTES_FROM_INPUT_FILE:
            return False

        # For now, we just check if tehere are ANY patched bytes in the IDB,
        # and assume that patches correspond to PAC codes being present in the IDB.
        # This of course doesn't always hold, but in practice, others uses for patches are rare.
        have_patches = bool(idaapi.visit_patched_bytes(0, idc.BADADDR, lambda *x: 1))
        return have_patches

    @PickleNetNode.cached('vtable_pac_xrefs')
    def generate_pac_xrefs(self):
        """
        The main functionality of the vtable analysis module:
        Generates two way xrefs:
            a. from pac code to method, remembering all the different vtables that reach this method
            b. from method to pac code(s), remembering all the different vtables,
               and supporting the unlikely case of various pac code for the same method

        Returns:
            funcs_by_code_dict: dict of <pac code>:<VtableXrefTuple(xref'ed method)>
            codes_by_func_dict: dict of <method ea>:<dict of <pac code>:<VtableXrefTuple(xref'ed method)> >

        """
        funcs_by_code_dict = {}
        codes_by_func_dict = {}

        _patched_bytes_obj = self.PatchedBytesIDB() if self.use_patched_bytes else \
            self.PatchedBytesFile(self.file_to_open)

        with _patched_bytes_obj as patched_bytes:
            """
            In case of multiple inheritance, the vtable contains more concatenated vtables in a special way.
            We need to parse the concatenated vtables of the base classes as well as the main one.
            
            vtable layout with multiple inheritance can look like this:
            <offset to this>
            <rtti>
            vmethod 1
            ...
            vmethod n
            
            <offset to this> --> this is the vtable of one of the base classes
            <rtti>  --> same rtti as before
            vmethod n+1
            ...
            vmethod m
            
            <offset of this> --> another base class
            < etc >
            """

            for ea, vtable_symbol in iteritems(self.vtable_eas):

                first_rtti_ptr = idaapi.get_qword(ea + 8)
                # first section of the vtable - main vtable.
                # mostly, this is the only part there is.
                # If there are concatenated vtables due to multiple inheritance, iterate over them.
                while True:
                    ea += 16  # skip 'this offset' and rtti in vtable
                    # offset in the current vtable
                    offset = 0
                    # now iterate over vmethods
                    while True:
                        orig_qword = patched_bytes.get_original_qword(ea + offset)
                        patched_qword = idaapi.get_qword(ea + offset)
                        if DEBUG_PATCHED_BYTES and orig_qword is None:
                            print("orig_qword is None")
                            print("ea 0x%x, offset 0x%x" % (ea, offset))
                            print("symbol: %s" % vtable_symbol)

                        # end of the vtable is detected by encountering not a tagged pointer
                        # this is okay even if there are severl conjoined vtables back-to-back,
                        # due to the first non-ptr element in the vtable
                        if orig_qword == patched_qword or orig_qword is None:
                            if DEBUG_VTABLE_SIZES:
                                size = self.vtable_struct_sizes.get(vtable_symbol)
                                if size is not None and offset != size:
                                    print("%s @ 0x%x: non-matching sizes: old 0x%x, new 0x%x" %
                                          (vtable_symbol, ea+size, size, offset))
                            break

                        # this is expected to always succeed
                        pac = self.get_pac(orig_qword)
                        if pac is not None:
                            xref_to = idaapi.get_qword(ea + offset)

                            # VtableXrefTuple = namedtuple('VtableXrefTuple', ['xref_to' , 'vtable_addr', 'vtable_entry_addr', 'offset', 'pac'])
                            xref_tuple = VtableXrefTuple(xref_to, ea-16, ea + offset, offset, pac)
                            refs = funcs_by_code_dict.setdefault((offset, pac), [])
                            refs.append(xref_tuple)

                            codes_dict = codes_by_func_dict.setdefault(xref_to, {})
                            refs = codes_dict.setdefault((offset, pac), [])
                            refs.append(xref_tuple)

                        offset += 8

                    # if we haven't parsed anything in the inner loop, no need to process this whole vtable any more
                    if offset == 0:
                        break
                    # in the context of the concatenated vtables loop, skip past the vtable we have just finished
                    ea += offset
                    rtti_ptr = idaapi.get_qword(ea + 8)
                    # we know there is an concatenated vtable only by encountering the same rtti ptr as the main one.
                    # normal case: not concatenated vtable, so break after one iteration
                    if first_rtti_ptr == 0 or rtti_ptr != first_rtti_ptr:
                        break
                    else:
                        if DEBUG_MULTIPLE_INHERITANCE:
                            print("parsing concatenated vtable at 0x%x, symbol %s " % (ea, vtable_symbol))

            return funcs_by_code_dict, codes_by_func_dict


MovkCodeTuple = namedtuple('MovkCodeTuple', ['pac_tuple', 'movk_addr', 'trace'])


class MovkAnalyzer(object):
    GOOD_MOVK_COMMENT = 'This MOVK has PAC xrefs'
    BAD_STATICVTBL_MOVK_COMMENT = 'This MOVK has **NO** PAC xrefs (static vtable)'
    BAD_ERROR_MOVK_COMMENT = 'This MOVK has **NO** PAC xrefs (analysis error, please report!)'

    def __init__(self, cache):
        self.cache = cache  # cache for analyzed data
        self.codes_by_movk_dict = None
        self.movk_by_code_dict = None

    def analyze(self):
        self.codes_by_movk_dict, self.movk_by_code_dict = self.analyze_all_funcs()
        print('MOVK analysis done')

    def can_xref_from_ea(self, ea):
        code = self.codes_by_movk_dict.get(ea)
        return ea if (code and code.pac_tuple) else None

    def pac_tuple_from_ea(self, ea):
        # MovkCodeTuple = namedtuple('MovkCodeTuple', ['pac_tuple', 'movk_addr', 'trace'])
        movk_code_tuple = self.codes_by_movk_dict.get(ea)
        if movk_code_tuple is None:
            return None
        return movk_code_tuple.pac_tuple

    def movks_from_pac_codes(self, pac_codes):
        movks = []
        for code in pac_codes:
            for movk in self.movk_by_code_dict.get(code, []):
                movks.append((movk, code))

        return movks

    @classmethod
    def edit_comment(cls, comment, wanted, delete):
        if comment is None:
            comment = ""
        if not delete and wanted not in comment:
            comment = comment.rstrip()
            if comment:
                comment += '\n'
            comment += wanted
        elif delete and wanted in comment:
            parts = comment.split(wanted)
            comment = '\n'.join((x.rstrip() for x in parts))
        return comment

    @classmethod
    def add_comment(cls, ea, wanted):
        comment = idc.get_cmt(ea, True)
        new_comment = cls.edit_comment(comment, wanted, delete=False)
        idc.set_cmt(ea, new_comment, True)

    @classmethod
    def delete_comment(cls, ea, wanted):
        comment = idc.get_cmt(ea, True)
        new_comment = cls.edit_comment(comment, wanted, delete=True)
        idc.set_cmt(ea, new_comment, True)

    @staticmethod
    def does_modify_reg(insn, reg):
        for i in range(6):
            op = insn.ops[i]
            if op.reg != reg:
                continue
            if insn.get_canon_feature() & (0x4 << i):  # CF_CHG1, CF_CHG2, ...
                return True
        return False

    @staticmethod
    def does_use_reg(insn, reg):
        for i in range(6):
            op = insn.ops[i]
            if op.reg != reg:
                continue
            if insn.get_canon_feature() & (0x100 << i):  # CF_USE1, CF_USE2, ...
                return True
        return False

    @staticmethod
    def does_use_any_reg(insn):
        for i in range(6):
            op = insn.ops[i]
            if op.reg == 0:
                continue
            if insn.get_canon_feature() & (0x100 << i):  # CF_USE1, CF_USE2, ...
                return True
        return False

    @classmethod
    def analyze_movk(cls, addr):
        trace = []
        seen_depac = False
        offset = 0

        cur_func = idaapi.get_func(addr)
        if not cur_func:
            return (None, None)
        cur_func_start = cur_func.start_ea

        insn = idautils.DecodeInstruction(addr)
        mnem = insn.get_canon_mnem()
        if mnem != 'MOVK' or insn.Op2.specval != 48:
            return (None, None)
        ctx_reg = insn.Op1.reg
        movk_code = insn.Op2.value

        line = idc.GetDisasm(insn.ea)
        trace.append(line)

        curr = addr
        visited = set()
        while True:
            refs = [x for x in idautils.CodeRefsTo(curr, True) if idaapi.get_func(x) and idaapi.get_func(x).start_ea == cur_func_start]
            if not refs:
                trace.append('ERROR NO REFS')
                break

            curr = refs[0]
            if curr in visited:
                trace.append('ERROR EXHAUSTED')
                break

            visited.add(curr)

            insn = idautils.DecodeInstruction(curr)
            mnem = insn.get_canon_mnem()
            line = idc.GetDisasm(insn.ea)
            line = line.split(';')[0]  # line comments get into the dissasembly
            line_parts = [x for x in line.split(' ') if x]

            trace.append(line)

            if line_parts[0:1] == ['LDRAA'] and line_parts[-1:] and line_parts[-1:][0].endswith('!') and \
                    insn.Op2.reg == ctx_reg:
                offset = insn.Op2.addr
                seen_depac = True
                break
            if line_parts and line_parts[0] in ['AUTDZA', 'AUTDA'] and insn.Op1.reg == ctx_reg:
                seen_depac = True
                break
            if cls.does_modify_reg(insn, ctx_reg):
                if not cls.does_use_any_reg(insn):
                    trace.append('ERROR STATIC VTABLE')
                    cls.add_comment(addr, cls.BAD_STATICVTBL_MOVK_COMMENT)
                    break
                elif mnem == 'MOV':
                    ctx_reg = insn.Op2.reg
                elif mnem == 'ADD':
                    ctx_reg = insn.Op2.reg
                    offset += insn.Op3.value
                else:
                    trace.append('ERROR BAD MODIFY')
                    #cls.add_comment(addr, cls.BAD_ERROR_MOVK_COMMENT)
                    break
            elif cls.does_use_reg(insn, ctx_reg) and line_parts[-1:] and line_parts[-1:][0].endswith('!'):
                if mnem == 'LDR' and insn.Op2.reg == ctx_reg:
                    offset += insn.Op2.addr
                else:
                    trace.append('ERROR BAD MODIFY')
                    #cls.add_comment(addr, cls.BAD_ERROR_MOVK_COMMENT)
                    break

        trace = trace[::-1]
        pac_tuple = (offset, movk_code) if seen_depac else None

        if pac_tuple is not None:
            cls.add_comment(addr, cls.GOOD_MOVK_COMMENT)

        return (pac_tuple, trace)

    def _analyze_func(self, func_addr, codes_by_movk_dict, movk_by_code_dict):
        for addr in idautils.FuncItems(func_addr):
            pac_tuple, trace = self.analyze_movk(addr)
            if not (pac_tuple is None and trace is None):
                codes_by_movk_dict[addr] = MovkCodeTuple(pac_tuple, addr, trace)
                if pac_tuple is not None:
                    movks = movk_by_code_dict.setdefault(pac_tuple, [])
                    movks.append(addr)

    @PickleNetNode.cached('movk_analysis')
    def analyze_all_funcs(self):
        codes_by_movk_dict = {}
        movk_by_code_dict = {}
        for func in idautils.Functions():
            self._analyze_func(func, codes_by_movk_dict, movk_by_code_dict)

        return codes_by_movk_dict, movk_by_code_dict


class _Choose(Choose):
    # Fix Choose.UI_Hooks_Trampoline to work with modal dialogs
    class UI_Hooks_Trampoline(Choose.UI_Hooks_Trampoline):
        def populating_widget_popup(self, form, popup_handle):
            chooser = self.v()
            if hasattr(chooser, "OnPopup") and \
                    callable(getattr(chooser, "OnPopup")):
                chooser.OnPopup(form, popup_handle)

    class chooser_handler_t(idaapi.action_handler_t):
        def __init__(self, handler):
            idaapi.action_handler_t.__init__(self)
            self.handler = handler

        def activate(self, ctx):
            self.handler()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_FOR_WIDGET \
                if idaapi.is_chooser_widget(ctx.widget_type) \
                else idaapi.AST_DISABLE_FOR_WIDGET

    def __init__(self, title, items, columns):
        Choose.__init__(
            self,
            title,
            columns,
            flags=Choose.CH_RESTORE)

        self.items = items

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def show(self):
        selected = self.Show(modal=True)
        if selected < 0:
            return None
        return self.items[selected]


class MovkXrefChooser(_Choose):
    unique_functions = True

    def __init__(self, title, items):
        _Choose.__init__(
            self,
            title,
            items,
            [ ["Address", 20 | Choose.CHCOL_HEX], ["Method", 40 | Choose.CHCOL_PLAIN],
              ["Class", 30 | Choose.CHCOL_PLAIN] ])

        self.all_items = items
        self.calculate_unique()

    def OnPopup(self, form, popup_handle):
        idaapi.attach_action_to_popup(form, popup_handle, "-", None, idaapi.SETMENU_FIRST)

        desc = idaapi.action_desc_t(
            "choose:unique",
            "PAC: toggle unique function names",
            self.chooser_handler_t(self.toggle_unique))
        idaapi.attach_dynamic_action_to_popup(form, popup_handle, desc, None, idaapi.SETMENU_FIRST)

    def OnRefresh(self, n):
        return (Choose.ALL_CHANGED, 0)

    def calculate_unique(self):
        if MovkXrefChooser.unique_functions:
            unique_dict = {}
            for addr, func, classname in self.all_items:
                if classname != unique_dict.setdefault((addr, func), classname):
                    unique_dict[(addr, func)] = '<multiple classes>'
            self.items = list(sorted( ([addr, funcname, classname] for (addr, funcname), classname in
                                       iteritems(unique_dict)), key=lambda x: x[0]))
        else:
            self.items = self.all_items

    def toggle_unique(self):
        MovkXrefChooser.unique_functions = not MovkXrefChooser.unique_functions
        self.calculate_unique()
        self.Refresh()

    @staticmethod
    def demangle(ea):
        name = idc.get_name(ea, idc.GN_LONG)
        demangled = (idaapi.demangle_name(str(name), idc.get_inf_attr(idc.INF_SHORT_DEMNAMES)) or '').\
            replace("`vtable for'", "")
        return demangled or name


class FuncXrefChooser(_Choose):
    def __init__(self, title, items):
        _Choose.__init__(
            self,
            title,
            items,
            [ ["Address", 30 | Choose.CHCOL_PLAIN], ["Address (Hex)", 20 | Choose.CHCOL_HEX],
              ["PAC Code", 20 | Choose.CHCOL_PLAIN] ])


class PacxplorerPlugin(idaapi.plugin_t, idaapi.UI_Hooks):
    plugin_initialized = False
    flags = idaapi.PLUGIN_MOD  | idaapi.PLUGIN_HIDE
    comment = "find xrefs for vtable methods using PAC codes"
    help = ""
    wanted_name = "PacXplorer"
    wanted_hotkey = ""

    class MenuBase(idaapi.action_handler_t):
        label = None
        shortcut = None
        tooltip = None
        icon = -1

        def __init__(self, plugin):
            self.plugin = plugin
            self.name = self.plugin.wanted_name + ':' + self.__class__.__name__
            self.register()

        def register(self):
            return idaapi.register_action(idaapi.action_desc_t(
                self.name,  # Name. Acts as an ID. Must be unique.
                self.label,  # Label. That's what users see.
                self,  # Handler. Called when activated, and for updating
                self.shortcut,  # shortcut,
                self.tooltip,  # tooltip
                self.icon  # icon
            ))

        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.__name__)

        def activate(self, ctx):
            # dummy method
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE_ALWAYS

        def path(self):
            return "Edit/Plugins/" + self.plugin.wanted_name + "/" + self.label

        def get_name(self):
            return self.name

    class AnalyzeMenu(MenuBase):
        label = 'Analyze IDB...'

        def activate(self, ctx):
            self.plugin.analyze()
            return 1

    class JumpXrefMenu(MenuBase):
        label = 'Jump to PAC XREFs...'
        shortcut = 'Meta-X'
        icon = 151

        def activate(self, ctx):
            self.plugin.choose_window_here()
            return 1

        def update(self, ctx):
            return idaapi.AST_ENABLE if self.plugin.can_find_xrefs_here() else idaapi.AST_DISABLE

    def __init__(self):
        self.analysis_done = False
        self.vtable_analyzer = None
        self.movk_analyzer = None
        self.ui_hook = False
        self.analyze_menu = None
        self.jump_xref_menu = None

    def init(self):
        """plugin_t init() function"""
        super(PacxplorerPlugin, self).__init__()

        typename = idaapi.get_file_type_name()
        if 'ARM64e' not in typename:
            print('%s: IDB deemed unsuitable (not an ARM64e binary). Skipping...' % self.wanted_name)
            return idaapi.PLUGIN_SKIP

        if not PacxplorerPlugin.plugin_initialized:
            self.analyze_menu = self.AnalyzeMenu(self)
            self.jump_xref_menu = self.JumpXrefMenu(self)

            self.ui_hook = True
            self.hook()
            print('%s: IDB deemed suitable. Initializing...' % self.wanted_name)

        return idaapi.PLUGIN_KEEP

    def run(self, arg=0):
        """plugin_t run() implementation"""
        return

    def term(self):
        """plugin_t term() implementation"""
        if self.ui_hook:
            self.unhook()
            self.ui_hook = False
        return

    def ready_to_run(self):
        """UI_Hooks function.
        Attaches actions to plugin in main menu.
        """

        idaapi.attach_action_to_menu(self.analyze_menu.path(), self.analyze_menu.get_name(), idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu(self.jump_xref_menu.path(), self.jump_xref_menu.get_name(), idaapi.SETMENU_APP)
        PacxplorerPlugin.plugin_initialized = True
        self.analyze(only_cached=True)

    def finish_populating_widget_popup(self, widget, popup_handle):
        """UI_Hooks function
        Attaches the Find Xref action to the dissasembly right click menu.
        """
        if not self.analysis_done:
            return
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM and self.can_find_xrefs_here():
            idaapi.attach_action_to_popup(widget, popup_handle, "-", None, idaapi.SETMENU_FIRST)
            idaapi.attach_action_to_popup(widget, popup_handle, self.jump_xref_menu.get_name(), None,
                                          idaapi.SETMENU_FIRST)

    def analyze(self, only_cached=False):
        cache = PickleNetNode(NETNODE)
        # cache.kill()

        if only_cached:
            if not cache.get('analysis_done', False):
                return
            print('%s: this IDB had been previously analyzed, loading from cache' % self.wanted_name)
        elif self.analysis_done:
            answer = idc.ask_yn(idaapi.ASKBTN_NO, "HIDECANCEL\nRe-analyze the IDB?")
            if answer != idaapi.ASKBTN_YES:
                return
            cache.kill()
            self.analysis_done = False

        should_hide_wait = False
        if not cache.get('analysis_done', False):
            should_hide_wait = True
            idaapi.show_wait_box("HIDECANCEL\n%s analyzing..." % self.wanted_name)

        # not catching exceptions, just want to call the finally block to hide the wait_box
        try:
            self.vtable_analyzer = VtableAnalyzer(cache)
            self.movk_analyzer = MovkAnalyzer(cache)

            if not self.vtable_analyzer.use_patched_bytes:
                file_to_open = self.choose_file_for_patches()
                if file_to_open is None:
                    print("%s: user cancelled" % self.wanted_name)
                    return
                self.vtable_analyzer.file_to_open = file_to_open

            self.vtable_analyzer.analyze()
            if len(self.vtable_analyzer.funcs_by_code_dict) == 0:
                idaapi.warning(('%s\nUnable to find vtables and pac codes.\n' 
                               'If this is a KernelCache:\n'
                                'make sure ida_kernelcache is run on this idb') % self.wanted_name)
                return

            self.movk_analyzer.analyze()
            if len(self.movk_analyzer.movk_by_code_dict) == 0:
                idaapi.warning('%s\nUnable to find movk pac codes.\nThis is weird...' % self.wanted_name)

            cache['analysis_done'] = True
            self.analysis_done = True
        finally:
            if should_hide_wait:
                idaapi.hide_wait_box()
            if not self.analysis_done:
                cache.kill()

    def choose_xref_from_movk(self, ea):
        pac_tuple = self.movk_analyzer.pac_tuple_from_ea(ea)
        if not pac_tuple:
            return None

        raw_candidates = self.vtable_analyzer.func_from_pac_tuple(pac_tuple)
        # VtableXrefTuple = namedtuple('VtableXrefTuple', ['xref_to' , 'vtable_addr', 'vtable_entry_addr', 'offset', 'pac'])
        candidates = [ ["0x%016x" % x.xref_to, MovkXrefChooser.demangle(x.xref_to),
                        MovkXrefChooser.demangle(x.vtable_addr)] for x in raw_candidates ]
        title = "PAC xrefs from 0x%016X" % ea
        chooser = MovkXrefChooser(title, candidates)
        chosen = chooser.show()
        if chosen is None:
            return None
        return int(chosen[0], 16)

    def choose_xref_to_func(self, ea):
        pac_codes = self.vtable_analyzer.codes_from_func_addr(ea)
        if not pac_codes:
            return None

        movks = self.movk_analyzer.movks_from_pac_codes(pac_codes)
        candidates = [[idc.get_func_off_str(addr), "0x%016x" % addr, "(%d, 0x%4x)" % (code[0], code[1])]
                      for addr, code in movks]

        title = 'PAC xrefs to 0x%016X' % ea
        chooser = FuncXrefChooser(title, candidates)
        chosen = chooser.show()

        if chosen is None:
            return None
        return int(chosen[1], 16)

    def pick_choose_func_for_ea(self, ea):
        ref_addr = self.movk_analyzer.can_xref_from_ea(ea)
        if ref_addr:
            return partial(self.choose_xref_from_movk, ref_addr)

        ref_addr = self.vtable_analyzer.can_xref_from_ea(ea)
        if ref_addr:
            return partial(self.choose_xref_to_func, ref_addr)

        return None

    def choose_by_ea(self, ea):
        choose_func = self.pick_choose_func_for_ea(ea)
        if choose_func is None:
            return

        addr = choose_func()
        if addr is not None:
            idc.jumpto(addr)

    def choose_window_here(self):
        if not self.analysis_done:
            return
        self.choose_by_ea(idc.here())

    def can_find_xrefs_here(self):
        if not self.analysis_done:
            return False
        return self.pick_choose_func_for_ea(idc.here()) is not None

    def choose_file_for_patches(self):
        file_path = idaapi.get_input_file_path()
        if os.path.exists(file_path):
            return file_path
        else:
            idaapi.info('%s\nNo patches are present in the IDB.\n'
                        'Please locate the input binary, to load PAC codes from' %
                        self.wanted_name)
            name = idaapi.ask_file(False, '*', 'locate the input binary')
            return name or None


def PLUGIN_ENTRY():
    return PacxplorerPlugin()
