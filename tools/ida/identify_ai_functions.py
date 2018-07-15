import binascii
import idaapi # type: ignore
import ida_hexrays as hr # type: ignore
import idc # type: ignore
import os
import struct
import sys
import typing

try:
    del sys.modules['hexrays_utils']
except: pass
from hexrays_utils import *

# Only valid for Switch 1.5.0.
TABLES = [
    ("Action", 0x71024416C8, 1771),
    ("AI", 0x7102448578, 1172),
    ("Behavior", 0x710244CF20, 224),
    ("Query", 0x710244F428, 165),
]

aidef_crc = dict() # type: typing.Dict[int, str]

with open(os.path.dirname(os.path.realpath(__file__)) + '/../aidef_strings.txt', 'r') as file:
    for string in file:
        string = string.rstrip('\n')
        aidef_crc[binascii.crc32(string.encode()) & 0xffffffff] = string

class MemberFunctionRenamer(hr.ctree_visitor_t):
    def __init__(self): # type: () -> None
        hr.ctree_visitor_t.__init__(self, hr.CV_PARENTS)
        self._reset_context()

    def _reset_context(self): # type: () -> None
        self._step = 0
        self._cfunc = None
        self._class_name = ""
        self._this_vidx = 0
        self._this_vidx2 = 0
        self._vtable_addr = 0
        self._base_class_name = ""
        self._names = dict() # type: typing.Dict[int, str]

    def run(self, cfunc, class_name, names, base_class_name): # type: (typing.Any, str, typing.Dict[int, str], str) -> None
        self._reset_context()
        self._cfunc = cfunc
        self._class_name = class_name
        self._names = names
        self._base_class_name = base_class_name
        hr.ctree_visitor_t.apply_to(self, cfunc.body, None)

    def _visit(self, c): # type: (...) -> int
        if self._step == 0:
            if c.op != hr.cot_asg:
                return 1
            lhs = c.x
            rhs = c.y
            if lhs.op != hr.cot_var or rhs.op != hr.cot_var:
                return 1
            if cfunc.get_lvars()[rhs.v.idx].name != "this":
                return 1
            self._this_vidx = rhs.v.idx
            self._this_vidx2 = lhs.v.idx
            self._step += 1
            return 0

        if self._step == 1:
            if c.op != hr.cot_call:
                return 0
            if self._base_class_name and idaapi.get_func_name(c.x.obj_ea) != self._base_class_name + "::ctor":
                return 1
            self._step += 1
            return 0

        if self._step == 2:
            if c.op != hr.cot_asg:
                return 0
            lhs = c.x
            rhs = c.y
            if lhs.op != hr.cot_ptr:
                return 0
            if lhs.x.op != hr.cot_var:
                return 0
            if unwrap_cast(lhs.x).v.idx != self._this_vidx and unwrap_cast(lhs.x).v.idx != self._this_vidx2:
                return 0
            if rhs.op != hr.cot_obj:
                return 0
            rename_vtable_functions(self._names, rhs.obj_ea, self._class_name)
            return 1

        print("!!! BUG: unknown step: %d" % self._step)
        return 1

    def visit_expr(self, c): # type: (...) -> int
        return self._visit(c)

renamer = MemberFunctionRenamer()
STRUCT_SIZE = 0x10
for category, address, size in TABLES:
    for i in range(size):
        print("%s [%u/%u]" % (category, i+1, size))
        entry = idaapi.get_many_bytes(address + STRUCT_SIZE*i, STRUCT_SIZE)
        crc, padding, fn = struct.unpack('<IIQ', entry)
        name = aidef_crc.get(crc, "Unknown_%08x" % crc)
        function_name = "AI_F_%s_%s" % (category, name)
        idc.MakeNameEx(fn, function_name, idc.SN_NOWARN)
        idc.SetType(fn, "void* makeHandler(void* param, sead::Heap* heap);")
        if "BL              operator new" not in idc.GetDisasm(fn + 6*4) or idc.GetMnem(fn + 9*4) != "BL":
            continue

        ctor_addr = idc.GetOperandValue(fn + 9*4, 0)
        class_name = "AI_%s_%s" % (category, name)
        idc.MakeNameEx(ctor_addr, "%s::ctor" % class_name, idc.SN_NOWARN)
        idc.SetType(ctor_addr, "void ctor(void* this, void* param);")

        if category == "Action":
            cfunc = idaapi.decompile(ctor_addr)
            names = {
                0: "rtti1",
                1: "rtti2",
                2: "dtor",
                3: "dtorDelete",
            }
            renamer.run(cfunc, class_name, names, "AI_ActionBase")

        if category == "AI":
            cfunc = idaapi.decompile(ctor_addr)
            names = {
                0: "rtti1",
                1: "rtti2",
                2: "dtor",
                3: "dtorDelete",
            }
            renamer.run(cfunc, class_name, names, "AI_AIBase")

        if category == "Behavior":
            cfunc = idaapi.decompile(ctor_addr)
            names = {
                0: "rtti1",
                1: "rtti2",
                2: "dtor",
                3: "dtorDelete",
            }
            renamer.run(cfunc, class_name, names, "AI_BehaviorBase")

        if category == "Query":
            cfunc = idaapi.decompile(ctor_addr)
            names = {
                0: "rtti1",
                1: "rtti2",
                2: "dtor",
                3: "dtorDelete",
                9: "doQuery",
            }
            renamer.run(cfunc, class_name, names, "AI_QueryBase")
