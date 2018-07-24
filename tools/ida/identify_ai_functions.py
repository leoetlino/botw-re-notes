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

class VtableGetter(hr.ctree_visitor_t):
    def __init__(self): # type: () -> None
        hr.ctree_visitor_t.__init__(self, hr.CV_PARENTS)
        self._reset_context()

    def _reset_context(self): # type: () -> None
        self._step = 0
        self._cfunc = None
        self._this_vidx = 0
        self._this_vidx2 = 0
        self._base_ctor_addr = 0
        self._vtable_addr = 0

    def get_base_ctor_and_vtable_address(self, cfunc): # type: (typing.Any) -> typing.Tuple[int, int]
        self._reset_context()
        self._cfunc = cfunc
        hr.ctree_visitor_t.apply_to(self, cfunc.body, None)
        return (self._base_ctor_addr, self._vtable_addr)

    def _visit(self, c): # type: (...) -> int
        if self._step == 0:
            if c.op != hr.cot_asg:
                return 1
            lhs = c.x
            rhs = unwrap_cast(c.y)
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
            base_ctor_name = idaapi.get_func_name(c.x.obj_ea)
            if not (base_ctor_name.startswith("AI_") and base_ctor_name.endswith("::ctor")):
                return 1
            self._base_ctor_addr = c.x.obj_ea
            self._step += 1
            return 0

        if self._step == 2:
            if c.op != hr.cot_asg:
                return 0
            lhs = unwrap_cast(c.x)
            rhs = unwrap_cast(c.y)
            if lhs.op != hr.cot_ptr:
                return 0
            deref_target = unwrap_cast(lhs.x)
            if deref_target.op != hr.cot_var:
                return 0
            if deref_target.v.idx != self._this_vidx and deref_target.v.idx != self._this_vidx2:
                return 0
            if rhs.op == hr.cot_obj:
                self._vtable_addr = rhs.obj_ea
                return 1
            if rhs.op == hr.cot_ref and rhs.x.op == hr.cot_obj:
                self._vtable_addr = rhs.x.obj_ea
                return 1
            return 0

        print("!!! BUG: unknown step: %d" % self._step)
        return 1

    def visit_expr(self, c): # type: (...) -> int
        return self._visit(c)

vtable_getter = VtableGetter()
def do_rename_vtable_functions(cfunc, names, class_name): # type: (typing.Any, typing.Dict[int, str], str) -> bool
    base_ctor_ea, vtable_ea = vtable_getter.get_base_ctor_and_vtable_address(cfunc)
    if not vtable_ea:
        return False

    base_ctor_name = idaapi.get_func_name(base_ctor_ea)
    base_class_ctors = {"AI_ActionBase::ctor", "AI_AIBase::ctor", "AI_BehaviorBase::ctor", "AI_QueryBase::ctor"}
    if base_ctor_name not in base_class_ctors:
        base_vtable_ea = vtable_getter.get_base_ctor_and_vtable_address(idaapi.decompile(base_ctor_ea))[1]
        if not base_vtable_ea or not has_all_vtable_functions_named(base_vtable_ea):
            print("Skipping %s (base: %s 0x%x)" % (class_name, base_ctor_name, base_ctor_ea))
            return False

    rename_vtable_functions(names, vtable_ea, class_name)
    return True

def do_rename_action(cfunc, class_name):
    names = {
        0: "rtti1",
        1: "rtti2",
        2: "dtor",
        3: "dtorDelete",
        10: "doAction",
        15: "loadParams",
    }
    return do_rename_vtable_functions(cfunc, names, class_name)

def do_rename_ai(cfunc, class_name):
    names = {
        0: "rtti1",
        1: "rtti2",
        2: "dtor",
        3: "dtorDelete",
        10: "doAction",
        15: "loadParams",
    }
    return do_rename_vtable_functions(cfunc, names, class_name)

def do_rename_behavior(cfunc, class_name):
    names = {
        0: "rtti1",
        1: "rtti2",
        2: "dtor",
        3: "dtorDelete",
        10: "loadParams",
    }
    return do_rename_vtable_functions(cfunc, names, class_name)

def do_rename_query(cfunc, class_name):
    names = {
        0: "rtti1",
        1: "rtti2",
        2: "dtor",
        3: "dtorDelete",
        9: "doQuery",
    }
    return do_rename_vtable_functions(cfunc, names, class_name)

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
            do_rename_action(cfunc, class_name)
        if category == "AI":
            cfunc = idaapi.decompile(ctor_addr)
            do_rename_ai(cfunc, class_name)
        if category == "Behavior":
            cfunc = idaapi.decompile(ctor_addr)
            do_rename_behavior(cfunc, class_name)
        if category == "Query":
            cfunc = idaapi.decompile(ctor_addr)
            do_rename_query(cfunc, class_name)
