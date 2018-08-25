from collections import namedtuple, OrderedDict
import idaapi # type: ignore
import ida_hexrays as hr # type: ignore
import idautils # type: ignore
import idc # type: ignore
import os
import sys
import typing
import yaml
import yaml_util
try: del sys.modules['havok_structures_nx']
except: pass
try: del sys.modules['hexrays_utils']
except: pass
from havok_structures_nx import *
from hexrays_utils import *

# Address of the hkClass constructor.
hkclass_ctor_ea = 0x7101583018
# Main module memory dump.
memdump = open('/home/leo/botw/main_memdump', 'rb').read()
# Base address for pointers in the main module memory dump.
memdump_pointer_base = 0x08005000
# Base address for IDA objects.
ida_base = 0x7100000000

def ida_addr_to_memdump_addr(p): # type: (int)->int
    return p - ida_base + memdump_pointer_base
def memdump_addr_to_ida_addr(p): # type: (int)->int
    return p - memdump_pointer_base + ida_base

def parse_enum(o): # type: (int) -> HkClassEnum
    re = make_hkclassenum_raw(memdump[o:o+HkClassEnumRawStruct.size])
    name = idc.GetString(memdump_addr_to_ida_addr(re.m_name))
    items = [] # type: typing.List[HkClassEnumItem]
    for j in range(re.m_numItems):
        o = (re.m_items - memdump_pointer_base) + j*HkClassEnumItemRawStruct.size
        ritem = make_hkclassenumitem_raw(memdump[o:o+HkClassEnumItemRawStruct.size])
        item_value = ritem.m_value
        item_name = idc.GetString(memdump_addr_to_ida_addr(ritem.m_name))
        items.append(HkClassEnumItem(item_value, item_name))
    flags = re.m_flags
    return HkClassEnum(name, items, flags)

def make_hkclass(offset, processed_classes): # type: (int,dict) -> HkClass
    processed_classes[offset] = '...'

    rclass = make_hkclass_raw(memdump[offset:offset+0x50]) # type: HkClassRaw

    enums = [] # type: typing.List[HkClassEnum]
    for i in range(rclass.m_numDeclaredEnums):
        o = (rclass.m_declaredEnums - memdump_pointer_base) + i*HkClassEnumRawStruct.size
        v = parse_enum(o)
        enums.append(v)

    members = []  # type: typing.List[HkClassMember]
    for i in range(rclass.m_numDeclaredMembers):
        o = (rclass.m_declaredMembers - memdump_pointer_base) + i*HkClassMemberRawStruct.size
        rmember = make_hkclassmember_raw(memdump[o:o+HkClassMemberRawStruct.size]) # type: HkClassMemberRaw

        mname = idc.GetString(memdump_addr_to_ida_addr(rmember.m_name))
        mcl = None
        if rmember.m_class:
            class_offset = rmember.m_class - memdump_pointer_base
            mcl = get_hkclass(class_offset, processed_classes)
        menum = parse_enum(rmember.m_enum - memdump_pointer_base) if rmember.m_enum else None
        mtype = HkClassMemberType(rmember.m_type)
        msubtype = HkClassMemberType(rmember.m_subtype)
        marray_size = rmember.m_cArraySize
        mflags = rmember.m_flags
        moffset = rmember.m_offset

        members.append(HkClassMember(mname, mcl, menum, mtype, msubtype, marray_size, mflags, moffset))

    name = idc.GetString(memdump_addr_to_ida_addr(rclass.m_name))
    parent = get_hkclass(rclass.m_parent - memdump_pointer_base, processed_classes) \
        if rclass.m_parent else None
    obj_size = rclass.m_objectSize
    flags = rclass.m_flags
    version = rclass.m_describedVersion
    return HkClass(name, parent, obj_size, enums, members, flags, version)

class HavokClassVisitor(hr.ctree_visitor_t):
    def __init__(self): # type: () -> None
        hr.ctree_visitor_t.__init__(self, hr.CV_PARENTS)

    def get_class_address(self, cfunc, call_ea): # type: (typing.Any, int) -> int
        self._call_ea = call_ea
        self._class_ea = -1
        hr.ctree_visitor_t.apply_to(self, cfunc.body, None)
        return self._class_ea

    def _visit(self, c): # type: (...) -> int
        if c.op != hr.cot_call or c.ea != self._call_ea or len(c.a) != 14:
            return 0
        this_arg = unwrap_ref(unwrap_cast(c.a[0]))
        if this_arg.op == hr.cot_obj:
            self._class_ea = this_arg.obj_ea
        return 1

    def visit_expr(self, c): # type: (...) -> int
        return self._visit(c)

def get_hkclass(offset, processed_classes): # type: (int,dict) -> HkClass
    if offset not in processed_classes:
        process_hkclass(offset, processed_classes)
    return processed_classes[offset]

def process_hkclass(offset, processed_classes): # type: (int,dict) -> None
    cl = make_hkclass(offset, processed_classes)
    processed_classes[offset] = cl

class NoAliasDumper(yaml.CSafeDumper):
    def ignore_aliases(self, data):
        return True

def main(): # type: () -> None
    processed_classes = dict() # type: typing.Dict[int, HkClass]
    visitor = HavokClassVisitor()

    for i, call_ea in enumerate(idautils.CodeRefsTo(hkclass_ctor_ea, 1)):
        class_ea = visitor.get_class_address(idaapi.decompile(call_ea), call_ea)
        if class_ea == -1:
            print("0x%x: failed to get class ea" % call_ea)
            break
        process_hkclass(class_ea - ida_base, processed_classes)
        print(i)

    dumper = NoAliasDumper
    yaml.add_representer(OrderedDict, lambda d, data: yaml_util.represent_dict(d, data.items()), Dumper=dumper)
    yaml.add_representer(HkClass, lambda d, data: yaml_util.represent_dict(d, data._asdict()), Dumper=dumper)
    yaml.add_representer(HkClassMember, lambda d, data: yaml_util.represent_dict(d, data._asdict()), Dumper=dumper)
    yaml.add_representer(HkClassEnum, lambda d, data: yaml_util.represent_dict(d, data._asdict()), Dumper=dumper)
    yaml.add_representer(HkClassEnumItem, lambda d, data: yaml_util.represent_dict(d, data._asdict()), Dumper=dumper)
    yaml.add_representer(HkClassMemberType, lambda d, data: d.represent_scalar('tag:yaml.org,2002:str', data.name), Dumper=dumper)

    with open(os.path.dirname(os.path.realpath(__file__)) + '/../havok_reflection_info.yml', 'wb') as f:
        yaml.dump({v.name: v for v in processed_classes.values()}, f, allow_unicode=True, Dumper=dumper)

main()
