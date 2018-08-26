from collections import namedtuple, OrderedDict
import idaapi # type: ignore
import idautils # type: ignore
import idc # type: ignore
import json
import os
import sys
import typing
try: del sys.modules['havok_structures_nx']
except: pass
from havok_structures_nx import *

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

def make_hkclass(offset, enums_by_id): # type: (int, typing.Dict[int, dict]) -> HkClass
    rclass = make_hkclass_raw(memdump[offset:offset+0x50]) # type: HkClassRaw

    declared_enums = [] # type: typing.List[dict]
    for i in range(rclass.m_numDeclaredEnums):
        o = (rclass.m_declaredEnums - memdump_pointer_base) + i*HkClassEnumRawStruct.size
        v = parse_enum(o)._asdict()
        enums_by_id[o] = v
        declared_enums.append(v)

    members = []  # type: typing.List[dict]
    for i in range(rclass.m_numDeclaredMembers):
        o = (rclass.m_declaredMembers - memdump_pointer_base) + i*HkClassMemberRawStruct.size
        rmember = make_hkclassmember_raw(memdump[o:o+HkClassMemberRawStruct.size]) # type: HkClassMemberRaw

        mname = idc.GetString(memdump_addr_to_ida_addr(rmember.m_name))
        mcl = rmember.m_class - memdump_pointer_base if rmember.m_class else 0
        menum = rmember.m_enum - memdump_pointer_base if rmember.m_enum else 0
        mtype = HkClassMemberType(rmember.m_type).name
        msubtype = HkClassMemberType(rmember.m_subtype).name
        marray_size = rmember.m_cArraySize
        mflags = rmember.m_flags
        moffset = rmember.m_offset

        members.append(HkClassMember(mname, mcl, menum, mtype, msubtype, marray_size, mflags, moffset)._asdict())

    name = idc.GetString(memdump_addr_to_ida_addr(rclass.m_name))
    parent = rclass.m_parent - memdump_pointer_base if rclass.m_parent else 0
    obj_size = rclass.m_objectSize
    flags = rclass.m_flags
    version = rclass.m_describedVersion
    return HkClass(name, parent, obj_size, declared_enums, members, flags, version)

def get_hkclass_list():
    # hkBuiltinTypeRegistry::StaticLinkedClasses
    ARRAY_START = 0x710254D830
    classes = [] # type: typing.List[int]
    ea = ARRAY_START
    while True:
        class_ea = struct.unpack('<Q', idaapi.get_many_bytes(ea, 8))[0]
        if not class_ea:
            break
        classes.append(class_ea)
        ea += 8

    # StaticCompoundInfo
    classes.append(0x710260E1B0)
    # ActorInfo
    classes.append(0x710260E130)
    # ShapeInfo
    classes.append(0x710260E0B0)

    return classes

def main(): # type: () -> None
    classes_by_id = dict() # type: typing.Dict[int, str]
    classes = dict() # type: typing.Dict[str, dict]
    enums_by_id = dict() # type: typing.Dict[int, dict]

    for i, class_ea in enumerate(get_hkclass_list()):
        hkclass = make_hkclass(class_ea - ida_base, enums_by_id)
        classes_by_id[class_ea - ida_base] = hkclass.name
        classes[hkclass.name] = hkclass._asdict()

    for cl in classes.itervalues():
        cl['parent'] = classes_by_id[cl['parent']] if cl['parent'] else None
        for member in cl['members']:
            member['cl'] = classes_by_id.get(member['cl'], '???') if member['cl'] else None

    with open(os.path.dirname(os.path.realpath(__file__)) + '/../havok_reflection_info.json', 'w') as f:
        json.dump({'enums_by_id': enums_by_id, 'classes': classes}, f, ensure_ascii=False, indent=2)

main()
