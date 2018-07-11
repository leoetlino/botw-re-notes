import binascii
import idaapi # type: ignore
import idc # type: ignore
import os
import struct
import typing

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

STRUCT_SIZE = 0x10
for category, address, size in TABLES:
    for i in range(size):
        entry = idaapi.get_many_bytes(address + STRUCT_SIZE*i, STRUCT_SIZE)
        crc, padding, fn = struct.unpack('<IIQ', entry)
        name = aidef_crc.get(crc, "Unknown_%08x" % crc)
        function_name = "AI_F_%s_%s" % (category, name)
        idc.MakeNameEx(fn, function_name, idc.SN_NOWARN)
        idc.SetType(fn, "void* makeHandler(void* param, sead::Heap* heap);")
        if "BL              operator new" in idc.GetDisasm(fn + 6*4) and idc.GetMnem(fn + 9*4) == "BL":
            ctor_addr = idc.GetOperandValue(fn + 9*4, 0)
            idc.MakeNameEx(ctor_addr, "AI_%s_%s::ctor" % (category, name), idc.SN_NOWARN)
            idc.SetType(ctor_addr, "void ctor(void* this, void* param);")
