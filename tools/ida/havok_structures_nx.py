from collections import namedtuple
from enum import IntEnum
import struct
import typing

# hkClass:
# 00000000 const char* m_name
# 00000008 hkClass* m_parent
# 00000010 int m_objectSize
# 00000014 int m_numImplementedInterfaces
# 00000018 hkClassEnum* m_declaredEnums
# 00000020 int m_numDeclaredEnums
# 00000028 hkClassMember* m_declaredMembers
# 00000030 int m_numDeclaredMembers
# 00000038 const void* m_defaults
# 00000040 hkCustomAttributes* m_attributes
# 00000048 hkFlags<enum hkClass::FlagValues,unsigned int> m_flags
# 0000004C int m_describedVersion
# 00000050 END
HkClassRaw = namedtuple('HavokClassRaw', 'm_name m_parent m_objectSize m_numImplementedInterfaces m_declaredEnums m_numDeclaredEnums m_declaredMembers m_numDeclaredMembers m_defaults m_attributes m_flags m_describedVersion')
HkClassRawStruct = struct.Struct('<QQiiQixxxxQixxxxQQIi')
assert HkClassRawStruct.size == 0x50
HkClass = namedtuple('HkClass', 'name parent obj_size enums members flags version')

def make_hkclass_raw(data): # type: (bytes) -> HkClassRaw
    return HkClassRaw._make(HkClassRawStruct.unpack(data))

# hkClassEnum:
# 00000000 const char* m_name
# 00000008 hkClassEnum::Item* m_items
# 00000010 int m_numItems
# 00000018 hkCustomAttributes* m_attributes
# 00000020 hkFlags<enum hkClass::FlagValues,unsigned int> m_flags
# 00000028 END
HkClassEnumRaw = namedtuple('HavokClassEnumRaw', 'm_name m_items m_numItems m_attributes m_flags')
HkClassEnumRawStruct = struct.Struct('<QQi4xQI4x')
assert HkClassEnumRawStruct.size == 0x28
HkClassEnum = namedtuple('HkClassEnum', 'name items flags')

def make_hkclassenum_raw(data): # type: (bytes) -> HkClassEnumRaw
    return HkClassEnumRaw._make(HkClassEnumRawStruct.unpack(data))

# hkClassEnum::Item:
# 00000000 unsigned int m_value
# 00000008 const char* m_name
# 00000010 END
HkClassEnumItemRaw = namedtuple('HavokClassEnumItemRaw', 'm_value m_name')
HkClassEnumItemRawStruct = struct.Struct('<I4xQ')
assert HkClassEnumItemRawStruct.size == 0x10
HkClassEnumItem = namedtuple('HkClassEnumItem', 'value name')

def make_hkclassenumitem_raw(data): # type: (bytes) -> HkClassEnumItemRaw
    return HkClassEnumItemRaw._make(HkClassEnumItemRawStruct.unpack(data))

# enum hkClassMember::Type
class HkClassMemberType(IntEnum):
    TYPE_VOID = 0
    TYPE_BOOL = 1
    TYPE_CHAR = 2
    TYPE_INT8 = 3
    TYPE_UINT8 = 4
    TYPE_INT16 = 5
    TYPE_UINT16 = 6
    TYPE_INT32 = 7
    TYPE_UINT32 = 8
    TYPE_INT64 = 9
    TYPE_UINT64 = 10
    TYPE_REAL = 11
    TYPE_VECTOR4 = 12
    TYPE_QUATERNION = 13
    TYPE_MATRIX3 = 14
    TYPE_ROTATION = 15
    TYPE_QSTRANSFORM = 16
    TYPE_MATRIX4 = 17
    TYPE_TRANSFORM = 18
    TYPE_ZERO = 19
    TYPE_POINTER = 20
    TYPE_FUNCTIONPOINTER = 21
    TYPE_ARRAY = 22
    TYPE_INPLACEARRAY = 23
    TYPE_ENUM = 24
    TYPE_STRUCT = 25
    TYPE_SIMPLEARRAY = 26
    TYPE_HOMOGENEOUSARRAY = 27
    TYPE_VARIANT = 28
    TYPE_CSTRING = 29
    TYPE_ULONG = 30
    TYPE_FLAGS = 31
    TYPE_HALF = 32
    TYPE_STRINGPTR = 33
    TYPE_RELARRAY = 34
    TYPE_MAX = 35

# hkClassMember
# 00000000 const char* m_name
# 00000008 hkClass* m_class
# 00000010 hkClassEnum* m_enum
# 00000018 hkEnum<enum hkClassMember::Type,unsigned char> m_type
# 00000019 hkEnum<enum hkClassMember::Type,unsigned char> m_subtype
# 0000001A unsigned short m_cArraySize
# 0000001C hkFlags<enum hkClassMember::FlagValues,unsigned short> m_flags
# 0000001E unsigned short m_offset
# 00000020 hkCustomAttributes* m_attributes
# 00000028 END
HkClassMemberRaw = namedtuple('HavokClassMemberRaw', 'm_name m_class m_enum m_type m_subtype m_cArraySize m_flags m_offset m_attributes')
HkClassMemberRawStruct = struct.Struct('<QQQBBHHHQ')
assert HkClassMemberRawStruct.size == 0x28
HkClassMember = namedtuple('HkClassMember', 'name cl enum type subtype array_size flags offset')

def make_hkclassmember_raw(data): # type: (bytes) -> HkClassMemberRaw
    return HkClassMemberRaw._make(HkClassMemberRawStruct.unpack(data))
