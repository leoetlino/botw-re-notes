from collections import namedtuple, OrderedDict
import idaapi
import idautils
import idc
import os
import struct
import yaml

# only valid in Switch 1.5.0
ARRAY_START = 0x00000071024CB7C8

AglenvFileInfo = namedtuple('AglenvFileInfo', 'id i0 ext bext s align system desc')
SwitchStruct = struct.Struct('<IIQQQixxxxQQ')

with open(os.path.dirname(os.path.realpath(__file__)) + '/../aglenv_file_info.yml', 'wb') as file:
    data = [] # type: list
    ea = ARRAY_START
    while True:
        raw_data = idaapi.get_many_bytes(ea, SwitchStruct.size)
        s = AglenvFileInfo._make(SwitchStruct.unpack(raw_data))
        if s.id == 0xFFFFFFFF:
            break

        s = s._replace(ext=idc.GetString(s.ext),
                       bext=idc.GetString(s.bext),
                       s=idc.GetString(s.s),
                       system=idc.GetString(s.system),
                       desc=idc.GetString(s.desc),
                      )
        data.append(s._asdict())
        ea += SwitchStruct.size

    dumper = yaml.CSafeDumper # type: ignore
    represent_dict_order = lambda self, data:  self.represent_mapping('tag:yaml.org,2002:map', data.items())
    yaml.add_representer(OrderedDict, represent_dict_order, Dumper=dumper)
    yaml.dump(data, file, allow_unicode=True, width=120, Dumper=dumper)
