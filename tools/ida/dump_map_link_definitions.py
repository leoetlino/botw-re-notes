from collections import namedtuple, OrderedDict
import idaapi
import idautils
import idc
import os
import struct
import yaml

# only valid in Switch 1.5.0
ARRAY_START = 0x71024DB0C0

MapLinkDefinition = namedtuple('MapLinkDefinition', 'name description num')
MapLinkDefinitionStruct = struct.Struct('<QQIxxxx')

with open(os.path.dirname(os.path.realpath(__file__)) + '/../map_link_definitions.yml', 'wb') as file:
    data = [] # type: list
    ea = ARRAY_START
    for i in range(42):
        raw_data = idaapi.get_many_bytes(ea, MapLinkDefinitionStruct.size)
        s = MapLinkDefinition._make(MapLinkDefinitionStruct.unpack(raw_data))
        s = s._replace(name=idc.GetString(s.name), description=idc.GetString(s.description))
        data.append(s._asdict())
        ea += MapLinkDefinitionStruct.size

    dumper = yaml.CSafeDumper # type: ignore
    represent_dict_order = lambda self, data:  self.represent_mapping('tag:yaml.org,2002:map', data.items())
    yaml.add_representer(OrderedDict, represent_dict_order, Dumper=dumper)
    yaml.dump(data, file, allow_unicode=True, width=120, Dumper=dumper)
