import argparse
from collections import defaultdict
from operator import itemgetter
from pathlib import Path
import sys
import typing
import yaml

import byml
import byml.yaml_util

# From PyYAML: https://github.com/yaml/pyyaml/blob/a9c28e0b52/lib3/yaml/representer.py
# with the sorting code removed.
def represent_mapping(dumper, tag, mapping, flow_style=None, sort=False):
    value = [] # type: ignore
    node = yaml.MappingNode(tag, value, flow_style=flow_style)
    best_style = True
    if hasattr(mapping, 'items'):
        mapping = list(mapping.items())
        if sort:
            try:
                mapping = sorted(mapping)
            except TypeError:
                pass
    for item_key, item_value in mapping:
        node_key = dumper.represent_data(item_key)
        node_value = dumper.represent_data(item_value)
        if not (isinstance(node_key, yaml.ScalarNode) and not node_key.style):
            best_style = False
        if not (isinstance(node_value, yaml.ScalarNode) and not node_value.style):
            best_style = False
        value.append((node_key, node_value))
    if flow_style is None:
        if dumper.default_flow_style is not None:
            node.flow_style = dumper.default_flow_style
        else:
            node.flow_style = best_style
    return node

def represent_dict(dumper, mapping, flow_style=None):
    return represent_mapping(dumper, 'tag:yaml.org,2002:map', mapping, flow_style)
def represent_dict_sort(dumper, mapping, flow_style=None):
    return represent_mapping(dumper, 'tag:yaml.org,2002:map', mapping, flow_style, sort=True)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("gamedata_dir", help="Path to the gamedata.sarc/ directory")
    args = parser.parse_args()
    DIR = Path(args.gamedata_dir)

    byml.yaml_util.add_representers(yaml.CSafeDumper)
    yaml.add_representer(dict, represent_dict, Dumper=yaml.CSafeDumper)
    yaml.add_representer(defaultdict, represent_dict_sort, Dumper=yaml.CSafeDumper)

    flags_per_reset_type: typing.Dict[int, list] = defaultdict(list)
    DATATYPES = ("bool", "s32", "f32", "string", "string64", "string256", "vector2f", "vector3f", "vector4",
        "bool_array", "s32_array", "f32_array", "string32_array", "string64_array", "string256_array", "vector2f_array", "vector3f_array", "vector4_array")

    for bgdata_path in DIR.glob("*.bgdata"):
        bgdata = byml.Byml(bgdata_path.open("rb").read()).parse()

        for datatype in DATATYPES:
            key = datatype + "_data"
            if key not in bgdata:
                continue
            flags = bgdata[key]
            for flag in flags:
                assert flag["DeleteRev"] == -1
                reset_type = flag["ResetType"]
                perms = ["-", "-"]
                if flag["IsProgramReadable"]:
                    perms[0] = "r"
                if flag["IsProgramReadable"]:
                    perms[1] = "w"
                flags_per_reset_type[reset_type].append({
                    "name": flag["DataName"],
                    "t": datatype,
                    "init": flag["InitValue"],
                    "min": flag["MinValue"],
                    "max": flag["MaxValue"],
                    "perms": "".join(perms),
                    "event": flag["IsEventAssociated"],
                    "save": flag["IsSave"],
                    "hash": flag["HashValue"] & 0xffffffff,
                    "reset_type": reset_type,
                })

    for x in flags_per_reset_type.values():
        x.sort(key=itemgetter("name"))
    yaml.dump(flags_per_reset_type, sys.stdout, Dumper=yaml.CSafeDumper)

main()
