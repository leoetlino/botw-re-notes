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

    result: typing.List[dict] = []

    for bgdata_path in DIR.glob("*.bgdata"):
        bgdata = byml.Byml(bgdata_path.open("rb").read()).parse()

        flags = bgdata.get("bool_data", None)
        if not flags:
            continue
        for flag in flags:
            reset_data = flag["InitValue"] >> 1
            if reset_data == 0:
                continue
            assert flag["ResetType"] == 0
            assert flag["DeleteRev"] == -1
            assert flag["IsProgramReadable"] and flag["IsProgramWritable"]
            assert flag["IsSave"]
            assert flag["MinValue"] is False and flag["MaxValue"] is True
            assert flag["InitValue"] & 1 == 0

            row = (reset_data - 1) & 0b111
            col = (reset_data - 1) >> 3

            result.append({
                "name": flag["DataName"],
                "hash": flag["HashValue"] & 0xffffffff,
                "col": col,
                "row": row,
            })

    result.sort(key=itemgetter("name"))
    yaml.dump(result, sys.stdout, Dumper=yaml.CSafeDumper)

main()
