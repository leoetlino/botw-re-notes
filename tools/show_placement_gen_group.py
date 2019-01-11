import pprint
import yaml

import argparse
import byml
import byml.yaml_util
import wszst_yaz0
from _map_utils import Map

def main() -> None:
    parser = argparse.ArgumentParser('Shows the placement generation group for a map object.')
    parser.add_argument('map_path', help='Path to a map unit (BYAML or compressed BYAML or YAML)')
    parser.add_argument('object_id', type=lambda x: int(x, 0), help='Map object ID (HashId)')
    args = parser.parse_args()
    MAP_PATH: str = args.map_path
    MAP_OBJID: int = args.object_id

    byml.yaml_util.add_constructors(yaml.CSafeLoader)
    with open(MAP_PATH, 'rb') as f:
        if MAP_PATH.endswith('mubin'):
            map_data = byml.Byml(wszst_yaz0.decompress(f.read())).parse()
        else:
            map_data = yaml.load(f, Loader=yaml.CSafeLoader)

    pmap = Map(map_data)
    pmap.parse_obj_links()

    gen_group = pmap.build_gen_group(pmap.get_obj(MAP_OBJID))

    for obj in gen_group:
        print(f"[0x{obj['HashId']:08x}] {obj['UnitConfigName']} {tuple(obj['Translate'])}")
        if '!Parameters' in obj:
            pprint.pprint(obj['!Parameters'], indent=2)
        for link in obj['__links']:
            print(f"| LINKS TO: {link.description()}")
        for link in obj['__links_to_self']:
            print(f"| LINKED BY: {link.description()}")
        print('-'*70)

main()
