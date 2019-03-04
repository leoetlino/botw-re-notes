#!/usr/bin/env python3
import pprint
import typing
import yaml

import argparse
import byml
import byml.yaml_util
from pathlib import Path
import wszst_yaz0
import zlib
from _map_utils import Map

actorinfodata = byml.Byml((Path(__file__).parent.parent/'game_files'/'ActorInfo.product.byml').open('rb').read()).parse()
def get_actor_data(name):
    h = zlib.crc32(name.encode())
    hashes = actorinfodata['Hashes']
    a = 0
    b = len(hashes) - 1
    while a <= b:
        m = (a + b) // 2
        if hashes[m] < h:
            a = m + 1
        elif hashes[m] > h:
            b = m - 1
        else:
            return actorinfodata['Actors'][m]
    return None

def is_flag4_actor(name):
    if name == 'Enemy_GanonBeast':
        return False
    info = get_actor_data(name)
    for x in ('Enemy', 'GelEnemy', 'SandWorm', 'Prey', 'Dragon', 'Guardian'):
        if info['profile'] == x:
            return True
    if 'NPC' in info['profile']:
        return True
    return False

def should_spawn_obj(obj):
    name = obj['UnitConfigName']
    if is_flag4_actor(name):
        return False
    if name == 'Enemy_Guardian_A':
        return False
    if 'Entrance' in name or 'WarpPoint' in name or 'Terminal' in name:
        return False
    return True

def main() -> None:
    parser = argparse.ArgumentParser('Shows actors that are not spawned when in final boss mode.')
    parser.add_argument('map_path', help='Path to a map unit (BYAML or compressed BYAML or YAML)')
    args = parser.parse_args()
    MAP_PATH: str = args.map_path

    byml.yaml_util.add_constructors(yaml.CSafeLoader)
    with open(MAP_PATH, 'rb') as f:
        if MAP_PATH.endswith('mubin'):
            map_data = byml.Byml(wszst_yaz0.decompress(f.read())).parse()
        else:
            map_data = yaml.load(f, Loader=yaml.CSafeLoader)

    pmap = Map(map_data)
    pmap.parse_obj_links()

    skip_reasons: typing.Dict[int, str] = dict()
    skipped_objs: typing.Set[int] = set()
    for obj in pmap.objs.values():
        objid = obj['HashId']
        if objid in skipped_objs or should_spawn_obj(obj):
            continue
        skipped_objs.add(objid)
        gen_group = pmap.build_gen_group(obj)
        for linked_obj in gen_group:
            skipped_objs.add(linked_obj['HashId'])
            skip_reasons[linked_obj['HashId']] = f'linked to skipped object: 0x{obj["HashId"]:08x} {obj["UnitConfigName"]}'
        skip_reasons[objid] = 'skipped'

    for objid in skipped_objs:
        obj = pmap.get_obj(objid)
        print(f"[0x{obj['HashId']:08x}] {obj['UnitConfigName']} {tuple(obj['Translate'])}")
        if '!Parameters' in obj:
            pprint.pprint(obj['!Parameters'], indent=2)
        print(f"| SKIP REASON: {skip_reasons[objid]}")
        for link in obj['__links']:
            print(f"| LINKS TO: {link.description()}")
        for link in obj['__links_to_self']:
            print(f"| LINKED BY: {link.description()}")
        print('-'*70)

main()
