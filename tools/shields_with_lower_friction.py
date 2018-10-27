import aamp
import csv
import json
from pathlib import Path
import sys

names = json.load((Path(__file__).resolve().parent / 'botw_names.json').open('r'))
content_dir = Path(sys.argv[1])
actorpack_dir = (content_dir/'Actor/Pack')

def represent_float(value: float):
    s = f'{value:g}'
    if 'e' not in s and '.' not in s:
        s += '.0'
    return s

print('Actor,Name,Life,RideBreakRatio,MirrorLevel,SurfingFriction')
for actorpack in actorpack_dir.glob('*'):
    actor_name = actorpack.stem
    if not actor_name.startswith('Weapon_Shield_'):
        continue
    try:
        bgparamlist_p = next((actorpack/'Actor/GeneralParamList').glob('*.bgparamlist'))
        pio = aamp.Reader(bgparamlist_p.open('rb').read()).parse()
        proot = pio.list('param_root')
        general = proot.object('General')
        shield = proot.object('Shield')

        print(','.join((
            actor_name,
            names[actor_name],
            str(general.param('Life')),
            represent_float(shield.param('RideBreakRatio')),
            str(shield.param('MirrorLevel')),
            represent_float(shield.param('SurfingFriction')),
        )))
    except StopIteration:
        continue
