#!/usr/bin/env python3
from pathlib import Path
import sys
from _actorparam_utils import Prop, dump_to_csv

PROPERTIES = (
    Prop('General', 'Life', 'Life'),
    Prop('Shield', 'RideBreakRatio', 'RideBreakRatio'),
    Prop('Shield', 'MirrorLevel', 'MirrorLevel'),
    Prop('Shield', 'SurfingFriction', 'SurfingFriction'),
)

def predicate(actor_name: str) -> bool:
    if not actor_name.startswith('Weapon_Shield_'):
        return False
    return True

dump_to_csv(Path(sys.argv[1]), predicate, PROPERTIES, sys.stdout)
