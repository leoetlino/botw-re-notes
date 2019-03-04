#!/usr/bin/env python3
from pathlib import Path
import sys
from _actorparam_utils import Prop, dump_to_csv

PROPERTIES = (
    Prop('General', 'Life', 'Life'),
    Prop('Attack', 'Power', 'Atk'),
    Prop('Bow', 'QuiverName', 'QuiverName'),
    Prop('Bow', 'ArrowName', 'ArrowName'),
    Prop('Bow', 'IsGuardPierce', 'IsGuardPierce'),
    Prop('Bow', 'ExtraDamageRatio', 'ExtraDamageRatio'),
    Prop('Bow', 'BaseAttackPowerRatio', 'BaseAttackPowerRatio'),
    Prop('Bow', 'IsLeadShot', 'IsLeadShot'),
    Prop('Bow', 'LeadShotNum', 'LeadShotNum'),
    Prop('Bow', 'LeadShotAng', 'LeadShotAng'),
    Prop('Bow', 'LeadShotInterval', 'LeadShotInterval'),
    Prop('Bow', 'IsRapidFire', 'IsRapidFire'),
    Prop('Bow', 'RapidFireNum', 'RapidFireNum'),
    Prop('Bow', 'RapidFireInterval', 'RapidFireInterval'),
    Prop('Bow', 'IsLongRange', 'IsLongRange'),
    Prop('Bow', 'ArrowFirstSpeed', 'ArrowFirstSpeed'),
    Prop('Bow', 'ArrowAcceleration', 'ArrowAcceleration'),
    Prop('Bow', 'ArrowStabilitySpeed', 'ArrowStabilitySpeed'),
    Prop('Bow', 'ArrowFallAcceleration', 'ArrowFallAcceleration'),
    Prop('Bow', 'ArrowFallStabilitySpeed', 'ArrowFallStabilitySpeed'),
    Prop('Bow', 'ArrowGravity', 'ArrowGravity'),
    Prop('Bow', 'ArrowChargeRate', 'ArrowChargeRate'),
    Prop('Bow', 'ArrowReloadRate', 'ArrowReloadRate'),
)

def predicate(actor_name: str) -> bool:
    if not actor_name.startswith('Weapon_Bow_'):
        return False
    return True

dump_to_csv(Path(sys.argv[1]), predicate, PROPERTIES, sys.stdout)
