#!/usr/bin/env python3
from pathlib import Path
import sys
from _actorparam_utils import Prop, dump_to_csv

PROPERTIES = (
    Prop('General', 'Life', 'Life'),
    Prop('Attack', 'Power', 'Atk'),
    Prop('AnimalUnit', 'StressFramesMin', 'StressFramesMin'),
    Prop('AnimalUnit', 'StressFramesMax', 'StressFramesMax'),
    Prop('AnimalUnit', 'SteeringOutputKp', 'SteeringOutputKp'),
    Prop('AnimalUnit', 'SteeringOutputKi', 'SteeringOutputKi'),
    Prop('AnimalUnit', 'SteeringOutputKd', 'SteeringOutputKd'),
    Prop('AnimalUnit', 'SteeringOutputIClamp', 'SteeringOutputIClamp'),
    Prop('AnimalUnit', 'SteeringOutputIReduceRatio', 'SteeringOutputIReduceRatio'),
    Prop('AnimalUnit', 'SteeringOutputDLerpRatio', 'SteeringOutputDLerpRatio'),
    Prop('AnimalUnit', 'SteeringOutputAvoidanceLerpRatio', 'SteeringOutputAvoidanceLerpRatio'),
    Prop('AnimalUnit', 'SteeringOutputIIRLerpRatio', 'SteeringOutputIIRLerpRatio'),
    Prop('AnimalUnit', 'OverrideSteeringOutputKp', 'OverrideSteeringOutputKp'),
    Prop('AnimalUnit', 'OverrideSteeringOutputKi', 'OverrideSteeringOutputKi'),
    Prop('AnimalUnit', 'OverrideSteeringOutputKd', 'OverrideSteeringOutputKd'),
    Prop('Horse', 'ASVariation', 'ASVariation'),
    Prop('Horse', 'Nature', 'Nature'),
    Prop('Horse', 'AttackPowerMultiplierGear2', 'AttackPowerMultiplierGear2'),
    Prop('Horse', 'AttackPowerMultiplierGear3', 'AttackPowerMultiplierGear3'),
    Prop('Horse', 'AttackPowerMultiplierGearTop', 'AttackPowerMultiplierGearTop'),
    Prop('Horse', 'RunnableFramesAtGearTop', 'RunnableFramesAtGearTop'),
    Prop('Horse', 'GearTopInterval', 'GearTopInterval'),
    Prop('Horse', 'GearTopChargeNum', 'GearTopChargeNum'),
    Prop('Horse', 'EatActorNames', 'EatActorNames'),
    Prop('Horse', 'EatActorNamesForExtraCharge', 'EatActorNamesForExtraCharge'),
    Prop('HorseUnit', 'RiddenAnimalType', 'RiddenAnimalType'),
    Prop('HorseUnit', 'CalmDownNum', 'CalmDownNum'),
)

def predicate(actor_name: str) -> bool:
    if not actor_name.startswith('GameRomHorse'):
        return False
    if 'Saddle' in actor_name or 'Reins' in actor_name:
        return False
    return True

dump_to_csv(Path(sys.argv[1]), predicate, PROPERTIES, sys.stdout)
