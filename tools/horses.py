import aamp
import csv
import json
from pathlib import Path
import sys
import typing

names = json.load((Path(__file__).resolve().parent / 'botw_names.json').open('r'))
content_dir = Path(sys.argv[1])
actorpack_dir = (content_dir/'Actor/Pack')

def represent_float(value: float):
    s = f'{value:g}'
    if 'e' not in s and '.' not in s:
        s += '.0'
    return s

def format_value(value) -> str:
    if isinstance(value, float):
        return represent_float(value)
    if isinstance(value, str):
        return value
    return str(value)

class Prop(typing.NamedTuple):
    obj: str
    param: str
    column_name: str
    format_fn: typing.Callable[[typing.Any], str] = format_value

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

writer = csv.writer(sys.stdout)
header = ['Actor', 'Name']
header.extend(prop.column_name for prop in PROPERTIES)
writer.writerow(header)

for actorpack in actorpack_dir.glob('*'):
    actor_name = actorpack.stem
    if not actor_name.startswith('GameRomHorse'):
        continue
    try:
        bgparamlist_p = next((actorpack/'Actor/GeneralParamList').glob('*.bgparamlist'))
        pio = aamp.Reader(bgparamlist_p.open('rb').read()).parse()
        proot = pio.list('param_root')

        try:
            proot.object('HorseObject')
            continue
        except KeyError:
            pass

        cols = [actor_name, names.get(actor_name, '?')]
        for prop in PROPERTIES:
            cols.append(prop.format_fn(proot.object(prop.obj).param(prop.param)))
        writer.writerow(cols)
    except StopIteration:
        continue
