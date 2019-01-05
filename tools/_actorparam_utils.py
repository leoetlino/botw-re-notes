import aamp
import csv
import json
from pathlib import Path
import typing

_names = json.load((Path(__file__).resolve().parent / 'botw_names.json').open('r'))

def _represent_float(value: float):
    s = f'{value:g}'
    if 'e' not in s and '.' not in s:
        s += '.0'
    return s

def _format_value(value) -> str:
    if isinstance(value, float):
        return _represent_float(value)
    if isinstance(value, str):
        return value
    return str(value)

class Prop(typing.NamedTuple):
    obj: str
    param: str
    column_name: str
    format_fn: typing.Callable[[typing.Any], str] = _format_value

"""A function that should return true or false given an actor name."""
ActorPredicate = typing.Callable[[str], bool]
def dump_to_csv(content_dir: Path, predicate: ActorPredicate, props: typing.Iterable[Prop], f: typing.TextIO) -> None:
    actorpack_dir = (content_dir/'Actor/Pack')

    writer = csv.writer(f)
    header = ['Actor', 'Name']
    header.extend(prop.column_name for prop in props)
    writer.writerow(header)

    for actorpack in actorpack_dir.glob('*'):
        actor_name = actorpack.stem
        if not predicate(actor_name):
            continue
        try:
            bgparamlist_p = next((actorpack/'Actor/GeneralParamList').glob('*.bgparamlist'))
            pio = aamp.Reader(bgparamlist_p.open('rb').read()).parse()
            proot = pio.list('param_root')

            cols = [actor_name, _names.get(actor_name, '?')]
            for prop in props:
                value = proot.object(prop.obj).param(prop.param)
                cols.append(prop.format_fn(value))
            writer.writerow(cols)
        except StopIteration:
            continue
