#!/usr/bin/env python3
import argparse
import collections
import json
from pathlib import Path
from shapely.geometry import box, MultiPolygon, mapping
from shapely.ops import unary_union
import typing

import beco

def process(beco_path: Path, dest_path: Path) -> None:
    with beco_path.open('rb') as f:
        b = beco.Beco(f.read())

    print(f'divisor: {b.get_divisor()}')
    print(f'number of rows: {b.get_num_rows()}')

    # build areas for each area number
    areas: typing.Dict[int, typing.List[typing.Any]] = collections.defaultdict(list)
    for i in range(b.get_num_rows() - 1):
        segments = b.get_segments_for_row(i)
        minz = i * b.get_divisor() - 4000.0 - 0.5
        maxz = (i+1) * b.get_divisor() - 4000.0 - 0.5

        x_divisor = 10 if b.get_divisor() == 10 else 1
        minx = -5000.0
        for segment in segments:
            areas[segment.data].append(box(minx, minz, minx + segment.length * x_divisor, maxz))
            minx += segment.length * x_divisor

    calc_areas: typing.Dict[int, typing.Any] = dict()
    for data, rects in areas.items():
        area = unary_union(rects)
        if area.type == 'MultiPolygon':
            calc_areas[data] = [mapping(a) for a in area]
        else:
            calc_areas[data] = [mapping(area)]

    with dest_path.open('w') as dest:
        json.dump(calc_areas, dest)

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('eco_dir', type=Path)
    args = parser.parse_args()

    for beco_path in args.eco_dir.glob('*.beco'):
        print('[+] ' + beco_path.stem)
        process(beco_path, beco_path.with_suffix('.json'))

main()
