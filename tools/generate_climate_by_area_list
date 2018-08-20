#!/usr/bin/env python3
import byml
import sys
from texttable import Texttable
import wszst_yaz0



climate_ids = (
    'HyrulePlainClimate',
    'NorthHyrulePlainClimate',
    'HebraFrostClimate',
    'TabantaAridClimate',
    'FrostClimate',
    'GerudoDesertClimate',
    'GerudoPlateauClimate',
    'EldinClimateLv0',
    'TamourPlainClimate',
    'ZoraTemperateClimate',
    'HateruPlainClimate',
    'FiloneSubtropicalClimate',
    'SouthHateruHumidTemperateClimate',
    'EldinClimateLv1',
    'EldinClimateLv2',
    'DarkWoodsClimat',
    'LostWoodClimate',
    'GerudoFrostClimate',
    'KorogForest',
    'GerudoDesertClimateLv2',
)

def main() -> None:
    area_data = byml.Byml(wszst_yaz0.decompress_file(sys.argv[1])).parse()
    assert isinstance(area_data, list)

    t = Texttable(max_width=130)
    t.set_deco(Texttable.BORDER | Texttable.HEADER | Texttable.VLINES)
    t.header(['Idx', 'Area', 'Climate', 'Climate idx'])
    for area in area_data:
        t.add_row([area['AreaNumber'], area['Area'], area['Climate'], climate_ids.index(area['Climate'])])
    print(t.draw())

if __name__ == '__main__':
    main()
