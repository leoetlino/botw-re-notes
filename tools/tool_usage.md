# Tool documentation

## BYML converters

Usage instructions can be [found here](https://github.com/leoetlino/byml-v2/blob/master/USAGE.md).

## SARC

Usage instructions can be [found here](https://pypi.org/project/sarc/).

## rstbtool

Usage instructions can be [found here](https://pypi.org/project/rstb/).

## FS utilities (botw-overlayfs, botw-contentfs, botw-edit, botw-patcher)

Usage instructions can be [found here](https://pypi.org/project/botwfstools/).

## parse_rstb

```
usage: parse_rstb [-h] [--aoc AOC] [-b] [--csv [CSV]] content_dir

Parses a RSTB (Resource Size TaBle) file.

positional arguments:
  content_dir  Path to a Breath of the Wild content root

optional arguments:
  -h, --help   show this help message and exit
  --aoc AOC    Path to a Breath of the Wild AoC root
  -b, --be     Use big endian. Defaults to false.
  --csv [CSV]  Path to output CSV for size information
```

## parse_scaling_config

Additional requirement: texttable

```
usage: parse_scaling_config [-h] [--kill_table_csv [KILL_TABLE_CSV]]
                            [--enemy_scaling_csv [ENEMY_SCALING_CSV]]
                            [--weapon_scaling_csv [WEAPON_SCALING_CSV]]
                            byml

Parses and prints information about scaling config.

positional arguments:
  byml                  Path to LevelSensor.byml

optional arguments:
  -h, --help            show this help message and exit
  --kill_table_csv [KILL_TABLE_CSV]
                        Path to output CSV for kill table information
  --enemy_scaling_csv [ENEMY_SCALING_CSV]
                        Path to output CSV for enemy scaling information
  --weapon_scaling_csv [WEAPON_SCALING_CSV]
                        Path to output CSV for weapon scaling information
```
