# Tool documentation

## First setup

* Make sure Python 3.6+ is installed
* Run: `pip install byml sarc rstb`

Additionally, for filesystem utilities:

* Install [WinFsp](http://www.secfs.net/winfsp/download/)
* Install other dependencies: `pip install fusepy colorama`

## BYML converters

Usage instructions can be [found here](https://github.com/leoetlino/byml-v2/blob/master/USAGE.md).

## SARC

Usage instructions can be [found here](https://pypi.org/project/sarc/).

## rstbtool

Usage instructions can be [found here](https://pypi.org/project/rstb/).

## botw-overlayfs

Additional requirement: fusepy (and on Windows, WinFsp)

Allows overlaying several game content directories and presenting a single merged view.

    botw-overlayfs  CONTENT_DIRS   TARGET_MOUNT_DIR

Pass as many content directories (layers) as required.
Directories take precedence over the ones on their left.

By default, the view is read-only. If you pass `--workdir` then any files you modify or create
in the view will be transparently saved to the work directory. Useful for modifying game files
without trashing the original files and without having to keep large backups.

Usage example:

    botw-overlayfs  botw/base/ botw/update/   botw/merged/

Then you can access `botw/merged/System/Version.txt` and have it show 1.5.0.

## botw-contentfs

Additional requirement: fusepy (and on Windows, WinFsp)

A tool to make game content extremely easy to access and modify.

Files that are in archives can be read and written to
*without having to unpack/repack an archive ever*.

    botw-contentfs  CONTENT_DIR   TARGET_MOUNT_DIR

By default, the view is read-only. If you pass `--workdir` then any files you modify or create
in the view will be transparently saved to the work directory. Extremely useful when used
in conjunction with the patcher (see below) for effortlessly patching game files.

Usage example:

    botw-contentfs  botw/merged/   botw/content/ --workdir botw/mod-files/

You can now access files that are in SARCs directly! Example: `botw/content/Pack/Bootup.pack/Actor/GeneralParamList/Dummy.bgparamlist`

## patcher

Additional requirement: colorama

Converts an extracted content patch directory into a loadable content layer.

This tool will repack any extracted archives and update the file sizes
in the Resource Size Table automatically.

    patcher  ORIGINAL_CONTENT_DIR   MOD_DIR  TARGET_DIR  --target {wiiu,switch}

Usage example:

    patcher  botw/merged/  botw/mod-files/  botw/patched-files/

The patched files can be used on console or with botw-overlayfs.

## botw-edit

Additional requirement: colorama, fusepy (and on Windows, WinFsp)

A convenience wrapper that combines contentfs, overlayfs and patcher.

    botw-edit --content-view CONTENT_VIEW --patched-view PATCHED_VIEW
              --work-dir WORK_DIR
              --target {wiiu,switch}
              CONTENT_DIRECTORIES

CONTENT_VIEW is the path to the directory where the extracted view should be mounted.

WORK_DIR is where files you modify and create will be stored.

PATCHED_VIEW is where the patched view should be mounted. If you use cemu for example,
this can be the path to the title content directory: `/mlc01/usr/title/00050000/101C9500/content/`

For CONTENT_DIRECTORIES, pass the base content directory, then the update content.

Usage example:

    botw-edit --content-view botw/view/  --patched-view wiiu/mlc01/usr/title/00050000/101C9500/content/
              --work-dir botw/patches/
              --target wiiu
              botw/base/ botw/update/

Then you can edit files in `botw/view/` and test them immediately, without ever having to keep
unneeded copies or manually create archives.

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
