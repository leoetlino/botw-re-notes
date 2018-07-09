# Tool documentation

## Common requirements

* [Python 3.6+](https://www.python.org/downloads/release/python-360/)
* PyYAML. [Windows builds can be found here](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pyyaml) (choose the package that corresponds to your Python version and win32 for 32-bit, amd64 for 64-bit and install them with `pip install`)
* [wszst](https://szs.wiimm.de/download.html) for yaz0 support

## byml converter

This lives in a [separate repository](https://github.com/leoetlino/byml-v2).

Usage instructions can be [found there](https://github.com/leoetlino/byml-v2/blob/master/USAGE.md).

## sarctool

A simple tool to manipulate SARC archives.

### List files in an archive

    sarctool list ARCHIVE

### Extract an archive

    sarctool extract ARCHIVE

### Create an archive

    sarctool create [--be] FILES_TO_ADD  DEST_SARC

You can give it directories too, in which case the entire directory will be added to the archive
recursively.

Pass `--be` (shorthand: `-b`) if you want sarctool to use big endian mode (for the Wii U).

An important option is `--base-path`. This option lets you remove parts of the path.
For example, if you pass a path like `Mods/BotW/System/Version.txt`, you will likely want to pass
`--base-path Mods/BotW` to get rid of the leading components.

If only a single directory is passed, the base path is set for you automatically.

So typical usage example:

    sarctool create  ~/botw/Bootup/  ~/botw/ModifiedBootup.pack

### Update an archive

    sarctool update  FILES_TO_ADD  SARC_TO_MODIFY

This is almost identical to `create`.

By default, sarctool will keep the endianness of the original archive. You can override this
with `--endian {le,be}` (le for little and be for big endian).

### Delete files from an archive

    sarctool delete  FILES_TO_DELETE  SARC_TO_MODIFY

Nothing much to say here. Just keep in mind FILES_TO_DELETE takes archive paths
(those that are printed by `list`).

## rstbtool

A tool to manipulate the [RSTB (Resource Size TaBle)](https://github.com/leoetlino/botw-re-notes/blob/master/resource_system.md#resource-size-table).

It is recommended to familiarize yourself with how the resource system works (roughly)
and how resources are listed
([Wii U RSTB](https://github.com/leoetlino/botw-re-notes/blob/master/game_files/wiiu_rstb_150.csv),
[Switch RSTB](https://github.com/leoetlino/botw-re-notes/blob/master/game_files/switch_rstb_150.csv))
in the table before modifying resource entries.

For all commands, you must pass `--be` if you are dealing with a big endian RSTB (Wii U version).

### Get a resource size

    rstbtool  [--be]  path/to/ResourceSizeTable.product.srsizetable  get  RESOURCE_NAME

### Set a resource size

    rstbtool  [--be]  path/to/ResourceSizeTable.product.srsizetable  set  RESOURCE_NAME  NEW_SIZE

NEW_SIZE can be an integer (hex or decimal), in which case the size will be set directly.

Or it can be a path on your _host filesystem_ (unlike RESOURCE_NAME). In that case rstbtool
will automatically calculate the size value it should write to the RSTB.

The RESOURCE_NAME must exist in the RSTB for this command.

### Add a resource size

    rstbtool  [--be]  path/to/ResourceSizeTable.product.srsizetable  add  RESOURCE_NAME  NEW_SIZE

Same as `set`, except the RESOURCE_NAME must *not* exist in the RSTB for this command.

### Delete a resource size

    rstbtool  [--be]  path/to/ResourceSizeTable.product.srsizetable  del  RESOURCE_NAME

Warning: deleting the entry for a resource will make the game waste precious memory
when loading it, since the resource system will fall back to a different, wasteful method
of calculating how much memory to allocate (see the resource system notes for more details).

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
