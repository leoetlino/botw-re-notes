# Game files

This document explains what files are included in game_files/ and where they can be found
in the romfs.

## Tools
* [`SARCExtract`](https://github.com/NWPlayer123/WiiUTools/blob/master/SARCTools/SARCExtract.py)
(note: needs patches to handle little endian files for the Switch version).
Useful to extract pack archives.

* `wszst` or any other tool to decompress yaz0 files. yaz0-compressed files usually have a `s`
prefix in their file extension.

* [`byml-v2`](https://github.com/leoetlino/byml-v2) for byml files. These usually have the .byml
file extension, but not always.

* [`BotW-aampTool`](https://github.com/Zer0XoL/BotW-aampTool) for AAMP files. These usually have
the .bxml file extension, but not always.

## Included files

### LevelSensor.yml
  Difficulty scaling configuration. Can be found at Pack/Bootup.pack@/Ecosystem/LevelSensor.sbyml.

### Item pictures
  Inventory item pictures. Can be found at UI/StockItem/*.bitemico.

  They can be automatically converted to png in a two step process. Copy the included `bfres_to_dds.py`
  script next to [BFRES-Tool](https://github.com/aboood40091/BFRES-Tool) files, then run it
  for each bitemico. The dds files can then be converted to png with mogrify.

  ```
  find $BOTW_ROMFS/UI/StockItem/ -name '*.dds' -exec mogrify -format png -channel rgba -separate -swap 0,2 -combine '{}' +
  ```

  Yes, swapping color channels manually is a workaround. I didn't feel like investigating
  the bug in BFRES-Tool.

## Misc information

Bootup.pack: SARC archive
- Ecosystem
  * LevelSensor: enemy and weapon scaling information

Map: actor locations

ActorInfo/Pack:
- AIProgram: AI
- ActorLink: (bxml) some flags
- AS: animations?
- ASList: list of animations
- DamageParam: enemy reactions to different damage types, damage points, properties (is shockable, drown, DamageRate per weapon type, burn damage, Urbosa's Fury...)
- DropTable: lists of actors + drop probablities
- GeneralParamList: general properties.
  * actor name HP, enemy info, rank, enemy level: intelligence
  * enemy race: equipable weapons, target victims, which actors to escape from
  * *unused (?)*: attack power, power for player
  * throwable items
  * food targets (favourite food actor names, actor tags for things the actor will eat)
