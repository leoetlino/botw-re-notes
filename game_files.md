# Game files

This document explains what files are included in game_files/ and where they can be found
in the romfs.

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

Pack/Bootup.pack: SARC archive
- Cooking
  * CookData: cooking information (byml). The key names are not very descriptive, though.
- Ecosystem
  * LevelSensor: enemy and weapon scaling information
- Event
  * EventInfo.product.yml: cutscenes (internally 'Demo'), including FMVs, and dialogue information
- Map
  * MainField/Location.mubin (byml): UI map location texts
  * MainField/Static.mubin (byml): UI map markers? Contains warp information and save flags
  * CDungeon/Static.mubin: Contains StartPos entries (Map -- dungeon map name, PosName -- often Entrance_1)
  * MainFieldDungeon/Static.mubin: Same thing, but for Divine Beasts. PosName can be StartDemoEnter (and also EndDemo118_0 for Vah Medoh)
- UI
  * MapTex/MainFieldArea.byaml: UI map information (list of tiles e.g. A-0, A-1, map changes with save flags e.g. Tarry Town, Eldin Bridge)

Pack/TitleBG.pack: SARC. Includes files that presumably always stay loaded.
- Map
  * [1.5.0] Structure is similar to Map/, except this only contains static mubin files. e.g. MainField/A-1/A-1_Static.mubin (byml)
- Quest
  * QuestProduct.bquestpack (byml): All quest information (shrine, sidequest, main quest): name, type, location, quest giver, dependencies, steps, save flags, trigger events, ...
- WorldMgr
  * normal.bwinfo: World information. Climates (weather type, sunny/rainy/cloudy/... rates, temperatures, wind, lighting, fog, ignited), cloud generation, sky, sun/moon, ...

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
