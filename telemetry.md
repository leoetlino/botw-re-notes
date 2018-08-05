## List of all `prepo` reports (on Switch)

* `korok`: whenever a hidden Korok appears. Includes: Korok ID, map info, play times, position
* `dungeon`: when you enter a dungeon or divine beast or the Final Trial, leave it, or complete it. Includes: map info, dungeon name, event, play times
* `challenge`: quest event. Includes: map info, Id, Name, Step, StepName, play times
* `gameover`: obvious. Includes: map info, reason (e.g. lightning), Killer (the name of the actor that killed you), play times, position, CRC32 of map name
* `bloodymoon`: includes version info, map info, Reason, RomWorkTime, SceneWorkTime, map name, play times, position
* `getitem`: includes map info, CRC32 of the item name, position, play times
* `options`: Reports a bunch of misc things. BalloonTextOnOff, AutoSaveOnOff, options like CameraUpDownReverse, jump button change, whether you're playing in docked mode, ControllerType, PlayTimeHandheld, PlayTimeConsole, PlayTimeAll, audio mode (stereo, mono, surround), etc.
* `emergencyheap`: whenever a memory allocation is made using an emergency heap. Includes: version info, heap name, play times, position

Version info:
* `RomVer` (game version)
* `AocVer` (DLC version)

Map info:
* `IsHardMode`
* `MapType`: MainField, AocField, CDungeon, MainFieldDungeon

Play times:
* `PlayTime` (play time since game init)
* `AllPlayTime` (cumulated play time)

Position:
* `PosX`
* `PosZ`

## Debug versions

Debug versions send additional play reports, for example for every enemy you kill, every
inventory item you get or use, etc.
