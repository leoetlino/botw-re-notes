# Scene changes

The following actions can be used to change the game scene (map):
* ChangeScene
* FromCDungeonToMainField
* ToCDungeon

All three actions are very similar and actually share the same base class.
ChangeScene is the most flexible action since the others can only be used for shrines.

## Demo
Demo005_1 is used as the event flow for most warps, for example when fast travelling to shrines,
towers, Travel Medallion and Divine Beasts.

Entry point `ClearRemains` is used when completing a Divine Beast. The main difference
between `CommonFunc` and `ClearRemains` is the warp effect (sound and visual).

## Actions
### ChangeScene
Parameters:

```yaml
# example: MainFieldDungeon/RemainsFire
# example: MainField/A-1
- {Name: WarpDestMapName, Type: String}
# example: StartR
- {Name: WarpDestPosName, Type: String}
- {Name: FadeType, Type: Int}
- {Name: StartType, Type: Int}
# example: Demo622_1
- {Name: EvflName, Type: String}
- {Name: EntryPointName, Type: String}
```

Exported by EventSystemActor as Demo_ChangeScene.

### FromCDungeonToMainField
Parameters:

```yaml
- {Name: StartType, Type: Int}
- {Name: EvflName, Type: String}
- {Name: EntryPointName, Type: String}
```

Exported by EventSystemActor as Demo_FromCDunToMainField.

Special purpose variant of ChangeScene which automatically sets WarpDestMapName and WarpDestPosName
to `CDungeon/%s` and `Entrance_1` respectively.

The dungeon map name is determined from the player's coordinates and location markers in
`Map/MainField/Static.mubin`. The coordinates of each `Dungeon` marker are compared
with the player's; if Link is within 100 distance units of (x,y,z) the dungeon name
is extracted from the `SaveFlag` name (e.g. Location_Dungeon051 -> Dungeon051) and used
as the warp destination map name.

### ToCDungeon
Parameters:

```yaml
- {Name: StartType, Type: Int}
- {Name: EvflName, Type: String}
- {Name: EntryPointName, Type: String}
```

Exported by EventSystemActor as Demo_ToCDungeon.

Special purpose variant of ChangeScene which automatically sets WarpDestMapName and WarpDestPosName
to `MainField/%s` [new map name, e.g. A-1] and `%s` [current map name, e.g. CDungeon100_1] respectively.

The new map name is determined using `Map/MainField/Static.mubin` and the current map name.
