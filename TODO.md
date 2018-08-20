# Things to investigate

## Difficulty Scaling (LevelSensor)
- How scaling works for amiibo weapons. What determines the drop table list that gets used?

## Castle Blights (scaling and actors)
- Scaling for Castle Blights
- HP for Castle Blights

## Final battle logic (actors and GameDataMgr)
- What game data exactly is transferred when the game is beaten

## Blood Moon (GameDataMgr)
- The Blood Moon mechanism

## Debug stuff
~~What happens if the ROM type is set to Show_2017_1st or RID_Demo?~~ The game crashes. Why?

Is it possible to get to the stage select screen on release versions?

## One-Hit Kill protection (player actor probably)
What are the conditions for one-hit kill protection to apply?

NoDeathDamageBase (in Link's bgparam) might be related.

Also worth noting that this is gone in Master Mode.

## Master Cycle Zero
- Is it possible to remove the area limitations? (i.e. use the MCZ in the desert)

UPDATE: It's possible to disable the 'instant disappear' when you enter an invalid region
by patching the executable, but there are other checks (for spawning the Master Cycle Zero).
The check is based on the [current climate](tools/check_master_cycle_ok_areas):

* ✅ HyrulePlainClimate
* ✅ NorthHyrulePlainClimate
* ✅ HebraFrostClimate
* ✅ TabantaAridClimate
* ✅ FrostClimate
* 🚫 GerudoDesertClimate
* ✅ GerudoPlateauClimate
* ✅ EldinClimateLv0
* ✅ TamourPlainClimate
* ✅ ZoraTemperateClimate
* ✅ HateruPlainClimate
* ✅ FiloneSubtropicalClimate
* ✅ SouthHateruHumidTemperateClimate
* 🚫 EldinClimateLv1
* 🚫 EldinClimateLv2
* ✅ DarkWoodsClimat
* ✅ LostWoodClimate
* ✅ GerudoFrostClimate
* ✅ KorogForest
* 🚫 GerudoDesertClimateLv2

- Why is it possible to use runes that are obtained from a chest, but not the MCZ?
