# Things to investigate

## Difficulty Scaling (LevelSensor)
- How scaling is disabled on Eventide for chests

## Castle Blights (scaling and actors)
- Scaling for Castle Blights
- HP for Castle Blights

## Final battle logic (actors and GameDataMgr)
- What happens when the final battle starts
- What game data exactly is transferred when the game is beaten

## Blood Moon (GameDataMgr)
- The Blood Moon mechanism

## The Great Plateau barrier (GameDataMgr and actors?)
- The Great Plateau death barrier

## Climate (WorldMgr)
- How the game forces daylight before the first tower is activated

## Debug stuff
~~What happens if the ROM type is set to Show_2017_1st or RID_Demo?~~ The game crashes. Why?

Is it possible to get to the stage select screen on release versions?

## One-Hit Kill protection (player actor probably)
What are the conditions for one-hit kill protection to apply?

NoDeathDamageBase (in Link's bgparam) might be related.

Also worth noting that this is gone in Master Mode.

## Master Cycle Zero
- Is it possible to remove the area limitations? (i.e. use the MCZ in the desert)

- Why is it possible to use runes that are obtained from a chest, but not the MCZ?
