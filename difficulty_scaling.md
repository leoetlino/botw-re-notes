# Difficulty scaling

## Overview

  Difficulty scaling in *The Legend of Zelda: Breath of the Wild* is based on a point system.

  Killing enemies is the only way to receive points. Enemies and weapons will be
  progressively replaced by more powerful variants as you gain more points.

  Whenever an enemy dies, the game increments a flag 'Defeated_{SameGroupActorName}_Num' ^[check]
  if all of the following conditions are satisfied:

  * The current kill count is < 10.
  * The actor does not have the NotCountDefeatedNum flag.
  * **For Monk Maz Koshia**: 'Defeated_Priest_Boss_Normal_Num' is 0.
  * **For Dark Beast Ganon**: It is the first time the boss is beaten. ^[check]
  * **For Blights**: It is the first time the blight is beaten in the Divine Beast, or in the
  Illusory Realm. Blights fought in Hyrule Castle do not count.

  This happens every time *any* enemy dies, even if they don't necessarily play a role
  in the point system (see below) and even if you are not responsible for their death.

  Because enemies have to be killed throughout the main quest and bosses are considered
  as enemies too, difficulty scaling is unavoidable.

  Only the defeated counter flags are stored in the save file.
  The `Ecosystem::LevelSensor` subsystem is responsible for
  [converting these kill counts to points](#ecosystemlevelsensorcalculatepoints)
  using a [configuration file](#ecosystemlevelsensorloadbyml).

  The subsystem provides two functions ([`loadWeaponInfo`](#ecosystemlevelsensorloadweaponinfo)
  and [`loadActorInfo`](#ecosystemlevelsensorloadactorinfo)) that may be called
  when a weapon or enemy actor is loaded.

## Scaling inhibitors

Both scaling functions will immediately return without doing anything if:

* WorldMgr::sInstance->stageType == 1 (Open World stage)
* and WorldMgr::sInstance->isAocField (current map is Trial of the Sword)
* and WorldMgr::sInstance->disableScaling (set to true when entering Trial of the Sword)

Scaling will also be skipped if the current [map area](areas.md) is 28. This corresponds to
"HateruSea", which is the Eventide Island area.

## Weapons
  'loadWeaponInfo' is called (i.e. weapons may be scaled) for a weapon if:

  * **For standalone weapons**: The actor property 'LevelSensorMode' is higher than 1 **and** it wasn't already picked up.
  * **For treasure chest drops**: Always upon opening or destroying the chest. *
  * **For Hinox weapons**: The flag `{MapName}_Necklace_{i}_{HinoxName}_{ID}` is false. *
  * **For other enemy drops**: The flag `{MapName}_WeaponDrop_{ID}` is false, **and** [the actor property 'LevelSensorMode' is higher than 1 *or* the enemy is a Guardian Scout ('Enemy_Guardian_Mini')].

  Note: Weapons that are bought from a shop cannot receive modifiers because they do not fit into any of the above cases.

## Enemies
  When loading enemies, the game will always try to scale enemies.

  However, the scaling function won't do anything if 'LevelSensorMode' is < 1 and
  will leave the enemy and any weapons they may hold unscaled.

  Note: Enemies that are not in any upgrade list (such as elemental Lizalfos) will not
  be scaled, but their weapon can still receive upgrades if:

  * 'LevelSensorMode' is non zero.
  * Weapon point requirements are satisfied
  * *or* the modifier tier is overridden using 'SharpWeaponJudgeType'.

[1.3.0] In Master Mode, **all** enemies are automatically ranked up one tier by default **post scaling**,
  independently of 'LevelSensorMode'. Actors can receive two additional parameters:

  Parameter | Default | Description
  ----------|---------|------------
  IsHardModeActor | false | Controls whether an enemy only shows up in Master Mode.
  DisableRankUpForHardMode | false | Controls whether the automatic rankup applies to an enemy.

In Master Mode, IsHardModeActor, DisableRankUpForHardMode and LevelSensorMode are combined on some actors to keep low-level enemies in the overworld (e.g. Red Bokoblin south of the Great Plateau).


## `LevelSensorMode`
  This actor property controls whether scaling is enabled for an enemy or weapon.
  Also applies to any weapons held by an enemy since 'loadWeaponInfo' is called when an enemy drops their weapon.

Note that this doesn't apply to weapons that are attached to a Hinox's necklace, because Hinoxes use a different underlying enemy actor which overrides the 'on weapon dropped' function and ignores 'LevelSensorMode'.

## `SharpWeaponJudgeType`
  This actor property controls the *minimum* modifier tier that a weapon can receive.
  Type: [`enum WeaponModifier`](#weaponmodifier-s32-enum).

  If [scaling](#levelsensormode) is enabled, the weapon may receive modifiers from an
  even higher tier if point requirements are met.

  Otherwise, the weapon will get modifiers from exactly the specified tier.

  For example, 0 ('None') doesn't mean a weapon will never receive a modifier.
  It just means that the developers haven't forced the weapon to spawn with a blue/yellow modifier.
  If scaling requirements are satisfied, the weapon will receive blue or yellow modifiers.

## `WeaponModifier`

  ### `BymlWeaponModifier` (s32 enum)
  There are three possible values for `weapons[].actors[].plus` in the LevelSensor config:

  Value | Description
  ------|--------------
  -1    | **None**: Weapon will receive no modifiers.
  0     | **Blue**: Weapon will receive blue modifiers, also referred to as 'SharpWeapon' in other strings.
  1     | **Yellow**: Weapon will receive yellow modifiers, also referred to as 'PoweredSharpWeapon' in other strings.

  ### `WeaponModifier` (s32 enum)
  Internally and in other assets such as mubin map files, the following values are used instead:

  Value | Description
  ------|--------------
  0     | **None**: No modifiers.
  1     | **RandomBlue**: Weapon will randomly get at least a blue modifier (with `weaponCommonSharpWeaponPer` being the probability).
  2     | **Blue**: Weapon will get at least a blue modifier.
  3     | **Yellow**: Weapon will get at least a yellow modifier.

## `Ecosystem::LevelSensor::loadByml`
  Called by `Ecosystem::init` from `ksys::InitializeApp`

  Sets up byml structures for reading `Ecosystem/LevelSensor.byml`
  (stored in romfs as `Pack/Bootup.pack@/Ecosystem/LevelSensor.sbyml`)

  All information related to difficulty (enemy and weapon) scaling is stored in that
  configuration file. Human-readable versions dumped from [1.0.0](game_files/1.0.0_LevelSensor.yml)
  and [1.5.0](game_files/1.5.0_LevelSensor.yml) are included in the repo.

  A [diff between 1.0.0 and 1.5.0](game_files/1.0.0_1.5.0_LevelSensor.yml.diff) is also in the repo.

  [1.4.0] Flag entries for Golden enemies, Igneo Talus Titan and Monk Maz Koshia were added to
  the kill point table. Weapon entries for the One-Hit Obliterator and Weapon_Sword_503 were also
  added to the weapon scaling list. They cannot receive any modifier.
  (Yes, the developers forgot to add golden enemies to the config in 1.3.0.)

## `Ecosystem::LevelSensor::calculatePoints`
  Called when loading actors

  Calculates weapon and enemy scaling points using a list of flags and
  configuration values.

  All flags that are referenced in the configuration file are of the form `Defeated_%s_Num`,
  but technically the configuration format allows for other flags to be specified.

  Interestingly, the game calculates a single point value based on the kill counter flags but
  calculates two separate values for weapons and enemies with two different multipliers.
  This format makes it possible to easily change the scaling.

  ```c++
  float points = 0.0;
  for (kill_flag : this->byml["flag"])
      int kill_count = GameData::getIntegerFlag(kill_flag["name"]);
      points += kill_count * kill_flag["point"];

  this->points = points;
  this->weapon_points = points * this->byml["setting"].Level2WeaponPower;
  this->enemy_points = points * this->byml["setting"].Level2EnemyPower;
  ```

  In practice, settings have never been modified. 1.5.0 (which will likely be the
  last game update) still has the same Level2WeaponPower and Level2EnemyPower.

## `Ecosystem::LevelSensor::loadWeaponInfo`
  Called from treasure chest code, enemy actors (?), `Ecosystem::LevelSensor::loadActorInfo`

  Given a weapon name, its modifier and current point status, this function
  returns the weapon to actually spawn and the modifier to use (if possible).

  If the algorithm fails to find an appropriate weapon that satisfies all conditions
  (point requirements, weapon series, modifier), the originally specified weapon and modifier
  will be used directly.

  Pseudocode (1.0.0):

  ```c++
  bool Ecosystem::LevelSensor::loadWeaponInfo(StringView weapon_to_look_up,
                                              WeaponModifier required_modifier,
                                              const char** weapon_to_use_name,
                                              WeaponModifier* modifier_to_use,
                                              void* unknown)
  {
    // some checks using 'unknown' here which seems to be a pointer to the actor

    for (weapon_table : this->byml["weapon"]) {
      // find the first weapon entry for which the player has enough points
      // with the specified name and modifier
      i = -1;
      for (j = 0; j < weapon_table["actors"].size; ++j) {
        entry = weapon_table["actors"][j];
        float points_for_next_transition = entry["value"];

        if (this->weapon_points > points_for_next_transition &&
            weapon_to_look_up == entry["name"] &&
            convert_to_modifier(entry["plus"]) == required_modifier) {
          i = j;
          break;
        }
      }

      if (i == -1)
        continue;

      do {
        entry = weapon_table["actors"][i];

        // not_rank_up means there is no link between weapons;
        // this table is just used to look up modifiers.
        // so go down the list until there are no more entries for the requested weapon
        // or until we reach a modifier that requires more points.
        if (weapon_table["not_rank_up"] && entry["name"] != weapon_to_look_up)
          break;

        // otherwise, just go down the list until we reach the end or a weapon which
        // requires more points. this will possibly upgrade the weapon (e.g. Knight -> Royal).
        if (this->weapon_points <= entry["value"])
          break;

        ++i;
      } while (i < weapon_table["actors"].size);

      *weapon_to_use_name = entry["name"];
      *modifier_to_use = convert_to_modifier(entry["plus"]);
      return true;
    }
    return false;  // cannot scale up
  }
  ```

## `Ecosystem::LevelSensor::loadActorInfo`
  Analogous to `LevelSensor::loadWeaponInfo`.

  Pseudocode (1.0.0):

  ```c++
  if (actor->params["LevelSensorMode"] < 1)
    return false;

  if (actor_name.contains("Enemy")) {
    for (enemy_table : this->byml["enemy"]) {
      i = -1;
      for (j = 0; j < enemy_table["actors"].size; ++j) {
        entry = enemy_table["actors"][j];
        if (entry["name"] == actor_name && this->enemy_points > entry["value"]) {
          i = j;
          break;
        }
      }

      if (i == -1)
        continue;

      do {
        entry = enemy_table["actors"][i];
        if (this->enemy_points <= entry["value"])
          break;
        ++i;
      } while (i < enemy_table["actors"].size);

      *actor_to_use = entry["name"];
      return true;
    }
    return false;  // cannot scale up
  }

  if (actor_name.contains("Weapon")) {
    weapon_name = actor->getWeaponName();
    modifier = actor->params["SharpWeaponJudgeType"];
    if (modifier == WeaponModifier::RandomBlue)
      modifier = get_random_blue_modifier(actor->getWeaponName());

    if (loadWeaponInfo(weapon_name, &weapon_to_use, &modifier_to_use)) {
      actor->setProperty("SharpWeaponJudgeType", modifier_to_use);
      *actor_to_use = weapon_to_use;
      return true;
    }
    return false;  // cannot scale up
  }
  ```

## The Data

  To make things easier to understand, here are links to:

  * [kill point, enemy scaling and weapon scaling tables](https://docs.google.com/spreadsheets/d/e/2PACX-1vRSlyOD7FLAn1TUBn64Pu8Pld-WOfgcVByuywHMWvBTEV0j8potD1wkBs-MJJXf-gvEkpfItUCMqMk6/pubhtml)

  * an [object map with all the scaling information](https://f.leolam.fr/botw-map/) embedded
  into the object names.

  This makes it possible to see both the required points for enemy/weapon upgrades,
  as well as all of the special cases extremely easily.

  For the map, a few special name suffixes were added:

  * `:NO_SCALING`: Enemy or weapon won't be scaled.
  * `:NO_RANKUP`: Enemy will not be automatically ranked up in master mode.
  * `:MODIFIER_X`: Weapon will receive at least modifier tier X.
  * `:OFF_WAIT_REVIVAL`: Enemy or weapon will always respawn even without a blood moon.

## Ganon Blights

Their health is determined from the base HP (set in GeneralParamList) and from blight defeat flags.

```cpp
__int64 SiteBoss::getInitialHP(SiteBoss *this) // 0x71002D01F4
{
  const int baseHp = Enemy::getInitialHP(this);
  const int halfBaseHp = baseHp >> 1;
  const bool dieGanonWind = hasFlag_Die_PGanonWind(0);
  const bool dieGanonWater = hasFlag_Die_PGanonWater(0);
  const bool dieGanonFire = hasFlag_Die_PGanonFire(0);
  const bool dieGanonElectric = hasFlag_Die_PGanonElectric(0);
  const int flags = this->siteBossFlags & 0xFFFFFFFC;
  int multiplier;
  if ( flags == 4 )
    multiplier = 3;
  else if ( flags == 8 )
    multiplier = 4;
  else
    multiplier = dieGanonFire + dieGanonWind + dieGanonWater + dieGanonElectric;
  return baseHp + multiplier * halfBaseHp;
}
```

Effectively, this means that the first blight Link fights will have 800+0×400 = 800 HP,
the second will have 800+1×400 = 1200 HP, the third 800+2×400 = 1600 HP and the last one 800+3×400 = 2000 HP.

### Special case 1: Castle Blights
Castle blights have `IsRemainBoss` set to false in the root AI parameters,
which sets flag 4.

Thus, blights that are fought in the Castle always have 800+3×400 = 2000 HP
regardless of story progression.

If flag 4 is set, the AI_Action_SiteBossDie code will NOT increment the "defeated" counter.
This means castle blights do not give any scaling points.

### Special case 2: DLC2 Blights
Illusory Realm blights possess the `EnemySiteBoss_R` actor tag. This causes flag 8 to be set.
So they will always have 500+4×250 = 1500 HP.

Interestingly, the Windblight AI function relies doesn't check the actor tag but
the actor name instead. For flag 8 to be set, the actor name must be `Enemy_SiteBoss_Bow_R`.
