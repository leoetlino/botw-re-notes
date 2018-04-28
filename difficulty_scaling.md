# Difficulty scaling

## Overview

  Difficulty scaling in *The Legend of Zelda: Breath of the Wild* is based on a point system.

  Killing enemies is the only way to receive points. Enemies and weapons will be
  progressively replaced by more powerful variants as you gain more points.

  Whenever an enemy dies, the game increments a 32-bit flag `Defeated_%s_Num`
  (where `%s` is the 'same group actor name' <sup>[check]</sup>)
  if all of the following conditions are satisfied:

  * The current kill count is < 10.
  * The actor does not have the `NotCountDefeatedNum` flag.
  * *For Monk Maz Koshia*: `Defeated_Priest_Boss_Normal_Num` is 0.
  * *For Dark Beast Ganon*: It is the first time the boss is beaten. <sup>[check]</sup>
  * *For Blights*: It is the first time the blight is beaten in the Divine Beast, or in the Illusory Realm. Blights fought in Hyrule Castle will apparently not count. <sup>[check]</sup>

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

## Weapons
  `loadWeaponInfo` is called (i.e. weapons may be scaled) when loading a weapon
  if the following conditions are true:

  * *For standalone weapons*: The boolean flag `%s_WeaponDrop_%u` (map, id) is false.
  * *For weapons attached to Hinox necklaces*: The boolean flag `%s_Necklace_%d_%s_%u`
    (map, idx, Hinox enemy name, id) is false.
  * *Scaling is enabled for the actor instance*: The actor property `LevelSensorMode`
    (found in mubin maps) is >= 1 **or** the enemy is a Guardian Scout (`Enemy_Guardian_Mini`).

  Note: Weapons that are bought from a shop or given by NPCs cannot receive modifiers.

## Enemies
  `loadActorInfo` is always called when loading enemies.

  However, the function won't do anything if `LevelSensorMode` is < 1 and
  will leave the enemy and any weapons they may hold unscaled.

  Note: Enemies that are not in any upgrade list (such as elemental Lizalfos) will not
  be scaled, but their weapon can still receive upgrades if:

  * `LevelSensorMode` is non zero.
  * Weapon point requirements are satisfied
  * *or* the modifier tier is overridden using `SharpWeaponJudgeType`.

  [1.3.0] In Master Mode, *all* enemies are automatically ranked up one tier by default post scaling,
  independently of `LevelSensorMode`. Actors can receive two additional parameters:

  Parameter | Default | Description
  ----------|---------|------------
  `IsHardModeActor` | false | Controls whether an enemy only shows up in Master Mode.
  `DisableRankUpForHardMode` | false | Controls whether the automatic rankup applies to an enemy.

  `IsHardModeActor=True`, `DisableRankUpForHardMode=True` and `LevelSensorMode=0` are combined
  on some actors to keep low-level enemies in Master Mode (e.g. Red Bokoblin south of the
  Great Plateau).

## `LevelSensorMode`
  This actor property controls whether scaling is enabled for an enemy or weapon.
  Also applies to any weapons held by an enemy since `loadWeaponInfo` is called by `loadActorInfo`.

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

  [1.3.0] Flag entries for Golden enemies were added to the kill point table.

  [1.4.0] Flag entries for Igneo Talus Titan and Monk Maz Koshia were added to the kill point table.

  [1.5.0] Weapon entries for the One-Hit Obliterator and Weapon_Sword_503 were added to the
  weapon scaling list. They cannot receive any modifier.

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
