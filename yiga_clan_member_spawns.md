# Yiga clan member spawns

There are two categories of Yiga clan member spawns.

Some of them are static -- which means they are listed in Map Units and can be seen on the object
map -- but as you complete the main quests, most Yiga clan members you see are actually
dynamically spawned.

## Static

### Traveler (disguised Yigas)

These are linked to 'Link' tags that make them spawn if and only if the `Electric_Relic_AssassinFirst` *or* `Npc_Kakariko001_TalkEnd` flag is set.

The latter is set after you talk to Impa.

I'm not sure about the AssassinFirst, but it seems to be set when the Yiga Clan Hideout
location appears (which is consistent with the findings in this
[reddit post](https://www.reddit.com/r/Breath_of_the_Wild/comments/6ghtvz/explaining_enemy_scaling_in_botw_xpost_rzelda/)).

### Near the hideout

The *five* non-disguised static Yiga clan members inside and near the hideout
seem to be spawned without any conditions.

## Dynamic

Other Yiga clan members are not listed on the map. This is because they are dynamically spawned
by a component called the AutoPlacement Manager.

From a quick look at the code, it seems that there are two sets of conditions.

If `Electric_Relic_GetBack` is set, which happens when you get back the Thunder Helm
from the hideout and the quest log shows this message:

> You retrieved the chief's heirloom from the
> thieves' leader!
>
> It's time to head back to Gerudo Town
> and return the heirloom to Riju!

...then Blademasters are allowed to spawn. And for Footsoldiers, the weapon they carry is random:

```cpp
// probability: roughly 75%
if (sead::Random::getU32() / (U32_MAX+1) < 0.75)
  weapon = "Weapon_Sword_073"; // Demon Carver
else
  weapon = "Weapon_Sword_053"; // Vicious Sickle
```

Otherwise:

* if Electric_Relic_AssassinFirst *or* Npc_Kakariko001_TalkEnd is set; **and**
* if the enemy is Enemy_Assassin_Junior, *or* a disguised Yiga (created by `CreateAndReplaceAssassin`),
*or* in some unknown, rare conditions

then only Footsoldiers may be dynamically generated, and they will only wield Vicious Sickles.

(In the AutoPlacement event flow files for Yiga clan members,
it seems that they won't be spawned if you're riding a horse, but I'm not 100% sure on this.)
