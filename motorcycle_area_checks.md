# Master Cycle Zero checks

The Master Cycle Zero cannot be used in some areas.
Below is a list of checks that must be patched to remove usage restrictions.

Most of them are located in a component that I've called the "ride manager" (or "RideMgr"
when following BotW's naming conventions) since it manages both horses and the Master Cycle Zero.

## Disappearing when entering a blacklisted climate

Called from the Motorcycle AI root code.

```cpp
if ( v6 && !RideMgr::motorcycleCanBeUsed(v6, (float *)&v68, 0LL) )  // 0x71004ADF18
  goto triggerDisappear;
```

Either change the condition to be always false, or change `RideMgr::motorcycleCanBeUsed`
(preferred to avoid side effects):

```cpp
bool RideMgr::motorcycleCanBeUsed(RideMgr* this, Vec3 *positions, __int64 a3) // 0x7100679D10
{
  if ( (a3 || (a3 = ActorSystem::sInstance->field_C0) != 0)
    && (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a3 + 0x180LL))(a3) & 1 )
  {
    return false;
  }
  if ( WorldMgr::sInstance
         && (v5 = (u64)WorldMgr::getClimateNum(WorldMgr::sInstance, positions) - 5, v5 <= 14) )
  {
    return (0x3CFEu >> v5) & 1;
  }
  return true;
}
```

Patch:
```
.text:0000007100679D84                 AND             W0, W8, #1
```
To:
```
.text:0000007100679D84                 MOV             W0, #1
```

## Rune UI/sound effect

Same climate based check as above, but done in a different RideMgr function. Just change:

```
.text:0000007100679650 TBNZ            W8, #0, loc_710067965C
```
to:
```
.text:0000007100679650 B               loc_710067965C
```

## Refusing to spawn when in a blacklisted climate

### Check 1

Deep in some RideMgr function, called from the PlayerNormal AI:

```cpp
else if ( !WorldMgr::sInstance
       || (v7 = (unsigned __int64)WorldMgr::getClimateNum(WorldMgr::sInstance, (float *)v4) - 5, v7 > 0xE)
       || (0x3CFEu >> v7) & 1 )
{
  v8 = (*(__int64 (**)(void))(**(_QWORD **)(HavokAI::sInstance->navMeshQueryReqPool + 0x1A0LL) + 0x30LL))();
  ...
}
```

Patch:
```
.text:0000007100679BA8                 CBZ             X0, loc_7100679BD8
```
to:
```
.text:0000007100679BA8                 B               loc_7100679BD8
```
so that the game always executes the code inside of the if block.

### Check 2

Found in another RideMgr member function and also called from the PlayerNormal AI code.

```cpp
bool RideMgr::checkUsable2(RideMgr *this, __int64 a2)
{
  if ( this->someFlag == 1 )
    return 0;
  float* v4 = this->gap12C;
  RideMgr::x_7(this, (float *)this->gap12C, (__int64)&this->field_134 + 4);
  if ( a2 || (a2 = ActorSystem::sInstance->field_C0) != 0 )
  {
    if ( (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a2 + 0x180LL))(a2) & 1 )
      return 0;
  }
  if ( !WorldMgr::sInstance )
    return 1;
  unsigned int climateNumMinus5 = WorldMgr::getClimateNum(WorldMgr::sInstance, v4) - 5;
  return ( climateNumMinus5 > 14 || (0x3CFEu >> climateNumMinus5) & 1 );
}
```

Change:
```
.text:000000710067B5FC                 CBZ             X0, loc_710067B62C
```
to:
```
.text:000000710067B5FC                 B               loc_710067B62C
```
to make the game always return "true".

## Disappearing when being away from the motorcycle

This is checked by Motorcycle AI root code (at 0x71004ADF28).

```cpp
v40 = (float *)PlayerInfo::getPlayerPos(PlayerInfo::sInstance);
if ( (float)((float)((float)(*(float *)&v68 - *v40) * (float)(*(float *)&v68 - *v40))
           + (float)((float)(*(float *)&v70 - v40[2]) * (float)(*(float *)&v70 - v40[2]))) > (float)(**(float **)&this->_4abuf[8] * **(float **)&this->_4abuf[8]) )
  goto triggerDisappear;
```

It is easy to change this condition to be always false.

## Other checks (in 0x7100678E80)

### Actor check

If the actor cannot be loaded, the game will not allow the player to use the motorcycle
and will show the regular "You can't use that here" message.

### 6 or 7 other checks

The RideMgr function at 0x7100678E80 calls 6 member functions that must all return true;
otherwise, the motorcycle cannot be used.

The first 4 functions appear to be using the Havok AI NavMesh system.
Something called "motorcycle shape cast" is used in the 3 other functions.
