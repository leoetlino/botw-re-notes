Ecosystem/AreaData has information about map areas, including names, numbers, climates, environments
and auto placement information.

Ecosystem/FieldMapArea maps coordinates to map area numbers.

## Coordinate to map area

Below is the function that does this mapping (I haven't reversed it yet):

```cpp
unsigned int __fastcall eco::getCurrentAreaNum(float posX, float posZ, Ecosystem *ecosystem, _QWORD *fieldMapAreaData)
{
  v4 = -5000.0;
  if ( posX >= -5000.0 )
  {
    v4 = posX;
    if ( posX > 4999.0 )
      v4 = 4999.0;
  }
  v5 = -4000.0;
  if ( posZ >= -4000.0 )
  {
    v5 = posZ;
    if ( posZ > 4000.0 )
      v5 = 4000.0;
  }
  v6 = *(_DWORD *)(*fieldMapAreaData + 8LL);
  v7 = *(_DWORD *)(*fieldMapAreaData + 4LL) - 2;
  if ( (float)(v4 + 5000.0) < 0.0 )
    v8 = -0.5;
  else
    v8 = 0.5;
  v9 = (signed int)(float)((float)(v4 + 5000.0) + v8);
  v10 = v5 + 4000.0;
  if ( v10 < 0.0 )
    v11 = -0.5;
  else
    v11 = 0.5;
  v12 = (signed int)(float)(v10 + v11) / v6;
  if ( v12 <= v7 )
    v7 = (signed int)(float)(v10 + v11) / v6;
  if ( v12 >= 0 )
    v13 = v7;
  else
    v13 = 0;
  v14 = (signed int *)(fieldMapAreaData[1] + 4LL * v13);
  if ( v6 == 0xA )
    v9 = (0x66666667LL * v9 >> 0x22) + ((unsigned __int64)(0x66666667LL * v9) >> 0x3F);
  v15 = *v14;
  v16 = v14[1];
  if ( (signed int)v15 >= (signed int)v16 )
    return 0xFFFFFFFF;
  v17 = fieldMapAreaData[2];
  v18 = v17 + 2 * v16;
  v19 = (signed __int16 *)(v17 + 2 * v15);
  v20 = 0;
  result = 0xFFFFFFFF;
  while ( 1 )
  {
    v20 += v19[1];
    if ( v9 < v20 )
      break;
    v19 += 2;
    if ( (unsigned __int64)v19 >= v18 )
      return result;
  }
  return *v19;
}
```

## WorldManager stage types

WorldManager reloads its world info config file and some state every time a stage is loaded
or reloaded.

Type | Description
-----|-------------
0 | Unused?
1 | Open world stage: non-GameTestField
2 | Indoor stage
3 | Open world stage: GameTestField
4 | MainFieldDungeon (Divine Beasts)
5 | Indoor stage / Viewer stage
