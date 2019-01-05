#!/usr/bin/env python3
climate_ids = (
    'HyrulePlainClimate',
    'NorthHyrulePlainClimate',
    'HebraFrostClimate',
    'TabantaAridClimate',
    'FrostClimate',
    'GerudoDesertClimate',
    'GerudoPlateauClimate',
    'EldinClimateLv0',
    'TamourPlainClimate',
    'ZoraTemperateClimate',
    'HateruPlainClimate',
    'FiloneSubtropicalClimate',
    'SouthHateruHumidTemperateClimate',
    'EldinClimateLv1',
    'EldinClimateLv2',
    'DarkWoodsClimat',
    'LostWoodClimate',
    'GerudoFrostClimate',
    'KorogForest',
    'GerudoDesertClimateLv2',
)

# bool __cdecl motorcycleCanBeUsed(__int64 a1, float *positions, __int64 a3)  // 0x7100679D10
# {
#   if ( (a3 || (a3 = ActorSystem::sInstance->field_C0) != 0)
#     && (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)a3 + 0x180LL))(a3) & 1 )
#   {
#     return false;
#   }
#   if ( WorldMgr::sInstance
#          && (v5 = (u64)WorldMgr::getClimateNum(WorldMgr::sInstance, positions) - 5, v5 <= 14) )
#   {
#     return (0x3CFEu >> v5) & 1;
#   }
#   return true;
# }
for i, climate in enumerate(climate_ids):
    i5 = i - 5
    if i5 < 0:
        print(f'✅ {climate}')
        continue
    ok = (0x3CFE >> i5) & 1
    if ok:
        print(f'✅ {climate}')
    else:
        print(f'🚫 {climate}')
