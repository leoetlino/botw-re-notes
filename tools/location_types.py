location_types = "Village, Hatago, Dungeon, Tower, StartPoint, CheckPoint, Castle, RemainsElectric, RemainsFire, RemainsWater, RemainsWind, ShopYadoya, ShopBougu, ShopYorozu, ShopColor, ShopJewel, Labo, Korok, Horse, YunBo, WolfLink, Challenge, PointGuide, MapName, DeathPlace, Player, Guardian, MapStamp00, MapStamp01, MapStamp02, MapStamp03, MapStamp04, MapStamp05, MapStamp06, MapStamp07, MapStamp08, MapStamp09, MapPinRed, MapPinBlue, MapPinYellow, MapPinGreen, MapPinPurple, WarpDLC, HeroDungeon, Motorcycle, None".split(", ")
if __name__ == '__main__':
    for i, x in enumerate(location_types):
        print(f'0x{i:x}: {x}')
