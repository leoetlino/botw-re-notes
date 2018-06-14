## Random information that hasn't been triaged yet

### Version string in executable
1.0.0's nnMain prints "00000010", whereas 1.5.0 prints "0000002d".

### Unused options?
The game accepts three different options: -fhd (flag for Full HD?), -no_sead_log (flag),
-out (string). However it seems that nothing is done with them; they're just loaded into memory
and not used anywhere.

### Main memory arena size
1.0.0 uses 0xC0600000. This was increased to 0xC1000000 in 1.5.0.

### GameConfig
The structure uses 0x810 bytes in 1.0.0. In 1.5.0, the size is now 0x840 bytes.

### Save-breaking bug in some development versions

Apparently some development versions (1523941 to 1548881) generated unusable saves.
These strings are unused in the retail version.

```
.rodata.2:0000007101DE98B0 a15239411548881 DCB "@1523941 ~ @1548881のROMからのセーブデータを利用しているようです。",0xA
.rodata.2:0000007101DE98B0                 DCB "バグ報告をせずに、セーブデータを消去してください。",0xA
.rodata.2:0000007101DE98B0                 DCB "@1523941 ~ @1548881からのセーブデータであるはずがないという場合のみ、バグ報告をしてください。",0xA
.rodata.2:0000007101DE98B0                 DCB "num_valid_normal_mode %d/%d, num_valid_hard_mode %d%d",0
```

### RomMode (to investigate)

The game calls a sead function to detect RomMode. The result is printed along with AOC (DLC)
information.

Some functions (including the SaveMgr) have a 'Show_2017_1st' string which may be related
to leftover demo code.
