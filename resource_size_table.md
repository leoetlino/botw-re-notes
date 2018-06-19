# Resource Size Table

The Resource Size Table (RSTB) contains information about game resource file sizes.

## Table structure

Sections are listed in the order they appear in the file.

### Header (optional)
```c++
struct RstbHeader {
  u32 magic;           // 'RSTB'
  u32 crc32TableSize;  // number of entries - can be 0 to indicate there is no crc32 table
  u32 nameTableSize;   // number of entries - can be 0 to indicate there is no name table
}; // sizeof() = 12
```

If the header is missing or if the magic is not correct, the game will assume there is
simply no header. In that case, the game will use the size of the RSTB file, divide it by 8
to get the number of crc32 table entries and assume the whole file is a crc32 table.

### CRC32 table (optional)
This is a mapping of CRC32 values to resource sizes. The table must be sorted; otherwise
the game will not be able to search for entries properly.

```c++
struct RstbCrc32TableEntry {
  u32 crc32;
  u32 size;
};  // sizeof() = 8
```

### Name table (optional)
This is a mapping of resource paths (strings) to resource sizes. This table is optional and
seems to be used whenever there would be conflicts in the crc32 table. Only usable if there
is a RSTB header.

```c++
struct RstbCrc32NameEntry {
  char name[128];
  u32 size;
};  // sizeof() = 132
```

## Game usage

The table is loaded and queried by `ResourceInfoContainer` which is a class member of
`res::ResourceMgrTask`.

When the resource manager task starts (i.e. when `Prepare` is called), which happens
extremely early in the game initialization process, ResourceInfoContainer loads the table
from `System/Resource/ResourceSizeTable.product.rsizetable`. After reading the header
(if it exists), pointers to the crc32 to size and file name to size maps are then stored.

## Lookup
`ResourceInfoContainer::getResourceSize` (non official name) starts by computing the crc32
for the resource name/path.

If a crc32 table is present, the game will do a binary search to find an entry
for the calculated crc32. If an entry is found, `entry.size` is returned.

Otherwise, if a name table is present, the game will go down the table until an entry that
matches the specified resource name is found. If an entry is found, `entry.size` is returned.

Otherwise, the game returns 0 (which indicates failure).

## Checks
The aforementioned function is only used by `res::ResourceMgrTask::getResourceSize`.

The RSTB is used differently depending on the subsystem:

* TipsMgr and EventResource use it only to check if the file they want to load exists
(by checking if ret != 0).
* EffectResource, when loading Effect/Game.esetlist: must not be zero.
* VfxResourceMgr, when loading Effect/%s.esetlist files: must not be zero.

* bfres loading code at 0x7100FE3978 (v1.5.0): unclear, but must not be zero.
It appears to check whether the file size listed in the RSTB is higher than some other value.

* res::ResourceMgrTask code at 0x710120BDE0 (v1.5.0) possibly called during resource load:
unclear, but must not be zero. It appears to check whether the file size listed in the
RSTB is higher than some other value.

```c++
if ( somePtr + 0x40 <= rstbSize )
{
  *(_DWORD *)(arg1 + 4) = ptr2 + rstbSize + 8;
}
else
{
  *(_DWORD *)(arg1 + 4) = (unsigned int)(float)(unsigned int)(ptr2 + somePtr + 0x48);
}
```

* 0x7100FE1630 (v1.5.0): unclear.
If the file is loaded by the resource memory or loading thread, or if the file size listed in
the RSTB is larger than a TempResourceLoader field, the game prints: "Texture archive size: %u MB"
(translated from Japanese).
