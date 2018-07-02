# Resource system

## Table of contents

- [Resource system](#resource-system)
  * [Factories](#factories)
  * [EntryFactory](#entryfactory)
    + [Complete list](#complete-list)
      - [Factories - General](#factories---general)
      - [Factories - ActorParam](#factories---actorparam)
      - [Factories - Physics](#factories---physics)
      - [Factories - Misc 2](#factories---misc-2)
  * [Loading compressed files](#loading-compressed-files)
  * [Loading from archives](#loading-from-archives)
  * [Heap size](#heap-size)
  * [Resource Size Table](#resource-size-table)
    + [Table structure](#table-structure)
      - [Header (optional)](#header--optional-)
      - [CRC32 table (optional)](#crc32-table--optional-)
      - [Name table (optional)](#name-table--optional-)
    + [Game usage](#game-usage)
      - [Lookup](#lookup)
      - [Checks](#checks)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

## Factories

Factories are an important concept in BotW's resource system. They are C++ classes that are
responsible for unwrapping/converting raw data from content files by creating 'resource' classes.

During application init, factory instances are created and registered with the resource system.
When a resource is loaded, the system will look up the corresponding factory based
on the file extension, load the entire file into memory, and pass the data to the factory,
which then returns a ready-to-use Resource object.

## EntryFactory

This class is the base class for all object factories that are specific to *Breath of the Wild*.

Derived from `sead::DirectResourceFactoryBase` -> `sead::ResourceFactory` -> `sead::TListNode<sead::ResourceFactory*>` -> `sead::ListNode`, `sead::IDisposer`

### Complete list

These values were extracted from the Switch 1.5.0 executable.

When a table cell has two values separated by a '/', the first value is for the Switch version
and the second one for the Wii U.

Otherwise, assume that the value only holds for the Switch version.

#### Factories - General

| Extension | sizeof(ResClass) | loadDataAlignment | Other extensions | Multiplier | Constant
| --- | --- | --- | --- | --- | --- |
| Base | 0x20 / 0x14 | 8 | (none) | | |
| ResourceBase\* | 0x38 / 0x20 | 4 | specifically: Tex.bfres, Tex{1,2}.bfres, Tex1.{1,2,3,4}.bfres, and any resource type without its own factory | 1 | 0 |
| sarc | 0x68 / 0x3c | 0x80 | pack, bactorpack, bmodelsh, beventpack, stera, stats | (none) | 1 | 0 |
| bfres | 0x1a8 / 0x13c | 0x1000 | (none) | 2.5 | 0x400000 |
| bcamanim | 0x50 / 0x2c | 0x2000 | (none) | 1 | 0x680 |
| batpl, bnfprl (U?) | 0x40 / 0x24 | 4 | (none) | 1 | 0 |
| bplacement (U?) | 0x48 | 4 | (none) | 1 | 0 |
| hks, lua (U?) | 0x38 | 4 | (none) | 1 | 0 |
| bactcapt (U?) | 0x538 | 4 | (none) | 1 | 0x1000 |
| bitemico | 0x60 / 0xd0 | 0x2000 | (none) | 1 | 0 |
| jpg | 0x80 / 0x174 | 0x2000 | (none) | 1 | 0 |
| bmaptex | 0x60 / 0xd0 | 0x2000 | (none) | 1 | 0 |
| bmapopen, breviewtex, bstftex | 0x60 / 0xd0 | 0x2000 | (none) | 1 | 0 |
| bgdata | 0x140 | 4 | (none) | 5 | 0xc0000 |
| bgsvdata | 0x38 | 4 | (none) | 1 | 0x300000 |
| hknm2 | 0x48 / 0x28 | 4 | (none) | 1 | 0xb28 |
| bmscdef | 0x2a8 | 4 | (none) | 1 | 0 |
| bars | 0xb0 / 0x84 | 0x80 | (none) | 1 | 0 |

#### Factories - ActorParam

| Extension | sizeof(ResClass) | loadDataAlignment | Other extensions | Multiplier | Constant
| --- | --- | --- | --- | --- | --- |
| bxml | 0x778 / 0x4a8 | 4 | (none) | 1 | 0x1000 |
| bgparamlist | 0x2c0 | 4 | (none) | 1 | 0xd318 + 0x800 |
| bmodellist | 0x7d0 | 4 | (none) | 2 | 0 |
| baslist | 0x410 | 4 | (none) | 0 | 0x80000 |
| baiprog | 0x448 | 4 | (none) | 1 | 0x300000 |
| bphysics | 0x470 | 4 | (none) | 6 | 0 |
| bchemical | 0x3c0 | 4 | (none) | 0 | 0x2000 |
| bas | 0x3c8 | 4 | (none) | 0 | 0x80000 |
| batcllist | 0x3f0 | 4 | (none) | 1 | 0x2000 |
| batcl | 0x428 | 4 | (none) | 1 | 0x2000 |
| baischedule | 0x2b8 | 4 | (none) | 1 | 0x800 |
| bdmgparam | 0x11d0 | 4 | (none) | 1 | 0x20000 |
| brgconfiglist | 0x3d0 | 4 | (none) | 1 | 0x2000 |
| brgconfig | 0x42d8 | 4 | (none) | 1 | 0x20000 |
| brgbw | 0x2c0 | 4 | (none) | 1 | 0x20000 |
| bawareness | 0xb38 | 4 | (none) | 1 | 0 |
| bdrop | 0x320 | 4 | (none) | 1 | 0x5000 |
| bshop | 0x320 | 4 | (none) | 1 | 0x20000 |
| brecipe | 0x320 | 4 | (none) | 1 | 0x20000 |
| blod | 0x3c0 | 4 | (none) | 1 | 0x20000 |
| bbonectrl | 0x8d0 | 4 | (none) | 1 | 0x40000 |
| blifecondition | 0x4b0 | 4 | (none) | 1 | 0x20000 |
| bumii | 0x2b8 | 4 | (none) | 1 | 0 |
| baniminfo | 0x2c8 | 4 | (none) | 1.5 | 0 |
| byaml | 0x20 | 4 | (none, this won't match 'byml') | 1 | 0 |
| bassetting | 0x260 | 4 | (none) | 0 | 0x80000 |

#### Factories - Physics

| Extension | sizeof(ResClass) | loadDataAlignment | Other extensions | Multiplier | Constant
| --- | --- | --- | --- | --- | --- |
| hkrb | 0x20 | 4 | (none) | 1 | 0x400 |
| hkrg | 0x20 | 4 | (none) | 1 | 0x400 |
| hkphyssb | 0x5b0 | 4 | (none) | 1 | 0x100000 |
| hkcl | 0xe8 | 4 | (none) | 2 | 0x2800 |
| hksc | 0x140 | 4 | (none) | 1.3 | 0x40000 |
| hktmrb | 0x48 | 4 | (none) | 1 | 0x800 |
| brgcon | 0x48 | 4 | (none) | 1 | 0x4000 |

#### Factories - Misc 2

| Extension | sizeof(ResClass) | loadDataAlignment | Other extensions | Multiplier | Constant
| --- | --- | --- | --- | --- | --- |
| esetlist | 0x38 | 0x4000 | (none) | 1 | 0 |
| bdemo | 0xb20 | 4 | (none) | 1 | 0xb20 |
| bfevfl | 0x40 | 4 | (none) | 1 | 0x40 |
| bfevtm | 0x40 | 4 | (none) | 1 | 0x40 |


The function that computes the loading heap size uses `max(loadDataAlignment, 0x20)` as the
actual alignment value.

For ResourceLoadArg3 (used in model/bfres related code), the factory is hardcoded
to be the ResourceBase factory.

For ResourceLoadArg2 (used for actor resources and physics stuff) and ResourceLoadArg (everything else), the factory is determined from the file extension.

\*Any file for which there isn't any specific factory will use the ResourceBase factory.
ResourceBase objects are nothing more than a thin wrapper over the underlying file bytes.
On the Wii U, sizeof(ResourceBase) = 0x20.

## Loading compressed files

To load compressed files, make sure the extension of the resource file starts with an 's'.
This prefix indicates the file is yaz0 compressed.

When calling the resource loading functions, drop the s from the path.

The resource system appears to always prepend 's' to the extension and use
`sead::ResourceMgr::tryLoadWithDecomp` to try loading a compressed version first, before
falling back to the specified path.

## Loading from archives

To load from an archive, set the global resource pack pointer
(`res::ResourceMgrTask::sInstance->packRes` @ this+0x9c06f0).

The game does not namespace archive contents: they can be accessed as if they were at the
root of the romfs/content partition.

Calls to any of the resource loading functions will automatically check whether the
specified resource exists in the archive. (The resource system gets a sead::ArchiveRes*
from the resource struct and calls sead::ArchiveRes::getFileImpl() to check.)

If it does exist, it will be loaded from the archive.
(The ResourceBinder will store a `sead::ArchiveRes*`.)

If the file cannot be found in the archive, the game will ignore the active resource pack
and load from the regular file device.


## Heap size

The size of the resource loading heap the system allocates every time a resource is loaded
depends on the value that is listed in the RSTB (see below).

If lookup fails, the game will fall back to the following formula (Switch on 1.5.0):

```c++
alignedFileSize = (actualFileSize + 31) & -32;

return factory->getResourceSize()
     + factory->constant
     + factory->getLoadDataAlignment()
     + (signed int)(float)(factory->sizeMultiplier * alignedFileSize)
     + (factory->sizeMultiplier * alignedFileSize >= 0.0 &&
        (float)(signed int)(float)(factory->sizeMultiplier * alignedFileSize)
                        != (float)(sizeMultiplier * factory->sizeMultiplier))
     + 0x750;
```

This means that failure to add resource files to the RSTB may result in system instability,
given that the resource system will often allocate way more memory than needed.

## Resource Size Table

The Resource Size Table (RSTB) contains information about game resource file sizes.

The game uses it to determine how much memory should be allocated when loading a resource.

It is currently unknown how Nintendo determined the values in the RSTB.
However by RE'ing the resource system it was found that the resource loading heap is,
at least for the most common factories, just used to allocate the file loading buffer (which
is as large as the file to load), the C++ resource class and some extra bytes to
ensure data is aligned correctly in memory.

So a formula that should always work for modifying the listed size is:

    (size rounded up to multiple of 32) + CONSTANT + sizeof(ResourceClass)

See below for the resource system constant value, and the factory list for resource class sizes.

### Table structure

Sections are listed in the order they appear in the file.

#### Header (optional)
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

#### CRC32 table (optional)
This is a mapping of CRC32 values to resource sizes. The table must be sorted; otherwise
the game will not be able to search for entries properly.

```c++
struct RstbCrc32TableEntry {
  u32 crc32;
  u32 size;
};  // sizeof() = 8
```

#### Name table (optional)
This is a mapping of resource paths (strings) to resource sizes. This table is optional and
seems to be used whenever there would be conflicts in the crc32 table. Only usable if there
is a RSTB header.

```c++
struct RstbCrc32NameEntry {
  char name[128];
  u32 size;
};  // sizeof() = 132
```

### Game usage

The table is loaded and queried by `ResourceInfoContainer` which is a class member of
`res::ResourceMgrTask`.

When the resource manager task starts (i.e. when `Prepare` is called), which happens
extremely early in the game initialization process, ResourceInfoContainer loads the table
from `System/Resource/ResourceSizeTable.product.rsizetable`. After reading the header
(if it exists), pointers to the crc32 to size and file name to size maps are then stored.

#### Lookup
`ResourceInfoContainer::getResourceSize` (non official name) starts by computing the crc32
for the resource name/path.

**Note**: AoC resources will have `Aoc/0010/` prepended to the resource path on Switch and Wii U.

If a crc32 table is present, the game will do a binary search to find an entry
for the calculated crc32. If an entry is found, `entry.size` is returned.

Otherwise, if a name table is present, the game will go down the table until an entry that
matches the specified resource name is found. If an entry is found, `entry.size` is returned.

Otherwise, the game returns 0.

#### Checks
The RSTB is used differently depending on the subsystem:

* TipsMgr and EventResource use it only to check if the file they want to load exists
(by checking if ret != 0).
* EffectResource, when loading Effect/Game.esetlist: must not be zero.
* VfxResourceMgr, when loading Effect/%s.esetlist files: must not be zero.

* bfres loading code at 0x7100FE3978 (v1.5.0): unclear, but must not be zero.
It appears to check whether the file size listed in the RSTB is larger than the heap size.

* res::ResourceMgrTask::getHeapSizeForResLoad (0x710120BDE0 in v1.5.0): called during resource load.

```c++
constant = 0x128 + 0x40;
if (auto* entry_factory = dynamic_cast<res::EntryFactoryBase*>(factory))
  resSize2 = entry_factory->getResourceSize(param->factory) + constant;
else
  resSize2 = sizeof(sead::DirectResource) + constant; // 0x20 + 0x168 = 0x188

totalSize = in->allocSize + resSize2;  // in this branch, in->allocSize seems to be always zero...
if (totalSize <= sizeInTable)
  out->readHeapSize = loadDataAlignment + sizeInTable + sizeof(void*);
else
  out->readHeapSize = (unsigned int)(float)(loadDataAlignment + totalSize + sizeof(void*));
```

Unclear what the 0x40 is. Note that the values are also different in the Wii U version
where constant is 0xe4 and sizeof(sead::DirectResource) is 0x14.

* 0x7100FE1630 (v1.5.0): unclear.
If the file is loaded by the resource memory or loading thread, or if the file size listed in
the RSTB is larger than a TempResourceLoader field, the game prints: "Texture archive size: %u MB"
(translated from Japanese).
