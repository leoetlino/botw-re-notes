## Resource system

### Resource EntryFactory

Derived from `sead::DirectResourceFactoryBase` -> `sead::ResourceFactory` -> `sead::TListNode<sead::ResourceFactory*>` -> `sead::ListNode`, `sead::IDisposer`

After the usual DirectResourceFactory functions, EntryFactory(Base) has two extra functions
that return constant values:

| Extension | sizeof(ResClass) | loadDataAlignment | Other extensions | Multiplier | Constant
| --- | --- | --- | --- | --- | --- |
| Base | 0x20 | 8 | (none) | | |
| ResourceBase | 0x38 (0x20 on Wii U) | 4 | specifically: Tex.bfres, Tex{1,2}.bfres, Tex1.{1,2,3,4}.bfres, and any resource type without its own factory | 1.0 | 0 |
| sarc | 0x68 | 0x80 | bactorpack, bmodelsh, beventpack, stera, stats | | |
| bfres | 0x1a8 | 0x1000 | bfres| | |
| bcamanim | 0x50 | 0x2000 | | | |
| batpl, bnfprl (U?) | 0x40 | 4 | | | |
| bplacement (U?) | 0x48 | 4 | | | |
| hks, lua (U?) | 0x38 | 4 | | | |
| bactcapt (U?) | 0x538 | 4 | | | |
| bitemico | 0x60 | 0x2000 | | | |
| jpg | 0x80 | 0x2000 | | | |
| bmaptex | 0x60 | 0x2000 | | | |
| bmapopen, breviewtex, bstftex | 0x60 | 0x2000 | | | |
| bgdata | 0x140 | 4 | | | |
| bgsvdata | 0x38 | 4 | | | |
| hknm2 | 0x48 | 4 | | | |
| bmscdef | 0x2a8 | 4 | | | |
| bars | 0xb0 | 0x80 | | | |
| bdemo | 0xb20 | 4 | | | |
| bfevfl | 0x40 | 4 | | | |
| bfevtm | 0x40 | 4 | | | |
| esetlist | 0x38 | 0x4000 | | |
| bassetting | 0x260 | 4 | | | |
| byaml | 0x20 | 4 | | | |
| baniminfo | 0x2c8 | 4 | | | |

(this list is incomplete: it's missing tons of factories that are registered in `ActorParam::init`)

For ResourceLoadArg3 (used in model/bfres related code), the factory is hardcoded to be the ResourceBase factory.

For ResourceLoadArg2 (used for actor resources and physics stuff) and ResourceLoadArg (everything else), the factory is determined from the file extension.


### Loading from archives

To load from an archive, set the global resource pack pointer
(`res::ResourceMgrTask::sInstance->packRes` @ this+0x9c06f0).

Calls to any of the resource loading functions will automatically check whether the
specified resource exists in the archive. (The resource system gets a sead::ArchiveRes*
from the resource struct and calls sead::ArchiveRes::getFileImpl() to check.))

If it is, it will be loaded from the archive. (The ResourceBinder will store
the sead::ArchiveRes pointer.)

The game does not namespace archive contents: they can be accessed as if they were at the
root of the romfs/content partition.

If the file cannot be found in the archive, the game will ignore the active resource pack
and load from the usual file device.
