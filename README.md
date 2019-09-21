# Breath of the Wild reverse engineering notes

## What's in this repository?

* Information and sometimes documentation about game internals. These files have the \*.md extension
in this repository. **Note: New documentation will be posted on the [ZeldaMods](https://zeldamods.org/) wiki instead to make it easier to update information for everybody.** Existing documentation is also being moved and will only be updated on the wiki.

* Some plain text files that were extracted from the executable or generated from the ROM,
containing information about game internals as well.

* Tools for understanding some game files in [tools](tools/).

* Tools and IDA scipts for reverse engineering the game and dumping structures/values
from the executable in [tools/ida](tools/ida).

* [A 010 Editor Template for beco files](tools/beco.bt), which are used to map coordinates to
map areas and/or tower areas.

* Some code snippets in [code](code/). I usually rewrite the function in C++ to make game logic easier to understand, since optimised code is hard to read. Sometimes the snippet is just pseudocode output from Hex-Rays. (A lot of snippets are currently in my gists, but I'll probably move them to this repo in the future)

## Tools

Originally this repository also contained a lot of tools for working with the ROM,
such as a SARC archive reader and a library to manipulate the RSTB.

These have been moved to their own repositories to make them more reusable and easier to install:

* [byml](https://github.com/leoetlino/byml-v2): library and CLI tools to convert between YAML and BYML (binary YAML)
* [sarc](https://github.com/leoetlino/sarc): library and CLI tool to create, extract and update SARC archives
* [rstb](https://github.com/leoetlino/rstb): library and CLI tool to query and edit the Resource
Size Table (RSTB)
* [botwfstools](https://github.com/leoetlino/botwfstools) (contentfs, overlayfs, edit, patcher):
tools that make it easier to explore the romfs and edit files by exposing archives as directories
and fixing the RSTB automatically

The following projects might also be helpful for playing with *Breath of the Wild* files:

* [aamp](https://github.com/leoetlino/aamp): library and CLI tools to convert between YAML and AAMP (Nintendo binary parameter archives)
* [evfl](https://github.com/leoetlino/evfl): library for manipulating Breath of the Wild's Event Flow files
* [EventEditor](https://github.com/leoetlino/event-editor): graphical editor for Event Flow files

These can all be installed with `pip install <name of the project>`. Usage information is available
in their respective repositories.

## Credits
Thanks to MrCheeze for botw-tools, the object map and Zer0XoL for BotW-aampTool.
