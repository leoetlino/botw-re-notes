# Symbols

Unfortunately, release versions of *The Legend of Zelda: Breath of the Wild* are stripped and
have absolutely no debugging symbols (as far as I know).

This is true in 1.0.0-switch, 1.5.0-wiiu and 1.5.0-switch.

Intermediary updates may or may not have symbols -- I was unable to confirm anything because
I don't have access to other versions. If anyone knows, please update this document.

However, the game shares a large amount of framework code (in the `sead::` namespace)
with *Super Mario Odyssey*, which does come with full symbols.

The game also shares most of the al::ByamlIter class and associated utils. Compared to SMO,
the code in BotW assumes little endian is being used; unused functions -- such as the 64-bit
value functions and writer -- were eliminated.

It also appears that the game shares eui:: (UI code).
