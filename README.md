# woz2dsk
Converts a .woz image of an unprotected disk into .dsk format

Usage: `python woz2dsk.py <input.woz> <output.dsk>`

Any errors found during conversion will be printed to the console, and the resulting .dsk image will contain zero-valued sector(s) in the corresponding places.

Requires [wozardry](https://github.com/a2-4am/wozardry) and python 3.
