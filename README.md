# mgbdis 

A Game Boy ROM disassembler.


## Features

- Generates assembly code compatible with RGBDS
- Supports ROMs with multiple banks
- Supports .sym files to define labels, code, data and text blocks
- Outputs a makefile to rebuild the ROM
- Uses defines from hardware.inc v2.6 for hardware registers ([source](https://github.com/tobiasvl/hardware.inc))
- Slow on large ROMs


## Usage

Disassemble a ROM:

    ./mgbdis.py some-game.gb

Default output is to the ```disassembly``` directory. You can verify the result of the disassembly by running ```make``` and then checking the ```game.gb``` (or ```game.gbc```) file created:

    cd disassembly
    make && md5 game.gb


## Symbol Files

To use a symbol file, it should exist in the same directory as the ROM and have the same name, except change the extension to be ```.sym```.

All values should be in hexadecimal.  Entries start with a bank number followed by the address in memory.  

Block types can be defined by using the ```.code```, ```.data```, ```.text``` magic labels, followed by the length of the block in bytes.

Adding a label for some code:

```
03:47f2 Read_Joypad_State
```

Adding a label for 512 bytes of data:

```
0d:4800 Level_Data
0d:4800 .data:200
```

Adding a label for 16 bytes of text:

```
00:3d00 Character_Name
00:3d00 .text:10
```


## Notes

- RGBDS optimises instructions like ```LD [$FF40],a``` to ```LDH [$FF00+40],a```, so these are encoded as data bytes using a macro to ensure exact reproduction of the original ROM (thanks to ISSOtm).
- RGBDS automatically adds ```NOP``` instructions after ```STOP``` and ```HALT```, so the disassembler will output these as data bytes if the instruction is not followed by a ```NOP``` in the original ROM.


