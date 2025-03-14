# mgbdis 

A Game Boy ROM disassembler.


## Features

- Generates assembly code compatible with RGBDS
- Supports ROMs with multiple banks
- Supports .sym files to define labels, code, data, text and image blocks
- Outputs a makefile to rebuild the ROM
- Uses defines from hardware.inc for hardware registers ([source](https://github.com/gbdev/hardware.inc))
- Slow on large ROMs

## Requirements

Requires Python v3.6 or later.

The assembly files generated by mgbdis are designed to be assembled with [RGBDS](https://rgbds.gbdev.io) v0.8.0 or later.

## Usage

Disassemble a ROM:

    ./mgbdis.py some-game.gb

Default output is to the ```disassembly``` directory. You can verify the result of the disassembly by running ```make``` and then checking the ```game.gb``` (or ```game.gbc```) file created:

    cd disassembly && make

There are also a number of options available to control the formatting and instruction style of the generated assembly code. You can view these by running:

    ./mgbdis.py -h

## Symbol Files

Symbol files allow you to indicate where code, data, test and image data blocks are in the ROM. 

The instructions of the Game Boy CPU (SM83) have different lengths, and data can be interleaved with code in the ROM, so it is not possible to always accurately identify where an instruction starts and stops. Defining code blocks in a symbol file can help to avoid problems with mgbdis trying to disassemble in the middle of an instruction. 

If you do not have a symbol file, you can try generating one with my Game Boy emulator - [Beaten Dying Moon](https://mattcurrie.com/bdm/). You can either use the web demo, or there are builds available for Windows and macOS. It can generate a symbol file with code block definitions based on the the addresses of the instructions that have actually been executed while you have been playing the game, avoiding instruction alignment issues.

To use a symbol file with mgbdis, it should exist in the same directory as the ROM and have the same name, except change the extension to be ```.sym```.

All values (except for image widths) should be in hexadecimal.  Entries start with a bank number followed by the address in memory.  

Block types can be defined by using the ```.code```, ```.data```, ```.text```, and ```.image``` magic labels, followed by the length of the block in bytes.

### Code

Adding a label for some code:

```
03:47f2 Read_Joypad_State
```

### Data

Adding a label for 512 bytes of data:

```
0d:4800 Level_Data
0d:4800 .data:200
```

### Text

Adding a label for 16 bytes of text:

```
00:3d00 Character_Name
00:3d00 .text:10
```

#### Custom Character Maps

If the game doesn't use ASCII encoding, it may be practical to use one or more [character maps](https://rgbds.gbdev.io/docs/v0.9.1/rgbasm.5#Character_maps).

1. mgbdis needs to be made aware of the charmaps; this is done by passing a path with `--character-map-path`.
2. Then, you can mark any text label to use one of these character maps instead of the default one, by using cm or charmap followed by the index or name of the character map you want to use.

Adding a label using the first character map for 16 bytes of text:

```
00:3d00 Character_Name
00:3d00 .text:10:charmap=0
```

### Image

The ```.image``` magic label allows you to define blocks of 1 or 2 bits per pixel tile data in the ROM.  Images are output as PNG files in the ```/gfx``` directory of the disassembly, and are converted back to 1bpp or 2bpp tile data by the makefile using rgbgfx.  If a label is specified at the address of the image block then it will be used for the name of the PNG file.

The block length in bytes should be a multiple of 16, as each tile requires 16 bytes of image data.

The image width in pixels can be specified as a decimal number prefixed with ```w```. The width value should be a multiple of 8, and the combination of block length and image width must result in a rectangluar image without any empty tiles. The default image width is ```128``` pixels, or if the block length indicates an odd number of tiles, then an image with a single row of tiles will be generated.

The palette is a byte sized value which selects the shades of grey to use when generating the image. It uses the same format as the BGP register at ```0xFF47```.  The value can be specified in hexidecimal prefixed with ```p```. The default palette is ```E4```.

The default is to treat it as 2 bits per pixel tile data. A ```1bpp``` option can be supplied to treat the data as 1 bit per pixel tile data.

Adding a label for 1280 bytes of tile data, with a width of 128 pixels and palette 0xE4:

```
02:791a Title_Screen_Tile_Data
02:791a .image:500:w128,pe4
```

Resulting image:

![Imgur](https://i.imgur.com/2duQ7Py.png)


Example for 1bpp tile data:

```
05:4000 Font
05:4000 .image:200:w128,1bpp
```

Resulting image:

![Imgur](https://i.imgur.com/iX5FCXL.png)

## Notes

- RGBDS automatically adds ```NOP``` instructions after ```STOP```, so the disassembler will output this instruction as a data byte if the instruction is not followed by a ```NOP``` in the original ROM.
