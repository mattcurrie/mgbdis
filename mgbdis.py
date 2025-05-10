#!/usr/bin/env python3

"""Disassemble a Game Boy ROM into RGBDS compatible assembly code"""

__author__ = 'Matt Currie and contributors'
__credits__ = ['mattcurrie', 'kemenaran', 'bnzis', 'ISSOtm', 'BlueAnthem37510']
__version__ = '3.0'
__copyright__ = 'Copyright 2018 by Matt Currie'
__license__ = 'MIT'

import argparse
import glob
import hashlib
import os
import png
import re
from shutil import copyfile

from instruction_set import instructions, cb_instructions, instruction_variants

default_symbols = [
    '00:0000 RST_00',
    '00:0000 .code:8',
    '00:0008 RST_08',
    '00:0008 .code:8',
    '00:0010 RST_10',
    '00:0010 .code:8',
    '00:0018 RST_18',
    '00:0018 .code:8',
    '00:0020 RST_20',
    '00:0020 .code:8',
    '00:0028 RST_28',
    '00:0028 .code:8',
    '00:0030 RST_30',
    '00:0030 .code:8',
    '00:0038 RST_38',
    '00:0038 .code:8',

    '00:0040 VBlankInterrupt',
    '00:0040 .code:8',
    '00:0048 LCDCInterrupt',
    '00:0048 .code:8',
    '00:0050 TimerOverflowInterrupt',
    '00:0050 .code:8',
    '00:0058 SerialTransferCompleteInterrupt',
    '00:0058 .code:8',
    '00:0060 JoypadTransitionInterrupt',
    '00:0060 .code:8',

    '00:0100 Boot',
    '00:0100 .code:4',
    '00:0104 HeaderLogo',
    '00:0104 .data:30',
    '00:0134 HeaderTitle',
    '00:0134 .text:10',
    '00:0144 .data:c',
    '00:0144 HeaderNewLicenseeCode',
    '00:0146 HeaderSGBFlag',
    '00:0147 HeaderCartridgeType',
    '00:0148 HeaderROMSize',
    '00:0149 HeaderRAMSize',
    '00:014a HeaderDestinationCode',
    '00:014b HeaderOldLicenseeCode',
    '00:014c HeaderMaskROMVersion',
    '00:014d HeaderComplementCheck',
    '00:014e HeaderGlobalChecksum',
]

gbc_symbols = [
    '00:0134 .text:b',
    '00:013f HeaderManufacturerCode',
    '00:013f .text:4',
    '00:0143 HeaderCGBFlag',
    '00:0143 .data:1'
]

hardware_labels = {
    0xFF00: 'rP1',
    0xFF01: 'rSB',
    0xFF02: 'rSC',
    0xFF04: 'rDIV',
    0xFF05: 'rTIMA',
    0xFF06: 'rTMA',
    0xFF07: 'rTAC',
    0xFF0F: 'rIF',
    0xFF40: 'rLCDC',
    0xFF41: 'rSTAT',
    0xFF42: 'rSCY',
    0xFF43: 'rSCX',
    0xFF44: 'rLY',
    0xFF45: 'rLYC',
    0xFF46: 'rDMA',
    0xFF47: 'rBGP',
    0xFF48: 'rOBP0',
    0xFF49: 'rOBP1',
    0xFF4A: 'rWY',
    0xFF4B: 'rWX',
    0xFF4D: 'rKEY1',
    0xFF4F: 'rVBK',
    0xFF51: 'rHDMA1',
    0xFF52: 'rHDMA2',
    0xFF53: 'rHDMA3',
    0xFF54: 'rHDMA4',
    0xFF55: 'rHDMA5',
    0xFF56: 'rRP',
    0xFF68: 'rBCPS',
    0xFF69: 'rBCPD',
    0xFF6A: 'rOCPS',
    0xFF6B: 'rOCPD',
    0xFF70: 'rSVBK',
    0xFFFF: 'rIE',
    0xFF24: 'rNR50',
    0xFF25: 'rNR51',
    0xFF26: 'rNR52',
    0xFF10: 'rNR10',
    0xFF11: 'rNR11',
    0xFF12: 'rNR12',
    0xFF13: 'rNR13',
    0xFF14: 'rNR14',
    0xFF16: 'rNR21',
    0xFF17: 'rNR22',
    0xFF18: 'rNR23',
    0xFF19: 'rNR24',
    0xFF1A: 'rNR30',
    0xFF1B: 'rNR31',
    0xFF1C: 'rNR32',
    0xFF1D: 'rNR33',
    0xFF1E: 'rNR34',
    0xFF20: 'rNR41',
    0xFF21: 'rNR42',
    0xFF22: 'rNR43',
    0xFF23: 'rNR44',
    0xFF76: 'rPCM12',
    0xFF77: 'rPCM34',
}

ldh_a8_formatters = {
    'ldh_a8': lambda value: '[{0}]'.format(hex_byte(value)),
    'ld_ff00_a8': lambda value: '[{0}+{1}]'.format(hex_word(0xff00), hex_byte(value)),
    'ldh_ffa8': lambda value: '[{0}]'.format(hex_word(0xff00 + value)),
}
special_characters = {
    0 : '\0', #null
    92 : '\\\\',
    34 : '\\"',
    123 : '\\{',
    125 : '\\}'
}

def warn(*args, **kwargs):
    print("WARNING: ", *args, **kwargs)

def abort(message):
    print("FATAL: ", message)
    os._exit(1)


def hex_word(value):
    if style['uppercase_hex']:
        return f'${value:04X}'
    else:
        return f'${value:04x}'        


def hex_byte(value):
    if style['uppercase_hex']:
        return f'${value:02X}'
    else:
        return f'${value:02x}'   

def format_hex(hex_string):
    if style['uppercase_hex']:
        return hex_string.upper()
    else:
        return hex_string.lower()

def bytes_to_string(data):
    return ' '.join(hex_byte(byte) for byte in data)


def rom_address_to_mem_address(address):
    if address < 0x4000:
        return address
    else:
        return ((address % 0x4000) + 0x4000)


def to_signed(value):
    if value > 127:
        return (256 - value) * -1
    return value

def apply_style_to_instructions(style, instructions):
    # set undefined opcodes to use db/DB
    for opcode, instruction in instructions.items():
        if instruction.startswith('db '):
            instructions[opcode] = style['db'] + ' ' + hex_byte(opcode)

    # set instruction variants
    for variant_name, variants in instruction_variants.items():
        for opcode, instruction in variants[style[variant_name]].items():
            instructions[opcode] = instruction

    return instructions


class Bank:

    def __init__(self, number, symbols, style, bank0, size, rom):
        self.style = style
        self.bank_number = number
        self.blocks = {}
        self.disassembled_addresses = set()
        self.symbols = symbols
        self.size = size
        self.bank0 = bank0

        if number == 0:
            self.memory_base_address = 0
            self.rom_base_address = 0
        else:
            self.memory_base_address = 0x4000
            self.rom_base_address = (number - 1) * 0x4000

        self.size_without_padding = self.size
        if rom.last_byte in (0x00,0xff):
            while rom.data[ self.memory_base_address + self.rom_base_address + self.size_without_padding - 1] == rom.last_byte and self.size_without_padding != 0:
                self.size_without_padding = self.size_without_padding - 1

        self.target_addresses = dict({
            'call': set(),
            'jp': set(),
            'jr': set()
        })

        self.instruction_label_prefixes = dict({
            'call': 'Call',
            'jp': 'Jump',
            'jr': 'jr'
        })

        self.disassemble_block_range = dict({
            'code': self.process_code_in_range,
            'data': self.process_data_in_range,
            'text': self.process_text_in_range,
            'image': self.process_image_in_range
        })


    def add_target_address(self, instruction_name, address):
        if address not in self.target_addresses[instruction_name]:
            self.target_addresses[instruction_name].add(address)


    def resolve_blocks(self):
        blocks = self.symbols.get_blocks(self.bank_number, self.size)
        block_start_addresses = sorted(blocks.keys())
        resolved_blocks = {}

        for index in range(len(block_start_addresses)):

            start_address = block_start_addresses[index]
            block = blocks[start_address]
            end_address = start_address + block['length']

            # check if there is another block after this block
            next_start_address = None
            if index < len(block_start_addresses) - 1:
                next_start_address = block_start_addresses[index + 1]

                # if the next block starts before this one finishes, then adjust end address
                if next_start_address < end_address:
                    end_address = next_start_address

            resolved_blocks[start_address] = {
                'type': block['type'],
                'length': end_address - start_address,
                'arguments': block['arguments'],
            }

            if next_start_address is None and (end_address != self.memory_base_address + self.size):
                # no more blocks and didn't finish at the end of the block, so finish up with a code block
                resolved_blocks[end_address] = {
                    'type': 'code',
                    'length': (self.memory_base_address + self.size) - end_address,
                    'arguments': None
                }

            if next_start_address is not None and end_address < next_start_address:
                # we have another block, but there is a gap until the next block, so fill in the gap with a code block
                resolved_blocks[end_address] = {
                    'type': 'code',
                    'length': next_start_address - end_address,
                    'arguments': None
                }

        self.blocks = resolved_blocks

    def get_label(self, address):
        if self.bank_number != 0 and address < 0x4000:
            return self.bank0.symbols.get_label(0, address)
        return self.symbols.get_label(self.bank_number, address)

    def get_label_for_instruction_operand(self, value):
        # an operand value lower than $100 is more probably an actual value than an address:
        # don't lookup symbols for it
        if value <= 0x100:
            return None

        return self.get_label(value)

    def get_label_for_jump_target(self, instruction_name, address):
        if self.bank_number == 0:
            if address not in self.disassembled_addresses:
                return None
        else:
            is_in_switchable_bank = 0x4000 <= address < 0x8000
            # if target address is in bank 0 then check if that address has been
            # disassembled in bank 0
            if not is_in_switchable_bank:
                return self.bank0.get_label_for_jump_target(instruction_name, address)
            if address not in self.disassembled_addresses:
                return None

        label = self.get_label(address)
        if label is not None:
            # if the address has a specific label then just use that
            return label

        if address in self.target_addresses[instruction_name]:
            return self.format_label(instruction_name, address)

        return None


    def get_labels_for_non_code_address(self, address):
        labels = []

        label = self.get_label(address)
        if label is not None:
            is_local = label.startswith('.')
            if is_local:
                labels.append(label + ':')
            else:
                labels.append(label + '::')

        return labels


    def get_labels_for_address(self, address):
        labels = []

        label = self.get_label(address)
        if label is not None:
            # if the address has a specific label then just use that
            is_local = label.startswith('.')
            if is_local:
                labels.append(label + ':')
            else:
                labels.append(label + '::')
        else:
            # otherwise, if the address was marked as a target address, generate a label
            for instruction_name in ['call', 'jp', 'jr']:
                if address in self.target_addresses[instruction_name]:
                    labels.append(self.format_label(instruction_name, address) + ':')

        return labels


    def format_label(self, instruction_name, address):
        formatted_bank = format_hex(f'{self.bank_number:03x}')
        formatted_address = format_hex(f'{address:04x}')
        return f'{self.instruction_label_prefixes[instruction_name]}_{formatted_bank}_{formatted_address}'                


    def format_image_label(self, address):
        return 'image_{0:03x}_{1:04x}'.format(self.bank_number, address)


    def format_instruction(self, instruction_name, operands, address = None, source_bytes = None):
        instruction = f"{self.style['indentation']}{instruction_name:<{self.style['operand_padding']}} {', '.join(operands)}"

        if self.style['print_hex'] and address is not None and source_bytes is not None:
            return f"{instruction:<50}; {hex_word(address)}: {bytes_to_string(source_bytes)}"
        else:
            return instruction.rstrip()


    def format_data(self, data):
        return self.format_instruction(self.style['db'], data)


    def append_output(self, text):
        self.output.append(text)


    def append_labels_to_output(self, labels):
        self.append_empty_line_if_none_already()
        self.append_output('\n'.join(labels))


    def append_empty_line_if_none_already(self):
        if len(self.output) > 0 and self.output[len(self.output) - 1] != '':
            self.append_output('')


    def disassemble(self, rom, first_pass = False):
        self.first_pass = first_pass
        self.current_map_index = None
        if first_pass:
            self.resolve_blocks()

        self.output = []

        if self.bank_number == 0:
            self.append_output('SECTION "ROM Bank ${0:03x}", ROM0[$0]'.format(self.bank_number))
        else:
            self.append_output('SECTION "ROM Bank ${0:03x}", ROMX[$4000], BANK[${0:x}]'.format(self.bank_number))
        self.append_output('')

        block_start_addresses = sorted(self.blocks.keys())

        for index in range(len(block_start_addresses)):
            start_address = block_start_addresses[index]
            block = self.blocks[start_address]
            end_address = start_address + block['length']
            self.disassemble_block_range[block['type']](rom, self.rom_base_address + start_address, self.rom_base_address + end_address, block['arguments'])
            self.append_empty_line_if_none_already()
        return '\n'.join(self.output)


    def process_code_in_range(self, rom, start_address, end_address, arguments = None):
        if not self.first_pass and debug:
            print('Disassembling code in range: {} - {}'.format(hex_word(start_address), hex_word(end_address)))

        self.pc = start_address
        while self.pc < end_address:
            instruction = self.disassemble_at_pc(rom, end_address)


    def disassemble_at_pc(self, rom, end_address):
        pc = self.pc
        pc_mem_address = rom_address_to_mem_address(pc)
        length = 1
        opcode = rom.data[pc]
        comment = None
        operands = None
        operand_values = []

        if opcode not in instructions:
            abort('Unhandled opcode: {} at {}'.format(hex_byte(opcode), hex_word(pc)))

        if opcode == 0xCB:
            cb_opcode = rom.data[pc + 1]
            length += 1

            instruction_name = rom.cb_instruction_name[cb_opcode]
            operands = rom.cb_instruction_operands[cb_opcode]
        else:
            instruction_name = rom.instruction_names[opcode]
            operands = rom.instruction_operands[opcode]

        if instruction_name == 'stop':
            if rom.data[pc + 1] == 0x00:
                # rgbds adds a nop instruction after a stop, so if that instruction
                # exists then we can insert it as a stop command with length 2
                length += 1
            else:
                # otherwise handle it as a data byte
                instruction_name = self.style['db']
                operands = [hex_byte(opcode)]


        # figure out the operand values for each operand
        for operand in operands:
            value = None

            if operand == 'a16':
                length += 2
                value = rom.data[pc + 1] + rom.data[pc + 2] * 256
                operand_values.append(hex_word(value))

            elif operand == '[a16]':
                length += 2
                value = rom.data[pc + 1] + rom.data[pc + 2] * 256
                label = self.get_label_for_instruction_operand(value)
                if label:
                    operand_values.append('[' + label + ']')
                else:
                    operand_values.append('[' + hex_word(value) + ']')

            elif operand == '[$ff00+a8]' or operand == '[a8]' or operand == '[$ffa8]':
                length += 1
                value = rom.data[pc + 1]
                full_value = 0xff00 + value
                label = self.get_label_for_instruction_operand(full_value)
                if label is not None:
                    # when referencing a label, we need to explicitely tell rgbds to use the short load opcode
                    instruction_name = 'ldh'
                    operand_values.append('[{}]'.format(label))
                elif full_value in hardware_labels:
                    operand_values.append('[{}]'.format(hardware_labels[full_value]))
                else:
                    # use one of the ldh_a8_formatters formatters
                    operand_values.append(ldh_a8_formatters[self.style['ldh_a8']](value))

            elif operand == 'd8':
                length += 1
                value = rom.data[pc + 1]
                operand_values.append(hex_byte(value))

            elif operand == 'd16':
                length += 2
                value = rom.data[pc + 1] + rom.data[pc + 2] * 256
                label = self.get_label_for_instruction_operand(value)
                if label is not None:
                    operand_values.append(label)
                else:
                    operand_values.append(hex_word(value))

            elif operand == 'r8':
                length += 1
                value = to_signed(rom.data[pc + 1])
                if value < 0:
                    operand_values.append('-' + hex_byte(abs(value)))
                else:
                    operand_values.append(hex_byte(value))

            elif operand == 'pc+r8':
                length += 1
                value = to_signed(rom.data[pc + 1])

                # calculate the absolute address for the jump
                rom_address = pc + 2 + value

                relative_value = rom_address - pc
                if relative_value >= 0:
                    operand_values.append('@+' + hex_byte(relative_value))
                else:
                    operand_values.append('@-' + hex_byte(relative_value * -1))

                # convert to banked value so it can be used as a label
                value = rom_address_to_mem_address(rom_address)

                # is the jump target is in this bank?
                if (rom_address >= self.rom_base_address + self.memory_base_address and 
                    rom_address < self.rom_base_address + self.memory_base_address + self.size):
                    # yep!
                    pass
                else:
                    # don't use labels for relative jumps across banks
                    value = None

                if rom_address < self.rom_base_address + self.memory_base_address:
                    # output as data, otherwise RGBDS will complain
                    instruction_name = self.style['db']
                    operand_values = [hex_byte(opcode), hex_byte(rom.data[pc + 1])]

                    # exit the loop to avoid processing the operands any further
                    break

            elif operand == 'sp+r8':
                length += 1
                value = to_signed(rom.data[pc + 1])

                if value < 0:
                    operand_values.append('sp-' + hex_byte(abs(value)))
                else:
                    operand_values.append('sp+' + hex_byte(value))

            elif operand == '[$ff00+c]':
                operand_values.append('[{0}+c]'.format(hex_word(0xff00)))

            elif type(operand) is str:
                operand_values.append(operand)

            else:
                operand_values.append(hex_byte(operand))


            if instruction_name in ['jr', 'jp', 'call'] and value is not None and value < 0x8000:
                mem_address = rom_address_to_mem_address(value)

                if self.first_pass:
                    # add the label
                    if mem_address >= self.memory_base_address and mem_address < self.memory_base_address + self.size_without_padding:
                        # label in cur bank
                        self.add_target_address(instruction_name, mem_address)
                    elif mem_address < 0x4000 and self.bank0 and mem_address < self.bank0.size_without_padding:
                        # label in fixed bank
                        self.bank0.add_target_address(instruction_name, mem_address)
                else:
                    # fetch the label name
                    label = self.get_label_for_jump_target(instruction_name, mem_address)
                    if label is not None:
                        # remove the address from operand values and use the label instead
                        operand_values.pop()
                        operand_values.append(label)


        # check the instruction is not spanning 2 banks
        if pc + length - 1 >= end_address:
            # must handle it as data
            length = 1
            instruction_name = self.style['db']
            operand_values = [hex_byte(opcode)]

        self.pc += length

        if self.first_pass:
            self.disassembled_addresses.add(pc_mem_address)
        else:
            labels = self.get_labels_for_address(pc_mem_address)
            if len(labels):
                self.append_labels_to_output(labels)

            if comment is not None:
                self.append_output(comment)

            instruction_bytes = rom.data[pc:pc + length]
            self.append_output(self.format_instruction(instruction_name, operand_values, pc_mem_address, instruction_bytes))

            # add some empty lines after returns and jumps to break up the code blocks
            if instruction_name in ['ret', 'reti', 'jr', 'jp']:
                if (
                    instruction_name == 'jr' or
                    (instruction_name == 'jp' and len(operand_values) > 1) or
                    (instruction_name == 'ret' and len(operand_values) > 0)
                ):
                    # conditional or jr
                    self.append_output('')
                else:
                    # always executes
                    self.append_output('')
                    self.append_output('')


    def process_data_in_range(self, rom, start_address, end_address, arguments = None):
        if not self.first_pass and debug:
            print('Outputting data in range: {} - {}'.format(hex_word(start_address), hex_word(end_address)))

        values = []

        for address in range(start_address, end_address):
            mem_address = rom_address_to_mem_address(address)

            labels = self.get_labels_for_non_code_address(mem_address)
            if len(labels):
                # add any existing values to the output and reset the list
                if len(values) > 0:
                    self.append_output(self.format_data(values))
                    values = []

                self.append_labels_to_output(labels)

            values.append(hex_byte(rom.data[address]))

            # output max of 16 bytes per line, and ensure any remaining values are output
            if len(values) == 16 or (address == end_address - 1 and len(values)):
                self.append_output(self.format_data(values))
                values = []

    def get_character_map_index(self, arguments):
        #no args
        if arguments == None:
            return -1
        name = None
        for argument in arguments.split(":"):
            key_value = argument.split("=", 1)
            if len(key_value) == 2:
                key,name = key_value
            else:
                key = key_value[0]
                name = "0"
            if key == "cm" or key == "charmap":
                break
        else:
            return -1
        #map name
        for m in range(len(rom.character_maps)):
            if rom.character_maps[m].name == name:
                return m     
        #index
        if name.isnumeric():
            map_index = int(name)
            if map_index >= len(rom.character_maps):
                abort("Character map index {} out of range".format(name))
            return map_index
        #no charmap found                       
        abort("Character map '{}' does not exist.".format(name)) 

    def process_text_in_range(self, rom, start_address, end_address, arguments = None):
        if not self.first_pass and debug:
            print('Outputting text in range: {} - {}'.format(hex_word(start_address), hex_word(end_address)))
        # process arguments
        custom_map = False                          
        map_index = self.get_character_map_index(arguments)
        if map_index != -1 and map_index < len(rom.character_maps):
            custom_map = True
            if self.current_map_index != map_index:
                self.current_map_index = map_index                       
                self.append_output("SETCHARMAP "+rom.character_maps[map_index].name)                                                   
        if map_index == -1 and self.current_map_index != None:  
            self.current_map_index = None
            self.append_output("SETCHARMAP main")
        values = []
        text = ''
        address = start_address - 1        
        while(address < end_address-1):
            address += 1   
            mem_address = rom_address_to_mem_address(address)
        
            labels = self.get_labels_for_non_code_address(mem_address)
            if len(labels):
                # add any existing values to the output and reset the list
                if len(text):
                    values.append('"{}"'.format(text))
                    text = ''

                if len(values):
                    self.append_output(self.format_data(values))
                    values = []

                self.append_labels_to_output(labels)

            byte = rom.data[address]
            if custom_map:
                key = None
                character_map = rom.character_maps[self.current_map_index]
                #check for multi length character mapping
                for length in range(character_map.max_length, 1,-1):                    
                    if address + length-1 > end_address: 
                        continue                  
                    to_check = tuple(list(rom.data[address: address+length]))                                        
                    if to_check in character_map.character_map:
                        key = to_check
                        break            
                if key == None:
                    if byte in character_map.character_map:
                        key = byte
                if key != None:
                    text += character_map.character_map[key]
                    if isinstance(key, tuple):
                        address += len(key)-1
                else:
                   
                    if len(text):
                        values.append('"{}"'.format(text))
                        text = ''
                    values.append(hex_byte(byte))
            else:
                if byte >= 0x20 and byte < 0x7F:
                    if byte in special_characters:
                        character = special_characters[byte]
                    else:
                        character = chr(byte)
                    text += character
                else:
                    if len(text):
                        values.append('"{}"'.format(text))
                        text = ''
                    values.append(hex_byte(byte))

        if len(text):
            values.append('"{}"'.format(text))

        if len(values):
            self.append_output(self.format_data(values))
    def process_image_in_range(self, rom, start_address, end_address, arguments = None):
        if not self.first_pass and debug:
            print('Outputting image in range: {} - {}'.format(hex_word(start_address), hex_word(end_address)))

        if self.first_pass:
            return

        mem_address = rom_address_to_mem_address(start_address)
        labels = self.get_labels_for_non_code_address(mem_address)
        if len(labels):
            self.append_labels_to_output(labels)
            basename = labels[0].rstrip(':')
        else:
            basename = self.format_image_label(mem_address)

        full_filename = rom.write_image(basename, arguments, rom.data[start_address:end_address])
        self.append_output(self.format_instruction('INCBIN', ['\"' + full_filename + '\"']))




class Symbols:
    def __init__(self, bank_size):
        self.symbols = {}
        self.blocks = {}
        self.bank_size = bank_size

    def load_sym_file(self, symbols_path):
        f = open(symbols_path, 'r')

        for line in f:
            # ignore comments and empty lines
            if line[0] != ';' and len(line.strip()):
                self.add_symbol_definition(line)

        f.close()


    def add_symbol_definition(self, symbol_def):
        try:
            location, label = symbol_def.split()
            bank, address = location.split(':')
            bank = int(bank, 16)
            address = int(address, 16)
        except:
            print("Ignored invalid symbol definition: {}\n".format(symbol_def))
        else:
            label_parts = label.split(':')
            is_block_definition = label[0] == '.' and len(label_parts) >= 2

            if is_block_definition:
                # add a block
                block_type = label_parts[0].lower()
                data_length = int(label_parts[1], 16)

                if block_type in ['.byt', '.data']:
                    block_type = 'data'

                elif block_type in ['.asc', '.text']:
                    block_type = 'text'

                elif block_type in ['.code']:
                    block_type = 'code'

                elif block_type in ['.image']:
                    block_type = 'image'

                else:
                    return

                if len(label_parts) == 3:
                    arguments = label_parts[2]
                else:
                    arguments = None

                self.add_block(bank, address, block_type, data_length, arguments)

            else:
                # add the label
                self.add_label(bank, address, label)

    def add_block(self, bank, address, block_type, length, arguments = None):
        memory_base_address = 0x0000 if bank == 0 else 0x4000

        if address >= memory_base_address:
            blocks = self.get_blocks(bank, self.bank_size)
            blocks[address] = {
                'type': block_type,
                'length': length,
                'arguments': arguments
            }

    def add_label(self, bank, address, label):
        if bank not in self.symbols:
            self.symbols[bank] = {}

        is_symbol_banked = self.bank_size <= address < 0x8000
        if is_symbol_banked:
            self.symbols[bank][address] = label
        else:
            self.symbols[0][address] = label

    def get_label(self, bank, address):
        # attempt to find a banked symbol
        is_symbol_banked = self.bank_size <= address < 0x8000
        if is_symbol_banked and bank in self.symbols and address in self.symbols[bank]:
            return self.symbols[bank][address]

        # attempt to find a symbol in non-banked space (stored as bank 0)
        if 0 in self.symbols and address in self.symbols[0]:
            return self.symbols[0][address]

        return None

    def get_blocks(self, bank, size):
        memory_base_address = 0x0000 if bank == 0 else 0x4000

        if bank not in self.blocks:
            self.blocks[bank] = {}
            # each bank defaults to having a single code block
            self.add_block(bank, memory_base_address, 'code', self.bank_size)

        return self.blocks[bank]

class ROM:

    def __init__(self, rom_path, style, tiny, character_maps):
        self.style = style
        self.script_dir = os.path.dirname(os.path.realpath(__file__))
        self.rom_path = rom_path
        self.load(tiny)
        self.split_instructions()
        self.tiny = tiny
        self.character_maps = character_maps        

        self.image_output_directory = 'gfx'
        self.image_dependencies = []

        print('ROM MD5 hash:', hashlib.md5(self.data).hexdigest())

        self.symbols = self.load_symbols()

        # add some bytes to avoid an index out of range error
        # when processing last few instructions in the rom
        self.data += b'\x00\x00'

        size = self.rom_size
        if tiny:
            self.banks = [Bank(0, self.symbols, style, None, min(size, 0x8000), self)]
        else:
            self.banks = [Bank(0, self.symbols, style, None, min(size, 0x4000), self)]
            for bank in range(1, self.num_banks):
                size -= 0x4000
                self.banks.append(Bank(bank, self.symbols, style, self.banks[0], min(size, 0x4000), self))

    def load(self, tiny):
        if os.path.isfile(self.rom_path):
            print('Loading "{}"...'.format(self.rom_path))
            with open(self.rom_path, 'rb') as f:
                self.data = f.read()
            self.rom_size = len(self.data)
            self.last_byte= self.data[self.rom_size - 1]
            if self.last_byte in (0x00,0xff):
                print("padding: {}".format(hex_byte(self.last_byte)))
            if self.rom_size < 0x150:
                abort("ROM is too small, doesn't even contain a header!")
            self.num_banks = self.rom_size // 0x4000
            if self.rom_size % 0x4000 != 0:
                warn(f"ROM size (${self.rom_size:04x}) is not a multiple of $4000!")
                self.num_banks += 1 # Count that incomplete bank
            if tiny:
                if self.num_banks > 2:
                    abort(f"ROM is ${self.rom_size:04x} bytes large, tiny ROMs can only be $8000 at most")
                self.num_banks = 1
        else:
            abort('"{}" not found'.format(self.rom_path))


    def split_instructions(self):
        # split the instructions and operands
        self.instruction_names = {}
        self.instruction_operands = {}
        self.cb_instruction_name = {}
        self.cb_instruction_operands = {}

        for opcode in instructions:
            instruction_parts = instructions[opcode].split()
            self.instruction_names[opcode] = instruction_parts[0]
            if len(instruction_parts) > 1:
                self.instruction_operands[opcode] = instruction_parts[1].split(',')
            else:
                self.instruction_operands[opcode] = []

        for cb_opcode in cb_instructions:
            instruction_parts = cb_instructions[cb_opcode].split()
            self.cb_instruction_name[cb_opcode] = instruction_parts[0]
            if len(instruction_parts) > 1:
                self.cb_instruction_operands[cb_opcode] = instruction_parts[1].split(',')
            else:
                self.cb_instruction_operands[cb_opcode] = []


    def load_symbols(self):
        symbols = Symbols(0x8000 if self.tiny else 0x4000)

        for symbol_def in default_symbols:
            symbols.add_symbol_definition(symbol_def)

        if self.supports_gbc():
            for symbol_def in gbc_symbols:
                symbols.add_symbol_definition(symbol_def)

        symbols_path = os.path.splitext(self.rom_path)[0] + '.sym'
        if os.path.isfile(symbols_path):
            print('Processing symbol file "{}"...'.format(symbols_path))
            symbols.load_sym_file(symbols_path)

        return symbols


    def supports_gbc(self):
        return ((self.data[0x143] & 0x80) == 0x80)


    def disassemble(self, output_dir):

        self.output_directory = os.path.abspath(output_dir.rstrip(os.sep))

        if os.path.exists(self.output_directory):
            if not args.overwrite:
                abort('Output directory "{}" already exists!'.format(self.output_directory))

            if not os.path.isdir(self.output_directory):
                abort('Output path "{}" already exists and is not a directory!'.format(self.output_directory))
        else:
            os.makedirs(self.output_directory)


        print('Generating labels...')
        self.generate_labels()

        self.image_dependencies = []

        print('Generating disassembly', end='')
        if debug:
            print('')

        for bank in range(0, self.num_banks):
            if self.banks[bank].size_without_padding != 0:
                self.write_bank_asm(bank)

        self.copy_hardware_inc()
        self.copy_charater_map()
        self.write_game_asm()
        self.write_makefile()

        print('\nDisassembly generated in "{}"'.format(self.output_directory))


    def generate_labels(self):
        for bank in range(0, self.num_banks):
            self.banks[bank].disassemble(rom, True)


    def write_bank_asm(self, bank):
        if not debug:
            # progress indicator
            print('.', end='', flush=True)

        path = os.path.join(self.output_directory, 'bank_{0:03x}.asm'.format(bank))
        f = open(path, 'w', encoding="utf-8")

        self.write_header(f)
        f.write(self.banks[bank].disassemble(rom))

        f.close()


    def write_header(self, f):
        f.write('; Disassembly of "{}"\n'.format(os.path.basename(self.rom_path)))
        f.write('; This file was created with:\n')
        f.write('; {}\n'.format(app_name))
        f.write('; https://github.com/mattcurrie/mgbdis\n\n')


    def copy_hardware_inc(self):
        src = os.path.join(self.script_dir, 'hardware.inc')
        dest = os.path.join(self.output_directory, 'hardware.inc')
        copyfile(src, dest)
    def get_character_map_paths(self):
        return list(set([p.path for p in self.character_maps]))
    def copy_charater_map(self):
        paths = self.get_character_map_paths()
        for src in paths:
            dest =  os.path.join(self.output_directory, os.path.basename(src))
            copyfile(src, dest)
    def write_game_asm(self):
        path = os.path.join(self.output_directory, 'game.asm')
        f = open(path, 'w', encoding="utf-8")

        self.write_header(f)

        f.write('INCLUDE "hardware.inc"')
        character_maps = self.get_character_map_paths()
        if(len(character_maps) > 0):
            for map in character_maps:
                f.write('\nINCLUDE "{}"'.format(os.path.basename(map)))
            f.write('\nSETCHARMAP main')
        for bank in range(0, self.num_banks):
            if self.banks[bank].size_without_padding != 0:
                f.write('\nINCLUDE "bank_{0:03x}.asm"'.format(bank))
        f.close()

    def write_image(self, basename, arguments, data):

        # defaults
        width = 128
        palette = 0xe4
        bpp = 2

        # process arguments
        if arguments is not None:
            for argument in arguments.split(','):
                if len(argument) > 1:
                    if argument[0] == 'w':
                        # width is in decimal
                        width = int(argument[1:], 10)

                    elif argument[0] == 'p':
                        palette = int(argument[1:], 16)

                    elif argument == '1bpp':
                        bpp = 1

        image_output_path = os.path.join(self.output_directory, self.image_output_directory)
        if os.path.exists(image_output_path):
            if not os.path.isdir(image_output_path):
                abort('File already exists named "{}". Cannot store images!'.format(image_output_path))
        else:
            os.makedirs(image_output_path)

        relative_path = os.path.join(self.image_output_directory, basename + '.' + "{}bpp".format(bpp))
        self.image_dependencies.append(relative_path)
        path = os.path.join(self.output_directory, self.image_output_directory, basename + '.png')

        bytes_per_tile_row = bpp  # 8 pixels at 1 or 2 bits per pixel
        bytes_per_tile = bytes_per_tile_row * 8  # 8 rows per tile

        num_tiles = len(data) // bytes_per_tile
        tiles_per_row = width // 8

        # if we have fewer tiles than the number of tiles per row, or if an odd number of tiles
        if (num_tiles < tiles_per_row) or (num_tiles & 1):
            # then just make a single row of tiles
            tiles_per_row = num_tiles
            width = num_tiles * 8

        tile_rows = (num_tiles / tiles_per_row)
        if not tile_rows.is_integer():
            abort('Invalid length ${:0x} or width {} for image block: {}'.format(len(data), width, basename))

        height = int(tile_rows) * 8

        pixel_data = self.convert_to_pixel_data(data, width, height, bpp)
        rgb_palette = self.convert_palette_to_rgb(palette, bpp)

        f = open(path, 'wb')
        w = png.Writer(width, height, alpha=False, bitdepth=2, palette=rgb_palette)
        w.write(f, pixel_data)
        f.close()

        return relative_path


    def convert_to_pixel_data(self, data, width, height, bpp):
        result = []
        for y in range(0, height):
            row = []
            for x in range(0, width):
                offset = self.coordinate_to_tile_offset(x, y, width, bpp)

                if offset < len(data):
                    # extract the color from the one or two bytes of tile data at the offset
                    shift = (7 - (x & 7))
                    mask = (1 << shift)
                    if bpp == 2:
                        color = ((data[offset] & mask) >> shift) + (((data[offset + 1] & mask) >> shift) << 1)
                    else:
                        color = ((data[offset] & mask) >> shift)
                else:
                    color = 0

                row.append(color)
            result.append(row)

        return result


    def coordinate_to_tile_offset(self, x, y, width, bpp):
        bytes_per_tile_row = bpp  # 8 pixels at 1 or 2 bits per pixel
        bytes_per_tile = bytes_per_tile_row * 8  # 8 rows per tile
        tiles_per_row = width // 8

        tile_y = y // 8
        tile_x = x // 8
        row_of_tile = y & 7

        return (tile_y * tiles_per_row * bytes_per_tile) + (tile_x * bytes_per_tile) + (row_of_tile * bytes_per_tile_row)


    def convert_palette_to_rgb(self, palette, bpp):
        col0 = 255 - (((palette & 0x03)     ) << 6)
        col1 = 255 - (((palette & 0x0C) >> 2) << 6)
        col2 = 255 - (((palette & 0x30) >> 4) << 6)
        col3 = 255 - (((palette & 0xC0) >> 6) << 6)
        if bpp == 2:
            return [
                (col0, col0, col0),
                (col1, col1, col1),
                (col2, col2, col2),
                (col3, col3, col3)
            ]
        else:
            return [
                (col0, col0, col0),
                (col3, col3, col3)
            ]


    def write_makefile(self):
        rom_extension = 'gb'
        if self.supports_gbc():
            rom_extension = 'gbc'

        path = os.path.join(self.output_directory, 'Makefile')
        f = open(path, 'w')

        if len(self.image_dependencies):
            f.write('IMAGE_DEPS = {}\n\n'.format(' '.join(self.image_dependencies)))

        f.write('all: game.{}\n\n'.format(rom_extension))

        f.write('%.2bpp: %.png\n')
        f.write('\trgbgfx --colors embedded -o $@ $<\n\n')

        f.write('%.1bpp: %.png\n')
        f.write('\trgbgfx -d 1 -o $@ $<\n\n')

        if len(self.image_dependencies):
            f.write('game.o: game.asm bank_*.asm $(IMAGE_DEPS)\n')
        else:
            f.write('game.o: game.asm bank_*.asm\n')

        f.write('\trgbasm -o game.o game.asm\n\n')

        f.write('game.{}: game.o\n'.format(rom_extension))
        if self.tiny:
            if self.last_byte in (0x00, 0xff):
                f.write('\trgblink --tiny -p {} -n game.sym -m game.map -o $@ $<\n'.format(self.last_byte))
            else:
                f.write('\trgblink --tiny -n game.sym -m game.map -o $@ $<\n')
        else:
            if self.last_byte in (0x00, 0xff):
                f.write('\trgblink -p {} -n game.sym -m game.map -o $@ $<\n'.format(self.last_byte))
            else:
                f.write('\trgblink -n game.sym -m game.map -o $@ $<\n')
        if self.last_byte == 0x00:
            f.write('\trgbfix -v -p {} $@\n\n'.format(self.last_byte))
        else:
            f.write('\trgbfix -v -p 255 $@\n\n')
        f.write('\t@if which md5sum &>/dev/null; then md5sum $@; else md5 $@; fi\n\n')

        f.write('clean:\n')
        f.write('\trm -f game.o game.{} game.sym game.map\n'.format(rom_extension))
        f.write('\tfind . \\( -iname \'*.1bpp\' -o -iname \'*.2bpp\' \\) -exec rm {} +')

        f.close()

class CharacterMap():
    def __init__(self, name, path):
        self.name = name        
        self.path = path
        self.character_map = {}
        self.max_length = 1
    def read_number(number_string):
        number_string = number_string.strip()
        if number_string.startswith("$"):
            return int(number_string[1:].replace("_", ""), 16)
        else:
            return int(number_string)
    def create_character_maps(file_path :str):
        lines = []
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        maps = []
        new_map = None
        for line in lines:
            line = line.strip()
            mapSearch = re.match(r"newcharmap", line, re.IGNORECASE)
            if mapSearch is not None:
                if new_map != None: 
                    maps.append(new_map)
                    if debug:
                        print("Loaded character map: "+new_map.name)
                        print("Mappings:")
                        print(new_map.character_map)
                new_map = CharacterMap(line[mapSearch.end():].strip(), file_path)                               
            else:
                mapSearch = re.search('[ \t]*charmap[ \t]*"((?:[^"]|\\")+)",[ \t]*(.+)', line, re.IGNORECASE)
                if(mapSearch == None): continue               
                mapping = mapSearch[1].rsplit('"', 1)[0]              
                ints = mapSearch[2].strip().split(",")
                if(len(ints) == 1):
                    key = CharacterMap.read_number(ints[0])
                else:
                    key = tuple(CharacterMap.read_number(i) for i in ints)
                    if len(key) > new_map.max_length:
                        new_map.max_length = len(key)
                new_map.character_map[key] = mapping
        maps.append(new_map)
        return maps

app_name = 'mgbdis v{version} - Game Boy ROM disassembler by {author}.'.format(version=__version__, author=__author__)
parser = argparse.ArgumentParser(description=app_name)
parser.add_argument('rom_path', help='Game Boy (Color) ROM file to disassemble')
parser.add_argument('--output-dir', default='disassembly', help='Directory to write the files into. Defaults to "disassembly"', action='store')
parser.add_argument('--character-map-path', help='ASM file containing character map(s) for use with data labeled .text:cm=<index>', action='store')
parser.add_argument('--uppercase-hex', help='Print hexadecimal numbers using uppercase characters', action='store_true')
parser.add_argument('--print-hex', help='Print the hexadecimal representation next to the opcodes', action='store_true')
parser.add_argument('--align-operands', help='Format the instruction operands to align them vertically', action='store_true')
parser.add_argument('--indent-spaces', help='Number of spaces to use to indent instructions', type=int, default=4)
parser.add_argument('--indent-tabs', help='Use tabs for indenting instructions', action='store_true')
parser.add_argument('--uppercase-db', help='Use uppercase for DB data declarations', action='store_true')
parser.add_argument('--hli', help='Mnemonic to use for \'ld [hl+], a\' type instructions.', type=str, default='hl+', choices=['hl+', 'hli', 'ldi'])
parser.add_argument('--ldh_a8', help='Mnemonic to use for \'ldh [ffa8], a\' type instructions.', type=str, default='ldh_ffa8', choices=['ldh_ffa8', 'ld_ff00_a8'])
parser.add_argument('--ld_c', help='Mnemonic to use for \'ldh [c], a\' type instructions.', type=str, default='ldh_c', choices=['ldh_c', 'ld_ff00_c'])
parser.add_argument('--overwrite', help='Allow generating a disassembly into an already existing directory', action='store_true')
parser.add_argument('--debug', help='Display debug output', action='store_true')
parser.add_argument('--tiny', help='Emulate RGBLINK `-t` option (non-banked / "32k" ROMs)', action='store_true')
args = parser.parse_args()

debug = args.debug

style = {
    'uppercase_hex': args.uppercase_hex,
    'print_hex': args.print_hex,
    'indentation': '\t' if args.indent_tabs else ' ' * args.indent_spaces,
    'operand_padding': 4 if args.align_operands else 0,
    'db': 'DB' if args.uppercase_db else 'db',
    'hli': args.hli,
    'ldh_a8': args.ldh_a8,
    'ld_c': args.ld_c,
}
instructions = apply_style_to_instructions(style, instructions)
charMap = []
if args.character_map_path is not None:
    charMap = CharacterMap.create_character_maps(args.character_map_path)
rom = ROM(args.rom_path, style, args.tiny, charMap)
rom.disassemble(args.output_dir)
