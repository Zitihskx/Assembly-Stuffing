
#! /usr/bin/env python3
#Program to disassemble text section of given binary

import sys
from typing import TextIO
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

def main() -> int:
    if len(sys.argv) != 2:                                          #Confirming if single filename argument is supplied
        print('ERROR: Specify exactly one filename argument.')
        return 1
    name: str=sys.argv[1]                                           #Accessing filename
    steam: TextIO
    try:                                                            #Exception handling for opening file
        file_open = open(name, 'rb')
        try:                                                          
            file_elf = ELFFile(file_open)                           # Creating elffile object
            text = file_elf.get_section_by_name('.text')            # Taking .text section of binary
            tstart = text.header.sh_addr                            # Starting address of text section
            #entry_point = file_elf.header.e_entry
            data = text.data()
            cap=Cs(CS_ARCH_X86, CS_MODE_64)
            cap.detail=True
            temp_inst=None
            found_main=False
            disa=cap.disasm(data, tstart)
            for i in disa: # Printing disassemble text section
                if (i.mnemonic=='call' and next(disa).mnemonic=='hlt'):
                    #print(f'0x{temp_inst.address:016x}: {temp_inst.mnemonic}: {temp_inst.op_str}')
                    last_operand=temp_inst.operands[-1]
                    if last_operand.type == X86_OP_IMM:
                        op_address=last_operand.value.imm
                    elif last_operand.type==X86_OP_REG:
                        op_address=i.reg_name(last_operand.value.reg)
                    elif last_operand.type==X86_OP_MEM:
                        op_address=last_operand.value.mem.disp
                    #print(type(op_address))
                    rip=hex(i.address)
                    addr_main = hex(int(rip,16) + int(op_address))
                    print(addr_main)
                    found_main=True
                    #print(f'0x{i.address:016x}: {i.mnemonic} {i.op_str}')
                    #print(f'0x{next(disa).address:016x}: {next(disa).mnemonic}: {next(disa).op_str}')
                temp_inst=i
            if (found_main == False):
                print("Can not locate main")

        except ELFError as err:                                     # Catching error while creating elffile object
            print(f'Unable to open ELF file:{err}')
            return 1
        
    except PermissionError as err:                                  # Catching file permission error
        print(f'Bad Permission: {err}')     
    except FileNotFoundError:                                # Catching file not found error
        print('File not found')
    except IsADirectoryError:                                # Catching if argument is a directory
        print('Is a directory')
    else:
        file_open.close()                                           # Closing the file
    return 0

if __name__=='__main__':
    main()
