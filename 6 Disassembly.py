
#! /usr/bin/env python3
#Program to disassemble text section of given binary

import sys
from typing import TextIO
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

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
            entry_point = file_elf.header.e_entry
            data = text.data()
            dis=Cs(CS_ARCH_X86, CS_MODE_64)                 
            for i in dis.disasm(data, tstart):                      # Printing disassemble text section
                print(f'0x{i.address:016x}: {i.mnemonic} {i.op_str}')

        except ELFError as err:                                     # Catching error while creating elffile object
            print(f'ELFError: {err}')
            return 1
        
    except PermissionError as err:                                  # Catching file permission error
        print(f'Bad Permission: {err}')     
    except FileNotFoundError as err:                                # Catching file not found error
        print(f'No such file: {name}')
    except IsADirectoryError as err:                                # Catching if argument is a directory
        print(f'{name} is a directory')
    except:
        print('A bad thing happened.')
    else:
        file_open.close()                                           # Closing the file
    finally:
        print('Done')
    return 0

if __name__=='__main__':
    main()
