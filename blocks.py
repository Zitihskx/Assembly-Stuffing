#!/usr/bin/env python3

'''Find the basic blocks of an ELF binary.'''

import sys
from typing import Optional, List, Set, Dict, Generator
from elftools.elf.elffile import ELFFile, ELFError          # type: ignore
from capstone import Cs, CsInsn, CS_ARCH_X86, CS_MODE_64    # type: ignore
from capstone.x86 import X86_OP_IMM, X86_OP_REG, X86_OP_MEM # type: ignore
from debug import debug, error, DEBUG


class RAD:
    '''Provide random-access disassembly of the .text section.

    To use this, make an instance.  You can test addresses with
    `is_in_range` and get a disassembly generator with `dis`.

    # Exceptions

    The following exceptions are known and should be expected.

      * FileNotFoundError
      * IsADirectoryError
      * PermissionError
      * ELFError
      * ValueError (if there is no .text section)
    '''

    @staticmethod
    def from_file(filename: str) -> "RAD":
        '''Create a RAD instance from a file.

        This returns a RAD instance or throws an exception if an error
        is encountered.
        '''
        file = open(filename, 'rb')
        elf = ELFFile(file)
        return RAD(elf)

    def __init__(self, elf: ELFFile):
        '''Initialize the instance with the given ELF file.

        If the given program has no .text section, then a `ValueError`
        is returned.
        '''
        self._text = elf.get_section_by_name('.text')
        if self._text is None:
            raise ValueError("There is no .text section")
        self._data = self._text.data()
        self._start = self._text.header.sh_addr
        self._end = self._start + len(self._data)
        self._cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self._cs.detail = True
        self._entry = elf.header.e_entry
        self._elf = elf
        self._cache: Dict[int, CsInsn] = {}
        self._populate_cache(self._start)
        debug(f"Entry point: 0x{self._entry:x}")
        debug(f"Text section is: [0x{self._start:x}, 0x{self._end})")

    def _populate_cache(self, addr: int) -> None:
        '''Populate the cache starting from the given address.'''
        debug(f'Populating cache')
        limit = 100
        for inst in self._cs.disasm(self._data[addr - self._start:], addr):
            if inst.address in self._cache or limit <= 0:
                break
            self._cache[inst.address] = inst
            limit -= 1

    def get_entry(self) -> int:
        '''Get the entry point.'''
        return self._entry

    def is_in_range(self, addr: int) -> bool:
        '''Determine if an address is in the .text section.

        Returns True iff the address is within the .text section.
        '''
        return self._start <= addr < self._end

    def dis(self, addr: int) -> Generator[CsInsn, None, None]:
        '''Get an instruction generator starting at the given address.

        If the given address is not in the .text section, a `ValueError` is
        thrown.
        '''
        if not self.is_in_range(addr):
            raise ValueError(f"The address 0x{addr:x} is out of range")
        while True:
            if addr in self._cache:
                inst = self._cache[addr]
                addr += len(inst.bytes)
                yield inst
            elif not self.is_in_range(addr):
                break
            else:
                self._populate_cache(addr)
                if addr not in self._cache:
                    error(f"Internal: Cache error at 0x{addr:x}")
                    break


def get_basic_block(rad: RAD, start_of_block: int, leaders: Set[int]) -> Optional[List[CsInsn]]:
    '''Extract a basic block.

    Given a RAD, the address of the start of the block, and a list of block leaders,
    extract and return the array of instructions making up the basic block.

    A ValueError is possible if the address is not in the file's .text section.
    '''
    dis = rad.dis(start_of_block)

    # Accumulate instructions until we find the end of the basic block.
    block = []
    for inst in dis:
        block.append(inst)
        rip = inst.address + len(inst.bytes)
        if rip in leaders:
            break
        mne = inst.mnemonic.split()[-1]
        if mne.startswith('j') or mne in ['jmp', 'ret', 'reti', 'hlt', 'loop']:
            # Found end of basic block.
            break

    return block


def find_main(rad: RAD) -> Optional[int]:
    '''Given a RAD instance, locate the main function if possible.

    This routine uses a simple heuristic of looking at the first basic block
    at the entry point and verifying that it ends with call followed by hlt.
    If so, it then tries to determine the value assigned to rdi and returns
    that value as the address of main.

    There are three possible return values.  If main is found, then the address
    is returned.  If it cannot be found, but no errors occur, then 0 is returned.
    If an error occurs it is reported to the user and None is returned.
    '''
    # Get the entry point, the text section (if any) and the
    # address of the text section.
    entry = rad.get_entry()

    # Get the basic block at the entry point.
    block = get_basic_block(rad, entry, set())
    if block is None:
        return None

    # Print out the basic block.
    if 'debug' in DEBUG:
        for inst in block:
            debug(f"0x{inst.address:x}:  {inst.mnemonic} {inst.op_str}")

    # See if the block ends with call hlt.
    if (len(block) < 3 or
            block.pop().mnemonic.split()[-1] != 'hlt' or
            block.pop().mnemonic.split()[-1] != 'call'):
        debug("Block does not match required pattern.")
        # This is not an error, but main cannot be found.  The program might
        # not use the C runtime and might not have a main.
        return 0

    # Now walk backward through the rest of the block and watch for
    # either an lea or a mov that sets rdi.  The first one we find
    # should be the address of main.
    main_addr = 0
    debug("Searching backward for rdi setting.")
    for inst in reversed(block):
        debug(f"0x{inst.address:x}:  {inst.mnemonic} {inst.op_str}")
        mne = inst.mnemonic.split()[-1]
        if mne == 'mov':
            debug("Is a mov")
            destination = inst.operands[0]
            source = inst.operands[1]
            if source.type != X86_OP_IMM or destination.type != X86_OP_REG:
                debug("Wrong operand types")
                continue
            if inst.reg_name(destination.value.reg) != 'rdi':
                debug("Wrong register")
                continue
            main_addr = source.value.imm
            break
        if mne == 'lea':
            debug("Is a lea")
            destination = inst.operands[0]
            source = inst.operands[1]
            if source.type != X86_OP_MEM or destination.type != X86_OP_REG:
                debug("Wrong operand types")
                continue
            if inst.reg_name(source.value.mem.base) != 'rip':
                debug("Not rip-relative")
                continue
            if inst.reg_name(destination.value.reg) != 'rdi':
                debug("Wrong register")
                continue
            rip = inst.address + len(inst.bytes)
            disp = source.value.mem.disp
            debug(f"address = rip (0x{rip:x}) + displacement (0x{disp:x})")
            main_addr = rip + disp
            break

    return main_addr


def pass_one(rad: RAD, leaders: Set[int]) -> Optional[Set[int]]:
    '''Find basic block leaders.

    Locate basic block leaders and return the set of all leaders found.
    An initial set of leaders is provided, which must not be empty.
    If an error is detected then it is reported, and None is returned.
    '''
    if len(leaders) == 0:
        error("Internal: Initial leader set is empty.")
        return None
    stack = list(leaders)

    def push(leader: int) -> None:
        '''Add a potential leader, with checking.'''
        if rad.is_in_range(leader) and leader not in leaders:
            debug(f'Adding leader: 0x{leader:x}')
            stack.append(leader)
            leaders.add(leader)

    while len(stack) > 0:
        # Get the next basic block leader from the stack.
        leader = stack.pop()
        dis = rad.dis(leader)
        debug(f'Stack depth is: {len(stack)}')
        for inst in dis:
            # If this address is already scheduled to be explored, do that now.  This
            # avoids creating a new disassembly generator.
            if inst.address in stack:
                stack.remove(inst.address)
            
            # Look for new block leaders.
            debug(f'0x{inst.address}: {inst.mnemonic} {inst.op_str}')
            mne = inst.mnemonic.split()[-1]
            rip = inst.address + len(inst.bytes)
            if mne in ['call', 'jmp']:
                target = inst.operands[0]
                if target.type == X86_OP_IMM:
                    debug(f'Potential leader: {mne} 0x{target.value.imm:x}')
                    push(target.value.imm)
                # We are not going to try to puzzle out any other form.
                if mne == 'jmp':
                    # Terminate the search.
                    break
            elif mne == 'loop' or mne.startswith('j'):
                target = inst.operands[0]
                if target.type == X86_OP_IMM:
                    debug(f'Potential leader: {mne} 0x{target.value.imm:x}')
                    push(target.value.imm)
                    debug(f'Potential leader: (fall through) 0x{rip:x}')
                    push(rip)
                # Terminate the search.
                break
            elif mne in ['ret', 'reti', 'hlt']:
                # Terminate the search.
                break
    return leaders


def pass_two(rad: RAD, leaders: Set[int]) -> None:
    '''Extract basic blocks and print them.

    Given a RAD and a set of basic block leaders, print the basic
    blocks in order by increasing address with a blank line between
    each one.
    '''
    leads = list(leaders)
    leads.sort()
    for leader in leads:
        block = get_basic_block(rad, leader, leaders)
        if block is None:
            error("Internal: Unable to extract a block at 0x{leader:x}")
            continue
        for inst in block:
            print(f'0x{inst.address}: {inst.mnemonic} {inst.op_str}')
        print()


def main() -> int:
    # pylint: disable=too-many-return-statements
    '''Find the main function of a compiled program, if we can.

    This function returns zero if an error was encountered, and
    returns zero otherwise.
    '''
    if len(sys.argv) != 2:
        error("Expect exactly one command line argument.")
        return 1
    debug(f"The argument is {sys.argv[1]}")

    # Open the file.
    try:
        rad = RAD.from_file(sys.argv[1])
    except FileNotFoundError as err:
        error(f"{err}")
        return 1
    except IsADirectoryError as err:
        error(f"{err}")
        return 1
    except ELFError as err:
        error(f"{err}")
        return 1
    except PermissionError as err:
        error(f"{err}")
        return 1
    except ValueError as err:
        error(f"{err}")
        return 1
    debug("File opened.")

    # If we can find main, start the analysis from there.  If we cannot,
    # start from the entry point.
    start_addr = find_main(rad)
    if start_addr is None:
        return 1
    if start_addr == 0:
        start_addr = rad.get_entry()
    debug(f'Starting analysis at address 0x{start_addr:x}')

    # Run pass one to find basic block leaders.  An initial set of leaders
    # is provided.
    leaders = pass_one(rad, set([start_addr]))
    if leaders is None:
        return 1
    debug(f"Found {len(leaders)} blocks")

    # Run pass two to extract the basic block for each leader.
    pass_two(rad, leaders)

    # Done.
    return 0

if __name__ == '__main__':
    main()
