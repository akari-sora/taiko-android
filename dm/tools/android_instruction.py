"""Detached A64 decoder facts for the importer's large retained collections.

Capstone5's CsInsn retains a 1864-byte architecture union for each instruction.
The ARM64 operand structures are copied in full, while the owning instruction
and its raw/detail allocation can be released. Decoding remains Capstone's job.
"""
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM, copy_ctypes

_NAMES=Cs(CS_ARCH_ARM64,CS_MODE_ARM)


class Instruction:
    __slots__=('id','address','size','bytes','mnemonic','op_str','writeback',
               'cc','update_flags','post_index','operands','groups','_registers')

    def __init__(self,decoded):
        self.id=decoded.id
        self.address=decoded.address
        self.size=decoded.size
        self.bytes=bytes(decoded.bytes)
        self.mnemonic=decoded.mnemonic
        self.op_str=decoded.op_str
        self.writeback=decoded.writeback
        self.cc=decoded.cc
        self.update_flags=decoded.update_flags
        self.post_index=decoded.post_index
        # Installed binding's copy_ctypes allocates a new standalone struct;
        # nested mem/shift views can only retain that operand, never CsInsn.
        self.operands=tuple(copy_ctypes(op) for op in decoded.operands)
        self.groups=tuple(decoded.groups)
        self._registers=tuple(tuple(registers) for registers in decoded.regs_access())

    def group(self,group):
        return group in self.groups

    def regs_access(self):
        return self._registers

    def reg_name(self,register):
        return _NAMES.reg_name(register)
