/* Disassembler structures definitions for the ARC.
   Copyright (C) 1994-2016 Free Software Foundation, Inc.

   Contributed by Claudiu Zissulescu (claziss@synopsys.com)

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef ARCDIS_H
#define ARCDIS_H

#ifdef __cplusplus
extern "C" {
#endif

  enum arc_ldst_writeback_mode
    {
      ARC_WRITEBACK_NO = 0,
      ARC_WRITEBACK_AW = 1,
      ARC_WRITEBACK_A = ARC_WRITEBACK_AW,
      ARC_WRITEBACK_AB = 2,
      ARC_WRITEBACK_AS = 3,
    };


  enum arc_ldst_data_size
    {
      ARC_SCALING_NONE = 0,
      ARC_SCALING_B = 1,
      ARC_SCALING_H = 2,
      ARC_SCALING_D = 3,
    };


  enum arc_condition_code
    {
      ARC_CC_AL = 0x0,
      ARC_CC_RA = ARC_CC_AL,
      ARC_CC_EQ = 0x1,
      ARC_CC_Z = ARC_CC_EQ,
      ARC_CC_NE = 0x2,
      ARC_CC_NZ = ARC_CC_NE,
      ARC_CC_PL = 0x3,
      ARC_CC_P = ARC_CC_PL,
      ARC_CC_MI = 0x4,
      ARC_CC_N = ARC_CC_MI,
      ARC_CC_CS = 0x5,
      ARC_CC_C = ARC_CC_CS,
      ARC_CC_LO = ARC_CC_CS,
      ARC_CC_CC = 0x6,
      ARC_CC_NC = ARC_CC_CC,
      ARC_CC_HS = ARC_CC_CC,
      ARC_CC_VS = 0x7,
      ARC_CC_V = ARC_CC_VS,
      ARC_CC_VC = 0x8,
      ARC_CC_NV = ARC_CC_VC,
      ARC_CC_GT = 0x9,
      ARC_CC_GE = 0xA,
      ARC_CC_LT = 0xB,
      ARC_CC_LE = 0xC,
      ARC_CC_HI = 0xD,
      ARC_CC_LS = 0xE,
      ARC_CC_PNZ = 0xF,
    };

  enum arc_operand_kind
    {
      ARC_OPERAND_KIND_UNKNOWN = 0,
      ARC_OPERAND_KIND_REG,
      ARC_OPERAND_KIND_SHIMM,
      ARC_OPERAND_KIND_LIMM
    };

  struct arc_insn_operand
  {
    /* Operand value as encoded in instruction.  */
    unsigned long value;

    enum arc_operand_kind kind;
  };

  /* Only LEAVE_S can have this amount of operands.  Other
     instructions have 3 operands at most.  */
#define ARC_MAX_OPERAND_COUNT (4)

  /* Container for information about instruction.  Provides a higher
     level access to data that is contained in struct arc_opcode.  */

  struct arc_instruction
  {
    /* Address of this instruction.  */
    bfd_vma address;

    /* Whether this is a valid instruction.  */
    bfd_boolean valid;

    insn_class_t insn_class;

    /* Length (without LIMM).  */
    unsigned int length;

    /* Instruction word as it is, in the host endianness.  */
    unsigned long raw_word;

    /* Is there a LIMM in this instruction?  */
    int limm_p;

    /* Long immediate value.  */
    unsigned long limm_value;

    /* Some ARC instructions have subopcodes nested up to 3 layers.  */
    unsigned int opcode;
    unsigned int subopcode1;
    unsigned int subopcode2;
    unsigned int subopcode3;

    /* Is it a branch/jump instruction?  */
    int is_control_flow;

    /* Whether this instruction has a delay slot.  */
    int has_delay_slot;

    /* Value of condition code field.  */
    enum arc_condition_code condition_code;

    /* Load/store writeback mode.  */
    enum arc_ldst_writeback_mode writeback_mode;

    /* Load/store data size.  */
    enum arc_ldst_data_size data_size_mode;

    /* Amount of operands in instruction.  Note that amount of
       operands reported by opcodes disassembler can be different from
       the one encoded in the instruction.  Notable case is "ld
       a,[b,offset]", when offset == 0.  In this case opcodes
       disassembler presents this instruction as "ld a,[b]", hence
       there are *two* operands, not three.  OPERANDS_COUNT and
       OPERANDS contain only those explicit operands, hence it is up
       to invoker to handle the case described above based on
       instruction opcodes.  Another notable thing is that in opcodes
       disassembler representation square brackets (`[' and `]') are
       so called fake-operands - they are in the list of operands, but
       do not have any value of they own.  Those "operands" are not
       present in this array.  */
    struct arc_insn_operand operands[ARC_MAX_OPERAND_COUNT];

    unsigned int operands_count;
  };

  /* Fill INSN with data about instruction at specified ADDR.  */

  void arc_insn_decode (bfd_vma addr,
			struct disassemble_info *di,
			disassembler_ftype func,
			struct arc_instruction *insn);

  /* Get address of next instruction after INSN, assuming linear
     execution (no taken branches).  If instruction has a delay slot,
     then returned value will point at the instruction in delay slot.
     That is - "address of instruction + instruction length with
     LIMM".  */

  static inline bfd_vma
  arc_insn_get_linear_next_pc (const struct arc_instruction *insn)
  {
    /* In ARC long immediate is always 4 bytes.  */
    return (insn->address + insn->length + (insn->limm_p ? 4 : 0));
  }

  /* Get register with base address of memory operation.  */

  int arc_insn_get_memory_base_reg (const struct arc_instruction *insn);

  /* Get offset of a memory operation INSN.  */

  bfd_vma arc_insn_get_memory_offset (const struct arc_instruction *insn);


  /* Provide insn_match shortcuts for commonly checked instructions.
     There is an alternative: use opcode_data->name to check for
     instruction, but using opcodes looks preferably because it is
     possible that a new encoding can be added for an existing
     instruction, so it will pass the "name" test, however it might,
     for example, has a different set of operands, which will break
     assumptions in current code about the operands.  If instructions
     are detected by their opcodes, then it will be required to update
     those matching instructions and all functions that use them.  */

  static inline bfd_boolean
  arc_insn_is_enter_s (const struct arc_instruction *insn)
  {
    return (insn->kind == ENTER_INSN);
  }

  static inline bfd_boolean
  arc_insn_is_leave_s (const struct arc_instruction *insn)
  {
    return (insn->kind == LEAVE_INSN);
  }

  static inline bfd_boolean
  arc_insn_is_mov (const struct arc_instruction *insn)
  {
    return (insn->kind == MOVE_INSN);
  }

  static inline bfd_boolean
  arc_insn_is_pop_s (const struct arc_instruction *insn)
  {
    return (insn->kind == POP_INSN);
  }

  static inline bfd_boolean
  arc_insn_is_push_s (const struct arc_instruction *insn)
  {
    return (insn->kind == PUSH_INSN);
  }

  static inline bfd_boolean
  arc_insn_is_st (const struct arc_instruction *insn)
  {
    return (insn->kind == STORE_INSN);
  }

  static inline bfd_boolean
  arc_insn_is_sub (const struct arc_instruction *insn)
  {
    return (insn->kind == SUB_INSN);
  }

#ifdef __cplusplus
}
#endif

#endif
