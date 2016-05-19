/* ARC disassembler helper.

   Copyright 2016 Free Software Foundation, Inc.
   Contributed by Synopsys Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#ifndef ARC_INSN_H
#define ARC_INSN_H

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


enum arc_condition_code_t
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

/* Container for information about instruction.  Provides a higher level access
   to data that is contained in struct arc_opcode of opcodes library.  Most of
   the static data about the instruction is available via structure fields,
   while most of the information about instruction operands is accessed via
   accessor functions - I consider it to be more consiece approach that having
   several arrays of operand data in arc_instruction: one array for operand
   regnums, another for operand immediate values.  In case of operand values
   and indirect jump targets actual value would depend on register value, so
   those values can be computed only on-demand with functions.  */

struct arc_instruction
{
  /* Address of this instruction.  */
  CORE_ADDR address;

  /* Pointer to arc_opcode struct from opcodes library.  */
  const struct arc_opcode *opcode_data;

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
  enum arc_condition_code_t condition_code;

  /* Load/store writaback mode.  */
  enum arc_ldst_writeback_mode writeback_mode;

  /* Load/store data size.  */
  enum arc_ldst_data_size data_size_mode;

  /* Copy of dis_insn_type from disassembler_info.  */
  enum dis_insn_type insn_type;
};

/* Fill INSN with data about instruction at specified ADDR.  */

void arc_insn_decode (struct gdbarch *gdbarch, CORE_ADDR addr,
		      struct arc_instruction *insn);

/* Dump INSN into gdb_stdlog.  */

void arc_insn_dump (const struct arc_instruction &insn);

/* Count amount of operands in INSN.  Note that amount of operands reported by
   opcodes disassembler can be different from the one encoded in the
   instruction.  Notable case is "ld a,[b,offset]", when offset == 0.  In this
   case opcodes disassembler presents this instruction as "ld a,[b]", hence
   there are *two* operands, not three.  This function returns the opcode
   value, hence it is up to invoker to handle the case described above based on
   instruction opcodes.  Another notable thing is that in opcodes
   representation square brackes (`[' and `]') are so called fake-operands -
   they are in the list of operands, but do not have any value of they own.
   This function doesn't count those "fake" operands.  */

unsigned int arc_insn_count_operands (const struct arc_instruction &insn);

/* Get address of next instruction after INSN, assuming linear execution (no
   taken branches).  If instruction has a delay slot, then returned value will
   point at the instruction in delay slot.  That is - "address of instruction +
   instruction length with LIMM".  */

CORE_ADDR arc_insn_get_linear_next_pc (const struct arc_instruction &insn);

/* Get branch/jump target address for the INSN.  Note that this function
   returns branch target and doesn't evaluate if this branch is taken or not.
   For the indirect jumps value depends in register state, hence can change.
   It is an error to call this function for a non-branch instruction.  */

CORE_ADDR arc_insn_get_branch_target (const struct arc_instruction &insn);

/* Returns register number of OPERAND_NUM in instruction INSN.  Returns -1 if
   operand is a short immediate value, not a register.  Returns 62 if operand
   is a long immediate value.  */

int arc_insn_get_operand_reg (const struct arc_instruction &insn,
			      unsigned int operand_num);

/* Returns an unsigned value of OPERAND_NUM in instruction INSN.
   For relative branch instructions returned value is an offset, not an actual
   branch target.  */

ULONGEST arc_insn_get_operand_value (const struct arc_instruction &insn,
				     unsigned int operand_num);

/* Like arc_insn_get_operand_value, but returns a signed value.  */

LONGEST arc_insn_get_operand_value_signed (const struct arc_instruction &insn,
					   unsigned int operand_num);

/* Returns TRUE if OPERAND_NUM in INSN is a register, FALSE if it is an
   immediate value.  */

int arc_insn_operand_is_reg (const struct arc_instruction &insn,
			     unsigned int operand_num);

/* Get register with base address of memory operation.  */

int arc_insn_get_memory_base_reg (const struct arc_instruction &insn);

/* Get offset of a memory operation INSN.  */

CORE_ADDR arc_insn_get_memory_offset (const struct arc_instruction &insn);


#define BITS(word,s,e)  (((word) << (sizeof (word) * 8 - 1 - e)) >>	\
			 (s + (sizeof (word) * 8 - 1 - e)))

/* Various functions that help with checking if given instruction has specified
   [sub]opcode or that it is a particular type of instruction.  */

static inline int
arc_insn_match_op (const struct arc_instruction &insn, unsigned int opcode)
{
  gdb_assert (opcode <= 0x1F);
  return (insn.opcode == opcode);
}

static inline int
arc_insn_match_subop1 (const struct arc_instruction &insn, unsigned int opcode,
		       unsigned int subopcode1)
{
  gdb_assert (opcode <= 0x1F);
  return (insn.opcode == opcode && insn.subopcode1 == subopcode1);
}

static inline int
arc_insn_match_subop2 (const struct arc_instruction &insn, unsigned int opcode,
		       unsigned int subopcode1, unsigned int subopcode2)
{
  gdb_assert (opcode <= 0x1F);
  return (insn.opcode == opcode
	  && insn.subopcode1 == subopcode1
	  && insn.subopcode2 == subopcode2);
}

static inline int
arc_insn_match_subop3 (const struct arc_instruction &insn, unsigned int opcode,
		       unsigned int subopcode1, unsigned int subopcode2,
		       unsigned int subopcode3)
{
  gdb_assert (opcode <= 0x1F);
  return (insn.opcode == opcode
	  && insn.subopcode1 == subopcode1
	  && insn.subopcode2 == subopcode2
	  && insn.subopcode3 == subopcode3);
}

/* Provide insn_match shortcuts for commonly checked instructions.  */

static inline int
arc_insn_is_enter_s (const struct arc_instruction &insn)
{
  return arc_insn_match_subop2 (insn, 0x18, 0x7, 0x0);
}

static inline int
arc_insn_is_leave_s (const struct arc_instruction &insn)
{
  return arc_insn_match_subop2 (insn, 0x18, 0x6, 0x0);
}

static inline int
arc_insn_is_mov (const struct arc_instruction &insn)
{
  /* mov b,c  */
  return (arc_insn_match_subop1 (insn, 0x04, 0xA)
	  /* mov_s g,h  */
	  || arc_insn_match_subop1 (insn, 0x08, 0x0)
	  /* mov_s h,s3  */
	  || arc_insn_match_subop1 (insn, 0x0E, 0x3)
	  /* mov_s.ne b,h  */
	  || arc_insn_match_subop1 (insn, 0x0E, 0x7)
	  /* mov_s b,u8  */
	  || arc_insn_match_op (insn, 0x1B));
}

static inline int
arc_insn_is_pop_s (const struct arc_instruction &insn)
{
  return (arc_insn_match_subop2 (insn, 0x18, 0x6, 0x1)
	  || arc_insn_match_subop2 (insn, 0x18, 0x6, 0x11));
}

static inline int
arc_insn_is_push_s (const struct arc_instruction &insn)
{
  return (arc_insn_match_subop2 (insn, 0x18, 0x7, 0x1)
	  || arc_insn_match_subop2 (insn, 0x18, 0x7, 0x11));
}

static inline int
arc_insn_is_st (const struct arc_instruction &insn)
{
  /* st c,[b,s9]  */
  return (arc_insn_match_op (insn, 0x03)
	  /* st_s r0,[gp,s11]  */
	  || arc_insn_match_subop1 (insn, 0x0A, 0x2)
	  /* st_s c,[b,u7]  */
	  || arc_insn_match_op (insn, 0x14)
	  /* stb_s c,[b,u7]  */
	  || arc_insn_match_op (insn, 0x15)
	  /* sth_s c,[b,u7]  */
	  || arc_insn_match_op (insn, 0x16)
	  /* st_s b,[sp,u7]  */
	  || arc_insn_match_subop1 (insn, 0x18, 0x2)
	  /* stb_s b,[sp,u7]  */
	  || arc_insn_match_subop1 (insn, 0x18, 0x3));
}

static inline int
arc_insn_is_sub (const struct arc_instruction &insn)
{
  /* sub a,b,c  */
  return (arc_insn_match_subop1 (insn, 0x4, 0x2)
	  /* sub_s c,b,u3  */
	  || arc_insn_match_subop1 (insn, 0x0D, 0x1)
	  /* sub_s b,b,c  */
	  || arc_insn_match_subop1 (insn, 0x0F, 0x2)
	  /* sub_s.ne b,b,b  */
	  || arc_insn_match_subop2 (insn, 0x0F, 0x0, 0x6)
	  /* sub_s b,b,u5  */
	  || arc_insn_match_subop1 (insn, 0x17, 0x3)
	  /* sub_s sp,sp,u7  */
	  || arc_insn_match_subop2 (insn, 0x18, 0x5, 0x1));
}

#endif /* ARC_INSN_H */
