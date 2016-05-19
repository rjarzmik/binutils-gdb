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

/* GDB header files.  */
#include "defs.h"
#include "disasm.h"

/* ARC header files.  */
#include "opcode/arc.h"
#include "arc-tdep.h"
#include "arch/arc-insn.h"

/* Convert litte endian to ARC middle endian.  */

static unsigned long
arc_getm32 (unsigned long data)
{
  unsigned long value = ((data & 0xff00) | (data & 0xff)) << 16;
  value |= ((data & 0xff0000) | (data & 0xff000000)) >> 16;
  return value;
}

/* Extract bits starting with S to E (inclusive) from the instruction WORD.  */

#define BITS(word,s,e)  (((word) << (sizeof (word) * 8 - 1 - e)) >>	\
			 (s + (sizeof (word) * 8 - 1 - e)))

/* Extract operand from instruction word.  OP must have fields `bits` and
   `shift`.  Would extract BITS amount of bits starting with SHIFT.  Used to
   extract operands and flags from arc_opcode.  */

#define EXTRACT_OPERAND(word,op) \
  (((word) >> (op)->shift) & ((1 << (op)->bits) - 1))

/* Identify instruction subopcodes.  In ARC ISA opcodes are always 5 most
   significant bits: 27-31 for 32-bit instructions, 11-15 for 16-bit
   instructions.  Subopcodes, however are not very unified - there lots of
   various formats; depending on opcode, subopcode may appear at different
   locations in instruction or may not be present at all.  On top of that many
   subopcodes have subopcodes of their own.  Subopcode hierarhy is not always
   symmetric, for example for [opcode=0x01 subopcode1=0x0] there is also
   subopcode2, but for [opcode=0x01 subopcode1=0x1] there is subopcode2 and
   subopcode3.  Perhaps, the most complex example are 16-bite stack based
   operations with opcode 0x18.  Bits 5-7 contain subopcode1.  Subopcodes 0x0,
   0x1, 0x2, 0x3 and 0x4 don't have any further subopcodes.  Subopcode1=0x5 has
   an additional subopcode2 at the bit 8 (bits 9 and 10 are always zero).  And
   subopcodes1 0x6 and 0x7 contain their subopcode2 at the bit 0.  And if and
   only if subopcode2 is 0x1, then bits 1-4 are also a subopcode3.  */

static void
set_insn_subopcodes (struct arc_instruction *insn)
{
  /* Find subopcode.  */
  switch (insn->opcode)
    {
    case 0x00:
      insn->subopcode1 = BITS (insn->raw_word, 16, 16);
      break;
    case 0x01:
      insn->subopcode1 = BITS (insn->raw_word, 16, 16);
      if (insn->subopcode1 == 0x1)
	{
	  insn->subopcode2 = BITS (insn->raw_word, 4, 4);
	  insn->subopcode3 = BITS (insn->raw_word, 0, 3);
	}
      else
	{
	  insn->subopcode2 = BITS (insn->raw_word, 17, 17);
	}
      break;
    /* No subopcodes for 0x02 - 0x03.  */
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07:
      insn->subopcode1 = BITS (insn->raw_word, 16, 21);
      if (insn->subopcode1 == 0x2F)
	{
	  insn->subopcode2 = BITS (insn->raw_word, 0, 5);
	  if (insn->subopcode2 == 0x3F)
	    insn->subopcode3 = BITS (insn->raw_word, 12, 14) << 3
	      | BITS (insn->raw_word, 24, 26);
	}
      break;
    case 0x08:
      insn->subopcode1 = BITS (insn->raw_word, 2, 2);
      break;
    case 0x09:
    case 0x0A:
      insn->subopcode1 = BITS (insn->raw_word, 3, 3);
      if (insn->subopcode1 == 0x0)
	insn->subopcode1 = BITS (insn->raw_word, 3, 4);
      break;
    case 0x0B:
      insn->subopcode1 = BITS (insn->raw_word, 10, 10);
      break;
    case 0x0C:
    case 0x0D:
      insn->subopcode1 = BITS (insn->raw_word, 3, 4);
      break;
    case 0x0E:
      insn->subopcode1 = BITS (insn->raw_word, 2, 4);
      break;
    case 0x0F:
      insn->subopcode1 = BITS (insn->raw_word, 0, 4);
      if (insn->subopcode1 == 0x0)
	{
	  insn->subopcode2 = BITS (insn->raw_word, 5, 7);
	  if (insn->subopcode2 == 0x7)
	    {
	      insn->subopcode3 = BITS (insn->raw_word, 8, 10);
	      if (insn->subopcode3 == 0x4)
		insn->condition_code = ARC_CC_EQ;
	      else if (insn->subopcode3 == 0x5)
		insn->condition_code = ARC_CC_NE;
	    }
	}
      break;
    /* No subopcodes for 0x10 - 0x16.  */
    case 0x17:
    case 0x18:
      insn->subopcode1 = BITS (insn->raw_word, 5, 7);
      /* PRM doesn't put this clearly, but 0x18 has subopcode2.  */
      switch (insn->subopcode1)
	{
	case 0x5:
	  /* ADD_S SP,SP,u7 and SUB_S SP,SP,u7.  */
	  insn->subopcode2 = BITS (insn->raw_word, 8, 8);
	  break;
	case 0x6:
	case 0x7:
	  /* PUSH_S, POP_S, LEAVE_S, ENTER_S.  */
	  insn->subopcode2 = BITS (insn->raw_word, 0, 0);
	  /* If bit 0 is 0, then it is LEAVE_S, ENTER_S.  Otherwise subopcode
	     should be expanded further.  */
	  if (insn->subopcode2 != 0x0)
	    insn->subopcode2 = BITS (insn->raw_word, 0, 4);
	  break;
	}
      break;
    case 0x19:
      insn->subopcode1 = BITS (insn->raw_word, 9, 10);
      break;
    /* No subopcodes for 0x1A - 0x1B.  */
    case 0x1C:
      insn->subopcode1 = BITS (insn->raw_word, 7, 7);
      break;
    case 0x1D:
      insn->subopcode1 = BITS (insn->raw_word, 7, 7);
      insn->condition_code = (insn->subopcode1 == 0x0 ? ARC_CC_EQ : ARC_CC_NE);
      break;
    case 0x1E:
      /* B_S, BEQ_S, BNE_S, Bcc_S.  */
      insn->subopcode1 = BITS (insn->raw_word, 9, 10);
      switch (insn->subopcode1)
	{
	case 0x1:
	  insn->condition_code = ARC_CC_EQ;
	  break;
	case 0x2:
	  insn->condition_code = ARC_CC_NE;
	  break;
	case 0x3:
	  /* Bcc_S  */
	  insn->subopcode2 = BITS (insn->raw_word, 6, 8);
	  /* In this case subopcode2 is the condition code.  */
	  switch (insn->subopcode2)
	    {
	    case 0x0:
	      insn->condition_code = ARC_CC_GT;
	      break;
	    case 0x1:
	      insn->condition_code = ARC_CC_GE;
	      break;
	    case 0x2:
	      insn->condition_code = ARC_CC_LT;
	      break;
	    case 0x3:
	      insn->condition_code = ARC_CC_LE;
	      break;
	    case 0x4:
	      insn->condition_code = ARC_CC_HI;
	      break;
	    case 0x5:
	      insn->condition_code = ARC_CC_HS;
	      break;
	    case 0x6:
	      insn->condition_code = ARC_CC_LO;
	      break;
	    case 0x7:
	      insn->condition_code = ARC_CC_LS;
	      break;
	    }
	  break;
	}
      break;
    /* No subopcodes for 0x1F.  */
    }
}

/* Parse various instruction flags that are not part of the opcode/subopcode.
   This is mainly memory ops parameters - data size and register writeback.
   Another instruction flag is a condition code.  Note, however, that in case
   of BRcc instructions disassembler doesn't set respective flags, so instead
   insn->condition_code is set based on subopcode and that is done in
   set_insn_subopcodes.  */

static void
set_insn_flags (struct arc_instruction *insn)
{
  for (const unsigned char *flag_index = insn->opcode_data->flags;
       *flag_index; flag_index++)
    {
      const struct arc_flag_class *flag_class
	= &arc_flag_classes[*flag_index];

      for (const unsigned int *flag_operand_index = flag_class->flags;
	   *flag_operand_index; flag_operand_index++)
	{
	  const struct arc_flag_operand *flag_operand
	    = &arc_flag_operands[*flag_operand_index];

	  if (!flag_operand->favail)
	    continue;

	  unsigned int value = EXTRACT_OPERAND (insn->raw_word, flag_operand);
	  if (flag_operand->code == value)
	    {
	      switch (flag_operand->name[0])
		{
		case 'a':
		  /* Address writeback mode.  */
		  insn->writeback_mode = (enum arc_ldst_writeback_mode) value;
		  break;
		case 'b':
		case 'h':
		case 'w':
		  /* Data size mode.  */
		  insn->data_size_mode = (enum arc_ldst_data_size) value;
		  break;
		}

	      /* Condition codes, which are mostly several characters.  */
	      if (0 == strcmp (flag_operand->name, "eq")
		  || 0 == strcmp (flag_operand->name, "z"))
		insn->condition_code = ARC_CC_EQ;
	      else if (0 == strcmp (flag_operand->name, "ne")
		       || 0 == strcmp (flag_operand->name, "nz"))
		insn->condition_code = ARC_CC_NE;
	      else if (0 == strcmp (flag_operand->name, "p")
		       || 0 == strcmp (flag_operand->name, "pl"))
		insn->condition_code = ARC_CC_PL;
	      else if (0 == strcmp (flag_operand->name, "n")
		       || 0 == strcmp (flag_operand->name, "mi"))
		insn->condition_code = ARC_CC_MI;
	      else if (0 == strcmp (flag_operand->name, "c")
		       || 0 == strcmp (flag_operand->name, "cs")
		       || 0 == strcmp (flag_operand->name, "lo"))
		insn->condition_code = ARC_CC_CS;
	      else if (0 == strcmp (flag_operand->name, "cc")
		       || 0 == strcmp (flag_operand->name, "nc")
		       || 0 == strcmp (flag_operand->name, "hs"))
		insn->condition_code = ARC_CC_CC;
	      else if (0 == strcmp (flag_operand->name, "vs")
		       || 0 == strcmp (flag_operand->name, "v"))
		insn->condition_code = ARC_CC_VS;
	      else if (0 == strcmp (flag_operand->name, "nv")
		       || 0 == strcmp (flag_operand->name, "vc"))
		insn->condition_code = ARC_CC_NV;
	      else if (0 == strcmp (flag_operand->name, "gt"))
		insn->condition_code = ARC_CC_GT;
	      else if (0 == strcmp (flag_operand->name, "ge"))
		insn->condition_code = ARC_CC_GE;
	      else if (0 == strcmp (flag_operand->name, "lt"))
		insn->condition_code = ARC_CC_LT;
	      else if (0 == strcmp (flag_operand->name, "le"))
		insn->condition_code = ARC_CC_LE;
	      else if (0 == strcmp (flag_operand->name, "hi"))
		insn->condition_code = ARC_CC_HI;
	      else if (0 == strcmp (flag_operand->name, "ls"))
		insn->condition_code = ARC_CC_LS;
	      else if (0 == strcmp (flag_operand->name, "pnz"))
		insn->condition_code = ARC_CC_PNZ;
	    }
	}
    }

  /* Disassembler doesn't set data size flags for some instructions - instead
     each "data size" variation is a separate instruction.  */
  if (arc_insn_match_op (*insn, 0x03))
    insn->data_size_mode
      = (enum arc_ldst_data_size) BITS (insn->raw_word, 1, 2);
  else if (arc_insn_match_op (*insn, 0x15))
    insn->data_size_mode = ARC_SCALING_B;
  else if (arc_insn_match_op (*insn, 0x16))
    insn->data_size_mode = ARC_SCALING_H;
  else if (arc_insn_match_subop1 (*insn, 0x18, 3))
    insn->data_size_mode = ARC_SCALING_B;

  /* Opcodes disassembler doesn't set writeback flags for POP_S and PUSH_S.  */
  if (arc_insn_is_push_s (*insn))
    insn->writeback_mode = ARC_WRITEBACK_AW;
  else if (arc_insn_is_pop_s (*insn))
    insn->writeback_mode = ARC_WRITEBACK_AB;
}

/* Helper function to invoke make_final_cleanup.  Copy of
   disasm.c:do_ui_file_delete.  */

static void
arc_do_ui_file_delete (void *arg)
{
  ui_file_delete ((struct ui_file *) arg);
}

/* Wrapper for gdb_disassemble_info that handles the ui_stream.  */

static struct disassemble_info
arc_disassemble_info (struct gdbarch *gdbarch)
{
  static struct ui_file *null_stream = NULL;

  /* Dummy stream for disassembler (see disasm.c:gdb_insn_length).  */
  if (null_stream == NULL)
    {
      null_stream = ui_file_new ();
      make_final_cleanup (arc_do_ui_file_delete, null_stream);
    }

  return gdb_disassemble_info (gdbarch, null_stream);
}

/* Read instruction as-is from memory.  This reads only instruction, without
   LIMM.  Returned value will be in converted encoding.  */

static unsigned long
read_instruction (struct disassemble_info *di, CORE_ADDR addr,
		  unsigned int length)
{
  unsigned long word;
  bfd_byte buffer[4];
  di->read_memory_func (addr, buffer, 4, di);

  if (length == 2)
    {
      unsigned int lowbyte = (di->endian == BFD_ENDIAN_LITTLE) ? 1 : 0;
      unsigned int highbyte = (di->endian == BFD_ENDIAN_LITTLE) ? 0 : 1;
      return (buffer[lowbyte] << 8) | buffer[highbyte];
    }

  return (di->endian == BFD_ENDIAN_LITTLE
	  ? arc_getm32 (bfd_getl32 (buffer))
	  : bfd_getb32 (buffer));
}

void
arc_insn_decode (struct gdbarch *gdbarch, CORE_ADDR addr,
		 struct arc_instruction *insn)
{
  /* Ensure that insn would be in the reset state.  */
  memset (insn, 0, sizeof (struct arc_instruction));

  struct disassemble_info di = arc_disassemble_info (gdbarch);
  unsigned int length_with_limm = arc_delayed_print_insn (addr, &di);
  if (length_with_limm == 2 || length_with_limm == 6)
    insn->length = 2;
  else
    insn->length = 4;

  insn->address = addr;
  insn->insn_type = di.insn_type;

  /* Quick exit if memory at this address is not an instruction.  */
  if (di.insn_type == dis_noninsn)
    return;

  /* arc_opcode must be set if this is not a dis_noninsn.  */
  gdb_assert (di.private_data != NULL);

  const struct arc_opcode *opcode
    = (const struct arc_opcode *) di.private_data;
  insn->opcode_data = opcode;

  insn->raw_word = read_instruction (&di, addr, insn->length);

  if (insn->length == 2)
    insn->opcode = BITS (insn->raw_word, 11, 15);
  else
    insn->opcode = BITS (insn->raw_word, 27, 31);
  set_insn_subopcodes (insn);

  /* Read LIMM if there is one.  */
  if (length_with_limm > 4)
    {
      insn->limm_value = read_instruction (&di, addr + insn->length, 4);
      insn->limm_p = TRUE;
    }

  insn->is_control_flow = (di.insn_type == dis_branch
			   || di.insn_type == dis_condbranch
			   || di.insn_type == dis_jsr
			   || di.insn_type == dis_condjsr);
  /* LEAVE_S has insn type dref and MEMORY opcode class, so has to be handled
     separately.  */
  if (arc_insn_is_leave_s (*insn))
    insn->is_control_flow = TRUE;

  /* ARC can have only one instruction in delay slot.  */
  gdb_assert (di.branch_delay_insns <= 1);
  insn->has_delay_slot = di.branch_delay_insns;

  set_insn_flags (insn);
}

/* Dump contents of arc_instruction to stdlog.  */

void
arc_insn_dump (const struct arc_instruction &insn)
{
  struct gdbarch *gdbarch = target_gdbarch ();

  arc_print ("Dumping arc_instruction at %s\n",
	     paddress (gdbarch, insn.address));
  arc_print ("\tlength=%u\n", insn.length);

  if (insn.insn_type == dis_noninsn)
    {
      arc_print ("This is not a valid ARC instruction.\n");
      return;
    }

  arc_print ("\tlength_with_limm=%u\n", insn.length + (insn.limm_p ? 4 : 0));
  arc_print ("\topcode=0x%02x\n", insn.opcode);
  arc_print ("\tsubopcode1=0x%02x\n", insn.subopcode1);
  arc_print ("\tsubopcode2=0x%x\n", insn.subopcode2);
  arc_print ("\tsubopcode3=0x%x\n", insn.subopcode3);
  arc_print ("\tcc=0x%x\n", insn.condition_code);
  arc_print ("\tis_control_flow=%i\n", insn.is_control_flow);
  arc_print ("\thas_delay_slot=%i\n", insn.has_delay_slot);

  CORE_ADDR next_pc = arc_insn_get_linear_next_pc (insn);
  arc_print ("\tlinear_next_pc=%s\n", paddress (gdbarch, next_pc));

  if (insn.is_control_flow)
    {
      CORE_ADDR t = arc_insn_get_branch_target (insn);
      arc_print ("\tbranch_target=%s\n", paddress (gdbarch, t));
    }

  if (insn.length == 2)
    arc_print ("\traw_word=0x%04lx\n", insn.raw_word);
  else
    arc_print ("\traw_word=0x%08lx\n", insn.raw_word);

  arc_print ("\tlimm_p=%i\n", insn.limm_p);
  if (insn.limm_p)
    arc_print ("\tlimm_value=0x%08lx\n", insn.limm_value);

  unsigned int operand_count = arc_insn_count_operands (insn);
  arc_print ("\toperand_count=%u\n", operand_count);
  for (unsigned int i = 0; i < operand_count; ++i)
    {
      int is_reg = arc_insn_operand_is_reg (insn, i);
      arc_print ("\toperand[%u].is_reg=%i\n", i, is_reg);
      if (is_reg)
	{
	  arc_print ("\toperand[%u].regnum=%i\n", i,
		     arc_insn_get_operand_reg (insn, i));
	}
      /* Don't know if this value is signed or not, so print both
	 representations.  This tends to look quite ugly especially for big
	 numbers.  */
      arc_print ("\toperand[%u].value=%s, signed=%s\n", i,
		 pulongest (arc_insn_get_operand_value (insn, i)),
		 plongest (arc_insn_get_operand_value_signed (insn, i)));
    }

  if (insn.opcode_data->insn_class == MEMORY)
    {
      arc_print ("\twriteback_mode=%u\n", insn.writeback_mode);
      arc_print ("\tdata_size_mode=%u\n", insn.data_size_mode);
      /* get_memory_offset returns an unsigned CORE_ADDR, but treat it as a
	 LONGEST for a nicer representation.  */
      arc_print ("\taddr_offset=%s\n",
		 plongest (arc_insn_get_memory_offset (insn)));
    }
}

unsigned int
arc_insn_count_operands (const struct arc_instruction &insn)
{
  unsigned int result = 0;

  for (const unsigned char *opindex = insn.opcode_data->operands; *opindex;
       opindex++)
    if (!(arc_operands[*opindex].flags & ARC_OPERAND_FAKE))
      result += 1;

  return result;
}

CORE_ADDR
arc_insn_get_linear_next_pc (const struct arc_instruction &insn)
{
  /* In ARC long immediate is always 4 bytes.  */
  return (insn.address + insn.length + (insn.limm_p ? 4 : 0));
}

CORE_ADDR
arc_insn_get_branch_target (const struct arc_instruction &insn)
{
  gdb_assert (insn.is_control_flow);

  /* For BI [c]: PC = nextPC + (c << 2).  */
  if (arc_insn_match_subop1 (insn, 0x04, 0x24))
    {
      ULONGEST reg_value = arc_insn_get_operand_value (insn, 0);
      return arc_insn_get_linear_next_pc (insn) + (reg_value << 2);
    }
  /* For BIH [c]: PC = nextPC + (c << 1).  */
  else if (arc_insn_match_subop1 (insn, 0x04, 0x25))
    {
      ULONGEST reg_value = arc_insn_get_operand_value (insn, 0);
      return arc_insn_get_linear_next_pc (insn) + (reg_value << 1);
    }
  /* JLI and EI.  */
  else if (arc_insn_match_op (insn, 0x0B))
    {
      /* JLI and EI depend on optional AUX registers.  For now we don't support
	 them.  */
      if (insn.subopcode1 == 0x0)
	fprintf_unfiltered (gdb_stderr, "\
JLI_S instructions are not supported by the GDB.");
      else
	fprintf_unfiltered (gdb_stderr, "\
EI_S instructions are not supported by the GDB.");
      return 0;
    }
  /* LEAVE_S.  */
  else if (arc_insn_is_leave_s (insn))
    {
      struct regcache *regcache = get_current_regcache ();
      ULONGEST value;
      regcache_cooked_read_unsigned (regcache, ARC_BLINK_REGNUM, &value);
      return value;
    }
  /* B, Bcc, BL, BLcc, BBIT0/1, BRcc - PC-relative operand.  */
  else if (insn.opcode_data->insn_class == BRANCH)
    {
      CORE_ADDR pcrel_addr;

      /* Most instructions has branch target as their sole argument.  However
	 conditional brcc/bbit has it as a third operand.  Opcode 0x1 also
	 covers simple conditional branches like Bcc.  Bit 16 is set for
	 BRcc/BBIT, not set for Bcc.  */
      if (arc_insn_match_subop1 (insn, 0x01, 0x1))
	pcrel_addr = arc_insn_get_operand_value (insn, 2);
      else
	pcrel_addr = arc_insn_get_operand_value (insn, 0);

      /* Offset is relative to the 4-byte aligned address of the current
	 instruction, hence last two bits should be truncated.  */
      return pcrel_addr + align_down (insn.address, 4);
    }
  else if (insn.opcode_data->insn_class == JUMP)
    {
      /* All jumps are single-operand.  */
      return arc_insn_get_operand_value (insn, 0);
    }

  /* This is some new and unknown instruction.  */
  gdb_assert_not_reached ("Unknown branch instruction.");
}

static const struct arc_operand *
get_arc_operand (const struct arc_instruction &insn, unsigned int operand_num)
{
  gdb_assert (operand_num < arc_insn_count_operands (insn));

  unsigned int cur_operand_index = 0;
  for (const unsigned char *opindex = insn.opcode_data->operands; *opindex;
       opindex++)
    {
      const struct arc_operand *operand = &arc_operands[*opindex];

      if (operand->flags & ARC_OPERAND_FAKE)
	continue;

      if (cur_operand_index == operand_num)
	return &arc_operands[*opindex];

      cur_operand_index += 1;
    }

  /* No way we could have gotten here.  If operand_num would be higher than
     operand count, an assertion would fail earlier.  */
  gdb_assert_not_reached ("Number of operands doesn't match.");
}

int
arc_insn_get_operand_reg (const struct arc_instruction &insn,
			  unsigned int operand_num)
{
  const struct arc_operand *operand = get_arc_operand (insn, operand_num);

  if (operand->flags & ARC_OPERAND_LIMM)
    {
      gdb_assert (insn.limm_p);
      return ARC_LIMM_REGNUM;
    }
  else if (operand->flags & ARC_OPERAND_IR)
    {
      /* Some operands are encoded in a simple manner with just a shift
	 and length, but some are encoded in two non-contiguous pieces,
	 so extracting them requires a special function.  */
      if (operand->extract != NULL)
	return ((*operand->extract) (insn.raw_word, NULL));
      else
	return EXTRACT_OPERAND (insn.raw_word, operand);
    }
  else
    {
      return -1;
    }
}

ULONGEST
arc_insn_get_operand_value (const struct arc_instruction &insn,
			    unsigned int operand_num)
{
  const struct arc_operand *operand = get_arc_operand (insn, operand_num);

  if (operand->flags & ARC_OPERAND_LIMM)
    {
      gdb_assert (insn.limm_p);
      return insn.limm_value;
    }
  else
    {
      ULONGEST value;

      /* Some operands are encoded in a simple manner with just a shift
	 and length, but some are encoded in two non-contiguous pieces,
	 so extracting them requires a special function.  */
      if (operand->extract != NULL)
	value = (*operand->extract) (insn.raw_word, NULL);
      else
	value = EXTRACT_OPERAND (insn.raw_word, operand);

      if (operand->flags & ARC_OPERAND_IR)
	{
	  /* Value in instruction is a register number.  */
	  struct regcache *regcache = get_current_regcache ();
	  regcache_cooked_read_unsigned (regcache, value, &value);
	}

      /* PC-relative flag is not handled here.  It may be set for some
	 branch instructions, but not for the others.  So
	 arc_insn_get_branch_target handles pc-relativeness itself,
	 while this function returns just an offset.  */

      /* No need for special treatment of 32-bit and 16-bit aligned
	 operands - that is already handled by the disassembler.  */

      /* No need to handle ARC_OPERAND_SIGNED - already done by the
	 disassembler.  */

      return value;
    }
}

LONGEST
arc_insn_get_operand_value_signed (const struct arc_instruction &insn,
				   unsigned int operand_num)
{
  const struct arc_operand *operand = get_arc_operand (insn, operand_num);

  if (operand->flags & ARC_OPERAND_LIMM)
    {
      gdb_assert (insn.limm_p);
      /* Convert unsigned raw value to signed one.  This assumes 2's
	 complement arithmetic, but so is the LONG_MIN value from generic
	 defs.h and that assumption is true for ARC.  */
      gdb_static_assert (sizeof (insn.limm_value) == sizeof (long));
      return (((LONGEST) insn.limm_value) ^ LONG_MIN) - LONG_MIN;
    }
  else
    {
      LONGEST value;

      /* Some operands are encoded in a simple manner with just a shift
	 and length, but some are encoded in two non-contiguous pieces,
	 so extracting them requires a special function.  */
      if (operand->extract != NULL)
	value = (*operand->extract) (insn.raw_word, NULL);
      else
	value = EXTRACT_OPERAND (insn.raw_word, operand);

      if (operand->flags & ARC_OPERAND_IR)
	{
	  /* Value in instruction is a register number.  */
	  struct regcache *regcache = get_current_regcache ();
	  regcache_cooked_read_signed (regcache, value, &value);
	}

      /* PC-relative flag is not handled here.  It may be set for some
	 branch instructions, but not for the others.  So
	 arc_insn_get_branch_target handles pc-relativeness itself,
	 while this function returns just an offset.  */

      /* No need for special treatment of 32-bit and 16-bit aligned
	 operands - that is already handled by the disassembler.  */

      /* No need to handle ARC_OPERAND_SIGNED - already done by the
	 disassembler.  */

      return value;
    }
}

int
arc_insn_operand_is_reg (const struct arc_instruction &insn,
			 unsigned int operand_num)
{
  const struct arc_operand *operand = get_arc_operand (insn, operand_num);

  if (operand->flags & ARC_OPERAND_LIMM)
    {
      gdb_assert (insn.limm_p);
      return FALSE;
    }
  else if (operand->flags & ARC_OPERAND_IR)
    return TRUE;
  else
    return FALSE;
}

int
arc_insn_get_memory_base_reg (const struct arc_instruction &insn)
{
  gdb_assert (insn.opcode_data->insn_class == MEMORY);

  /* POP_S and PUSH_S have SP as an implicit argument in a disassembler.  */
  if (arc_insn_is_pop_s (insn) || arc_insn_is_push_s (insn))
    return ARC_SP_REGNUM;

  /* Other instructions all have at least two operands: operand 0 is data,
     operand 1 is address.  Operand 2 is offset from address.  However, see
     comment to arc_insn_count_operands - in some cases, third operand may be
     missing, if it is 0.  */
  gdb_assert (arc_insn_count_operands (insn) >= 2);
  return arc_insn_get_operand_reg (insn, 1);
}

CORE_ADDR
arc_insn_get_memory_offset (const struct arc_instruction &insn)
{
  gdb_assert (insn.opcode_data->insn_class == MEMORY);

  /* POP_S and PUSH_S have offset as an implicit argument in a
     disassembler.  */
  if (arc_insn_is_pop_s (insn))
    return 4;
  else if (arc_insn_is_push_s (insn))
    return -4;

  /* Other instructions all have at least two operands: operand 0 is data,
     operand 1 is address.  Operand 2 is offset from address.  However, see
     comment to arc_insn_count_operands - in some cases, third operand may be
     missing, if it is 0.  */
  if (arc_insn_count_operands (insn) < 3)
    return 0;

  CORE_ADDR value = arc_insn_get_operand_value (insn, 2);
  /* Handle scaling.  */
  if (insn.writeback_mode == ARC_WRITEBACK_AS)
    {
      /* Byte data size is not valid for AS.  Halfword means shift by 1 bit.
	 Word and double word means shift by 2 bits.  */
      gdb_assert (insn.data_size_mode != ARC_SCALING_B);
      if (insn.data_size_mode == ARC_SCALING_H)
	value <<= 1;
      else
	value <<= 2;
    }
  return value;
}
