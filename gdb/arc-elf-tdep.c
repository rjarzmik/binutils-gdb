/* Target dependent code for ARC processor family, for GDB, the GNU debugger.

   Copyright 2005 Free Software Foundation, Inc.
   Copyright 2009-2012 Synopsys Inc.

   Contributed by Codito Technologies Pvt. Ltd. (www.codito.com) on behalf of
   Synopsys Inc.

   Authors:
      Soam Vasani          <soam.vasani@codito.com>
      Ramana Radhakrishnan <ramana.radhakrishnan@codito.com>
      Richard Stuckey      <richard.stuckey@arc.com>

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/******************************************************************************/
/*                                                                            */
/* Outline:                                                                   */
/*     This module provides support for the ARC processor family's target     */
/*     dependencies which are specific to the arc-elf32 configuration of the  */
/*     ARC gdb.                                                               */
/*                                                                            */
/*                                                                            */
/*  Functionality:                                                            */
/*     This module provides a number of operations:                           */
/*                                                                            */
/*     1) a function which returns the name of a register, given its number   */
/*                                                                            */
/*     2) a function which determines whether a given register belongs to a   */
/*        particular group (e.g. the group of registers which should be saved */
/*        and restored across a function call)                                */
/*                                                                            */
/*     3) a function which prints out registers                               */
/*                                                                            */
/*     4) functions which implement the gdb extended commands                 */
/*                                                                            */
/*        arc-watch-range <start> [<kind>]  for setting a watchpoint range    */
/*        arc-break-range <start> <length>  for setting a breakpoint range    */
/*        arc-fill-memory <start> <length> [<pattern>] for filling memory     */
/*                                                                            */
/* Usage:                                                                     */
/*     The module exports a function _initialize_arc_elf_tdep: the call to   */
/*     this function is generated by the gdb build mechanism, so this function*/
/*     should not be explicitly called.                                       */
/*                                                                            */
/*     This module exports a function arc_elf_initialize which creates the   */
/*     user commands which use those command-implementing functions; it also  */
/*     stores pointers to the other functions in a data structure so that     */
/*     they may be called from outside this module.                           */
/*                                                                            */
/*     Some of the operations provided by this module are registered with gdb */
/*     during initialization; gdb then calls them via function pointers,      */
/*     rather than by name (this allows gdb to handle multiple target         */
/*     architectures):                                                        */
/*                                                                            */
/*          set_gdbarch_XXX (gdbarch, <function>);                            */
/*                                                                            */
/******************************************************************************/

/* system header files */
#include <string.h>

/* gdb header files */
#include "defs.h"
#include "inferior.h"
#include "gdbcmd.h"
#include "regcache.h"
#include "reggroups.h"
#include "observer.h"
#include "objfiles.h"
#include "arch-utils.h"

/* ARC header files */
#include "arc-tdep.h"
#include "arc-aux-registers.h"


/* -------------------------------------------------------------------------- */
/*                               local types                                  */
/* -------------------------------------------------------------------------- */

typedef struct
{
  struct gdbarch *gdbarch;
  struct ui_file *file;
  struct frame_info *frame;
} PrintData;


/* -------------------------------------------------------------------------- */
/*                               local data                                   */
/* -------------------------------------------------------------------------- */


/* -------------------------------------------------------------------------- */
/*		   ARC specific GDB architectural functions		      */
/*									      */
/* Functions are listed in the order they are used in arc_elf_init_abi.       */
/* -------------------------------------------------------------------------- */

/*! Determine whether a register can be read.

    An ELF target can see any register visible via the JTAG debug interface.

    @todo We'll need a more complex interface once the aux registers are
          defined via XML.

    @param[in] gdbarch  The current GDB architecture.
    @param[in] regnum   The register of interest.
    @return             Non-zero (TRUE) if we _cannot_ read the register,
                        false otherwise. */
static int
arc_elf_cannot_fetch_register (struct gdbarch *gdbarch, int regnum)
{
  /* Default is to be able to read regs, pick out the others explicitly. */
  switch (regnum)
    {
    case ARC_RESERVED_REGNUM:
    case ARC_LIMM_REGNUM:
      return 1;				/* Never readable. */

    default:
      return 0;				/* Readable via JTAG. */
    }
}	/* arc_elf_cannot_fetch_register () */


/*! Determine whether a register can be written.

    An ELF target can see any register visible via the JTAG debug interface.

    @todo We'll need a more complex interface once the aux registers are
          defined via XML.

    @param[in] gdbarch  The current GDB architecture.
    @param[in] regnum   The register of interest.
    @return             Non-zero (TRUE) if we _cannot_ write the register,
                        false otherwise. */
static int
arc_elf_cannot_store_register (struct gdbarch *gdbarch, int regnum)
{
  /* Default is to be able to write regs, pick out the others explicitly. */
  switch (regnum)
    {
    case ARC_RESERVED_REGNUM:
    case ARC_LIMM_REGNUM:
    case ARC_PCL_REGNUM:
      return 1;				/* Never writable. */

    default:
      return 0;				/* Writable via JTAG. */
    }
}	/* arc_elf_cannot_store_register () */


/* -------------------------------------------------------------------------- */
/*                               externally visible functions                 */
/* -------------------------------------------------------------------------- */

/*! Function to identify the OSABI to be used.

    Every target variant must define this appropriately. */
enum gdb_osabi
arc_get_osabi (void)
{
  return  GDB_OSABI_UNKNOWN;

}	/* arc_get_osabi () */


/*! Initialize the ELF ABI */
static void
arc_elf_init_abi (struct gdbarch_info info, struct gdbarch *gdbarch)
{
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);

  /* todo: Do we really need this. Seems an archaic JTAG thing. */
  /* arc_aux_pc_guard (gdbarch); */

  /* have aux registers been defined for that arch`? */
  if (!arc_aux_regs_defined (gdbarch))
    {
      /* Try to get the definitions of the target's auxiliary registers */
      arc_read_default_aux_registers (gdbarch);
    }

  /* Fill in target-dependent info in ARC-private structure. */

  tdep->is_sigtramp = NULL;
  tdep->sigcontext_addr = NULL;
  tdep->sc_reg_offset = NULL;
  tdep->sc_num_regs = 0;

  /* Set up target dependent GDB architecture entries. */
  set_gdbarch_cannot_fetch_register (gdbarch, arc_elf_cannot_fetch_register);
  set_gdbarch_cannot_store_register (gdbarch, arc_elf_cannot_store_register);

}


/*! ELF specific initialization function. */
void
_initialize_arc_elf_tdep (void)
{
  /* register a handler with gdb for the Linux O/S ABI variant for the ARC
   * processor architecture, providing an initialization function;
   *
   * 'bfd_arch_arc' is an enumeration value specifically denoting the ARC
   *                architecture
   */
  gdbarch_register_osabi (bfd_arch_arc, 0,	/* machine (irrelevant) */
			  GDB_OSABI_UNKNOWN, arc_elf_init_abi);

}	/* _initialize_arc_elf_tdep () */