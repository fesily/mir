/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   Encoder of DWARF call frame information for Linux x86-64 JIT frames and the
   assembler of the .eh_frame like registration blocks the system unwinder
   (libgcc_s) is given through __register_frame.

   Only the code publishing and the x86-64 generator/wrappers include this
   file: the rest of MIR is target independent and does not know about unwinding.

   Two layers are provided:

   * Instruction stream emitters (mir_dwarf_cfi_*).  They append DW_CFA_*
     instructions to a growable byte VARR.  A stream does not contain the CIE and
     hides nothing: no offset or size is limited by the encoding besides the
     values the DWARF opcodes themselves can express.

   * The registration block assembler (mir_dwarf_cfi_assemble).  It writes one
     CIE followed by one FDE per described range and the zero terminator into a
     byte VARR.  The addresses in the FDEs are absolute (DW_EH_PE_absptr), so the
     block has to be assembled after the code is published.  The block is copied
     by the caller into immovable memory: libgcc_s keeps the pointer, it never
     copies the data.

   The register numbers of MIR and of the x86-64 DWARF ABI are different, so all
   conversions go through mir_dwarf_cfi_reg.  */

#ifndef MIR_DWARF_CFI_H
#define MIR_DWARF_CFI_H

#include <stdint.h>
#include <string.h>

/* x86-64 DWARF register numbers (psABI, "DWARF Register Number Mapping").  */
enum {
  MIR_DWARF_RAX = 0,
  MIR_DWARF_RDX = 1,
  MIR_DWARF_RCX = 2,
  MIR_DWARF_RBX = 3,
  MIR_DWARF_RSI = 4,
  MIR_DWARF_RDI = 5,
  MIR_DWARF_RBP = 6,
  MIR_DWARF_RSP = 7,
  MIR_DWARF_R8 = 8,
  MIR_DWARF_R9 = 9,
  MIR_DWARF_R10 = 10,
  MIR_DWARF_R11 = 11,
  MIR_DWARF_R12 = 12,
  MIR_DWARF_R13 = 13,
  MIR_DWARF_R14 = 14,
  MIR_DWARF_R15 = 15,
  MIR_DWARF_RIP = 16,
  MIR_DWARF_XMM0 = 17,
  MIR_DWARF_XMM15 = 32,
  MIR_DWARF_ST0 = 33
};

/* The x86-64 psABI puts ABI level of the DWARF version at 4 ... (nothing to do
   here), but it keeps the x87 register numbers at 33: they are used by the
   c2mir builtins only, never by the generator.  */

static const uint8_t mir_dwarf_cfi_ret_addr_reg = MIR_DWARF_RIP;
static const uint8_t mir_dwarf_cfi_cfa_reg = MIR_DWARF_RSP;
static const int64_t mir_dwarf_cfi_cfa_offset = 8; /* the return address is at cfa-8 */
static const int64_t mir_dwarf_cfi_data_align = -8;

#define MIR_DWARF_CFI_OP_advance_loc(delta) (0x40 | (delta)) /* delta < 64 */
#define MIR_DWARF_CFI_OP_offset(reg) (0x80 | (reg))          /* reg < 64 */
#define MIR_DWARF_CFI_OP_restore(reg) (0xc0 | (reg))         /* reg < 64 */

#define MIR_DWARF_CFI_nop 0x00
#define MIR_DWARF_CFI_set_loc 0x01
#define MIR_DWARF_CFI_advance_loc1 0x02
#define MIR_DWARF_CFI_advance_loc2 0x03
#define MIR_DWARF_CFI_advance_loc4 0x04
#define MIR_DWARF_CFI_offset_extended 0x05
#define MIR_DWARF_CFI_restore_extended 0x06
#define MIR_DWARF_CFI_undefined 0x07
#define MIR_DWARF_CFI_same_value 0x08
#define MIR_DWARF_CFI_register 0x09
#define MIR_DWARF_CFI_remember_state 0x0a
#define MIR_DWARF_CFI_restore_state 0x0b
#define MIR_DWARF_CFI_def_cfa 0x0c
#define MIR_DWARF_CFI_def_cfa_register 0x0d
#define MIR_DWARF_CFI_def_cfa_offset 0x0e
#define MIR_DWARF_CFI_def_cfa_expression 0x0f
#define MIR_DWARF_CFI_expression 0x10
#define MIR_DWARF_CFI_offset_extended_sf 0x11
#define MIR_DWARF_CFI_def_cfa_sf 0x12
#define MIR_DWARF_CFI_def_cfa_offset_sf 0x13
#define MIR_DWARF_CFI_val_offset 0x14
#define MIR_DWARF_CFI_val_offset_sf 0x15
#define MIR_DWARF_CFI_val_expression 0x16
#define MIR_DWARF_CFI_GNU_args_size 0x2e

/* MIR hard register -> DWARF register.  MIR enumerates the integer registers in
   its own order (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15) which is not
   the DWARF one, so the mapping is explicit.  The caller passes the MIR number
   of an integer register (0..15) or an XMM register (16..31).  */
static inline unsigned mir_dwarf_cfi_reg (unsigned mir_hard_reg) {
  static const uint8_t map[] = {
    MIR_DWARF_RAX, MIR_DWARF_RCX, MIR_DWARF_RDX, MIR_DWARF_RBX, MIR_DWARF_RSP,
    MIR_DWARF_RBP, MIR_DWARF_RSI, MIR_DWARF_RDI, MIR_DWARF_R8,  MIR_DWARF_R9,
    MIR_DWARF_R10, MIR_DWARF_R11, MIR_DWARF_R12, MIR_DWARF_R13, MIR_DWARF_R14,
    MIR_DWARF_R15};
  if (mir_hard_reg < 16) return map[mir_hard_reg];
  /* XMM0..XMM15: MIR 16..31, DWARF 17..32.  */
  return MIR_DWARF_XMM0 + (mir_hard_reg - 16);
}

/* ------------------------------- emitters -------------------------------- */

static inline void mir_dwarf_cfi_byte (VARR (uint8_t) * s, uint8_t v) {
  VARR_PUSH (uint8_t, s, v);
}

static inline void mir_dwarf_cfi_uleb (VARR (uint8_t) * s, uint64_t v) {
  do {
    uint8_t b = (uint8_t) (v & 0x7f);

    v >>= 7;
    if (v != 0) b |= 0x80;
    mir_dwarf_cfi_byte (s, b);
  } while (v != 0);
}

/* Signed LEB128: the value is shifted left keeping its sign: the standard
   (v << 1) ^ sign trick would overflow on INT64_MIN, the loop below does not. */
static inline void mir_dwarf_cfi_sleb (VARR (uint8_t) * s, int64_t v) {
  int more;

  do {
    uint8_t b = (uint8_t) (v & 0x7f);

    v >>= 7; /* arithmetic shift, implementation defined but universal */
    more = !((v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0));
    if (more) b |= 0x80;
    mir_dwarf_cfi_byte (s, b);
  } while (more);
}

/* Advance the row address from FROM to TO (all rows are at instruction ends).
   A zero delta is not encoded: DW_CFA_advance_loc with delta 0 is illegal.  */
static inline void mir_dwarf_cfi_advance (VARR (uint8_t) * s, size_t from, size_t to) {
  uint64_t delta;

  /* A zero delta produces no row (DW_CFA_advance_loc with 0 only wastes a byte),
     a backwards one is a bug.  */
  if (to <= from) return;
  delta = (uint64_t) (to - from);
  mir_assert (delta <= 0xffffffffu); /* the widest operand is advance_loc4 */
  if (delta < 0x40) {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_OP_advance_loc ((uint8_t) delta));
  } else if (delta <= 0xff) {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_advance_loc1);
    mir_dwarf_cfi_byte (s, (uint8_t) delta);
  } else if (delta <= 0xffff) {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_advance_loc2);
    mir_dwarf_cfi_byte (s, (uint8_t) (delta & 0xff));
    mir_dwarf_cfi_byte (s, (uint8_t) (delta >> 8));
  } else {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_advance_loc4);
    for (unsigned i = 0; i < 4; i++) mir_dwarf_cfi_byte (s, (uint8_t) (delta >> (8 * i)));
  }
}

/* The register REG is saved at CFA + DISP (DISP is a multiple of -data_align).
   Only the CFA relative address is stored, so the same rule is valid while the
   CFA itself moves.  DW_CFA_offset takes an *unsigned* factored offset, so a
   negative factor has to use the signed form.  */
static inline void mir_dwarf_cfi_offset (VARR (uint8_t) * s, unsigned reg, int64_t disp) {
  int64_t factor = disp / mir_dwarf_cfi_data_align;

  mir_assert (disp % mir_dwarf_cfi_data_align == 0);
  if (reg < 64 && factor >= 0) {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_OP_offset ((uint8_t) reg));
    mir_dwarf_cfi_uleb (s, (uint64_t) factor);
  } else if (factor >= 0) {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_offset_extended);
    mir_dwarf_cfi_uleb (s, reg);
    mir_dwarf_cfi_uleb (s, (uint64_t) factor);
  } else {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_offset_extended_sf);
    mir_dwarf_cfi_uleb (s, reg);
    mir_dwarf_cfi_sleb (s, factor);
  }
}

/* The register is restored to the rule it had at the function entry (used
   after the epilogue has loaded the caller value back).  */
static inline void mir_dwarf_cfi_restore (VARR (uint8_t) * s, unsigned reg) {
  if (reg < 64) {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_OP_restore ((uint8_t) reg));
  } else {
    mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_restore_extended);
    mir_dwarf_cfi_uleb (s, reg);
  }
}

/* CFA = REG + OFFSET for the following rows.  */
static inline void mir_dwarf_cfi_def_cfa (VARR (uint8_t) * s, unsigned reg, uint64_t offset) {
  mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_def_cfa);
  mir_dwarf_cfi_uleb (s, reg);
  mir_dwarf_cfi_uleb (s, offset);
}

static inline void mir_dwarf_cfi_remember_state (VARR (uint8_t) * s) {
  mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_remember_state);
}

static inline void mir_dwarf_cfi_restore_state (VARR (uint8_t) * s) {
  mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_restore_state);
}

/* --------------------------- registration block -------------------------- */

/* A described range: the half open code interval [BEGIN, END) and the
   instruction stream for it.  A NULL or empty stream means the default CIE
   rules (a leaf frame which changes neither RSP nor a non-volatile register). */
struct mir_dwarf_cfi_range {
  uintptr_t begin, end;
  const uint8_t *insns;
  size_t insns_len;
};

#define MIR_DWARF_CFI_CIE_VERSION 1
#define MIR_DWARF_CFI_ENCODING_ABSPTR 0x00

static inline void mir_dwarf_cfi_emit_u32 (VARR (uint8_t) * s, uint32_t v) {
  for (unsigned i = 0; i < 4; i++) mir_dwarf_cfi_byte (s, (uint8_t) (v >> (8 * i)));
}

static inline void mir_dwarf_cfi_emit_u64 (VARR (uint8_t) * s, uint64_t v) {
  for (unsigned i = 0; i < 8; i++) mir_dwarf_cfi_byte (s, (uint8_t) (v >> (8 * i)));
}

/* Pad the entry which started at START so that its total length is a multiple of
   the 8-byte address size (with DW_CFA_nop); the length itself is written by
   mir_dwarf_cfi_fix_len afterwards.  */
static inline void mir_dwarf_cfi_pad (VARR (uint8_t) * s, size_t start) {
  while ((VARR_LENGTH (uint8_t, s) - start) % 8 != 0) mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_nop);
}

/* Write the length of the entry which started at START into LEN_POS.  A length
   which does not fit the DWARF32 field is a bug, not something to truncate.  */
static inline void mir_dwarf_cfi_fix_len (VARR (uint8_t) * s, size_t start, size_t len_pos) {
  size_t total = VARR_LENGTH (uint8_t, s) - start;

  mir_assert (total - 4 <= 0xffffffffu);
  {
    uint32_t len = (uint32_t) (total - 4);
    uint8_t *p = VARR_ADDR (uint8_t, s) + len_pos;

    for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t) (len >> (8 * i));
  }
}

/* Write the CIE (version 1, augmentation "zR", absolute addresses) and return
   its offset in S.  The return address is at CFA-8 and the initial CFA rule is
   RSP+8, which is exactly the state of a function just after the call.  */
static inline size_t mir_dwarf_cfi_cie (VARR (uint8_t) * s) {
  size_t start = VARR_LENGTH (uint8_t, s), len_pos;

  mir_dwarf_cfi_emit_u32 (s, 0); /* length, patched below */
  len_pos = start;
  mir_dwarf_cfi_emit_u32 (s, 0); /* CIE_id */
  mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_CIE_VERSION);
  mir_dwarf_cfi_byte (s, 'z');
  mir_dwarf_cfi_byte (s, 'R');
  mir_dwarf_cfi_byte (s, 0);
  mir_dwarf_cfi_uleb (s, 1);  /* code alignment factor */
  mir_dwarf_cfi_sleb (s, mir_dwarf_cfi_data_align);
  mir_dwarf_cfi_byte (s, mir_dwarf_cfi_ret_addr_reg); /* a byte in version 1 */
  mir_dwarf_cfi_uleb (s, 1);                         /* augmentation data length */
  mir_dwarf_cfi_byte (s, MIR_DWARF_CFI_ENCODING_ABSPTR);
  mir_dwarf_cfi_def_cfa (s, mir_dwarf_cfi_cfa_reg, (uint64_t) mir_dwarf_cfi_cfa_offset);
  mir_dwarf_cfi_offset (s, mir_dwarf_cfi_ret_addr_reg, -8);
  mir_dwarf_cfi_pad (s, start);
  mir_dwarf_cfi_fix_len (s, start, len_pos);
  return start;
}

/* Append one FDE for RANGE.  CIE_START is the offset of the CIE in S: the
   CIE_pointer field holds the distance from the field itself back to the CIE. */
static inline void mir_dwarf_cfi_fde (VARR (uint8_t) * s, size_t cie_start,
                                      const struct mir_dwarf_cfi_range *range) {
  size_t start = VARR_LENGTH (uint8_t, s), len_pos, cie_field;

  mir_dwarf_cfi_emit_u32 (s, 0); /* length, patched below */
  len_pos = start;
  cie_field = VARR_LENGTH (uint8_t, s);
  /* the field is 4 bytes wide: the distance from it back to the CIE has to be
     representable, otherwise the unwinder would look at the wrong block offset */
  mir_assert (cie_field - cie_start <= 0xffffffffu);
  mir_dwarf_cfi_emit_u32 (s, (uint32_t) (cie_field - cie_start)); /* CIE_pointer */
  mir_dwarf_cfi_emit_u64 (s, (uint64_t) range->begin);            /* initial_location */
  mir_dwarf_cfi_emit_u64 (s, (uint64_t) (range->end - range->begin)); /* address_range */
  mir_dwarf_cfi_uleb (s, 0); /* augmentation data length */
  if (range->insns != NULL && range->insns_len != 0)
    VARR_PUSH_ARR (uint8_t, s, range->insns, range->insns_len);
  mir_dwarf_cfi_pad (s, start);
  mir_dwarf_cfi_fix_len (s, start, len_pos);
}

/* Assemble a whole registration block (CIE, one FDE per range, the zero
   terminator) into S, which must be empty.  The ranges have to be ordered by
   BEGIN and must not overlap.  */
static inline void mir_dwarf_cfi_assemble (VARR (uint8_t) * s, size_t n,
                                           const struct mir_dwarf_cfi_range *ranges) {
  size_t cie_start = mir_dwarf_cfi_cie (s);

  for (size_t i = 0; i < n; i++) mir_dwarf_cfi_fde (s, cie_start, &ranges[i]);
  mir_dwarf_cfi_emit_u32 (s, 0); /* the terminator: an entry with a zero length */
}

#endif /* #ifndef MIR_DWARF_CFI_H */
