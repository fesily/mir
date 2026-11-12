/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   Encoder of version 1 UNWIND_INFO structures (no exception handler, no chained
   info) for Windows x64 JIT frames.  Only the code publishing and the x86-64
   generator/wrappers include this file: the rest of MIR is target independent
   and does not know about Windows unwind data.

   The builder collects unwind operations in the order the prologue executes
   them (together with the prologue offset of the instruction end).  The encoder
   writes them back to front, which is the order required by UNWIND_INFO
   (descending code offsets).

   Code offsets, SizeOfProlog and the number of unwind code slots are limited by
   255 by the format.  Any limit violation sets bad_p (and the encoder then
   returns 0): metadata is never silently truncated.  */

#ifndef MIR_WIN64_UNWIND_H
#define MIR_WIN64_UNWIND_H

#include <stdint.h>
#include <string.h>

/* Windows x64 register numbers as used by unwind codes.  */
enum {
  MIR_UNWREG_RAX = 0,
  MIR_UNWREG_RCX = 1,
  MIR_UNWREG_RDX = 2,
  MIR_UNWREG_RBX = 3,
  MIR_UNWREG_RSP = 4,
  MIR_UNWREG_RBP = 5,
  MIR_UNWREG_RSI = 6,
  MIR_UNWREG_RDI = 7,
  MIR_UNWREG_R8 = 8,
  MIR_UNWREG_R9 = 9,
  MIR_UNWREG_R10 = 10,
  MIR_UNWREG_R11 = 11,
  MIR_UNWREG_R12 = 12,
  MIR_UNWREG_R13 = 13,
  MIR_UNWREG_R14 = 14,
  MIR_UNWREG_R15 = 15
};

#define MIR_UNWOP_PUSH_NONVOL 0
#define MIR_UNWOP_ALLOC_LARGE 1
#define MIR_UNWOP_ALLOC_SMALL 2
#define MIR_UNWOP_SET_FPREG 3
#define MIR_UNWOP_SAVE_NONVOL 4
#define MIR_UNWOP_SAVE_NONVOL_FAR 5
#define MIR_UNWOP_SAVE_XMM128 8
#define MIR_UNWOP_SAVE_XMM128_FAR 9

/* The maximal number of UNWIND_CODE slots (16-bit slots, i.e. a pair of bytes)
   and the maximal size of an encoded UNWIND_INFO.  */
#define MIR_WIN64_UNWIND_MAX_OPS 255
#define MIR_WIN64_UNWIND_MAX_BYTES (4 + 3 * 2 * MIR_WIN64_UNWIND_MAX_OPS + 4)

struct mir_win64_unwind_op {
  uint8_t code_offset; /* offset of the end of the corresponding prologue insn */
  uint8_t op;          /* MIR_UNWOP_* */
  uint8_t info;        /* OpInfo field */
  uint8_t far_p;       /* the operation takes the wide (ULONG) operand form */
  uint32_t extra;      /* operation operand (already scaled where needed) */
};

struct mir_win64_unwind_builder {
  uint8_t nops, size_of_prolog, frame_register, frame_offset_bytes, bad_p;
  struct mir_win64_unwind_op ops[MIR_WIN64_UNWIND_MAX_OPS];
};

static inline void mir_win64_unwind_init (struct mir_win64_unwind_builder *b) {
  b->nops = b->size_of_prolog = b->frame_register = b->frame_offset_bytes = b->bad_p = 0;
}

static inline struct mir_win64_unwind_op *mir_win64_unwind_new_op (struct mir_win64_unwind_builder *b,
                                                                  uint8_t code_offset) {
  if (b->nops >= MIR_WIN64_UNWIND_MAX_OPS) {
    b->bad_p = 1;
    return &b->ops[MIR_WIN64_UNWIND_MAX_OPS - 1];
  }
  if (code_offset < b->size_of_prolog) b->bad_p = 1; /* prologue offsets must grow */
  b->size_of_prolog = code_offset;
  b->ops[b->nops].code_offset = code_offset;
  b->ops[b->nops].info = b->ops[b->nops].op = b->ops[b->nops].far_p = 0;
  b->ops[b->nops].extra = 0;
  return &b->ops[b->nops++];
}

static inline void mir_win64_unwind_set_prolog_size (struct mir_win64_unwind_builder *b,
                                                     uint8_t size) {
  if (size < b->size_of_prolog) b->bad_p = 1;
  b->size_of_prolog = size;
}

static inline void mir_win64_unwind_set_frame_reg (struct mir_win64_unwind_builder *b,
                                                   uint8_t reg, uint32_t offset) {
  if (reg == 0 || offset > 240 || offset % 16 != 0) {
    b->bad_p = 1;
    return;
  }
  b->frame_register = reg;
  b->frame_offset_bytes = (uint8_t) offset;
}

static inline void mir_win64_unwind_push_nonvol (struct mir_win64_unwind_builder *b,
                                                  uint8_t code_offset, uint8_t reg) {
  struct mir_win64_unwind_op *o = mir_win64_unwind_new_op (b, code_offset);

  o->op = MIR_UNWOP_PUSH_NONVOL;
  o->info = reg;
}

static inline void mir_win64_unwind_alloc (struct mir_win64_unwind_builder *b, uint8_t code_offset,
                                           uint64_t size) {
  struct mir_win64_unwind_op *o = mir_win64_unwind_new_op (b, code_offset);

  o->op = MIR_UNWOP_ALLOC_LARGE;
  if (size <= 128 && size % 8 == 0) {
    o->op = MIR_UNWOP_ALLOC_SMALL;
    o->info = (uint8_t) (size / 8 - 1);
  } else if (size % 8 == 0 && size / 8 <= 0xffff && size != 0) {
    o->info = 0;
    o->extra = (uint32_t) (size / 8);
  } else if (size <= 0xffffffffu && size % 8 == 0 && size != 0) {
    o->info = 1;
    o->far_p = 1;
    o->extra = (uint32_t) size;
  } else {
    b->bad_p = 1; /* not representable as an unwind allocation */
  }
}

/* The frame pointer is established by LEA reg,[rsp+offset] (offset is the
   frame register offset declared by mir_win64_unwind_set_frame_reg).  */
static inline void mir_win64_unwind_set_fpreg (struct mir_win64_unwind_builder *b,
                                               uint8_t code_offset) {
  struct mir_win64_unwind_op *o = mir_win64_unwind_new_op (b, code_offset);

  o->op = MIR_UNWOP_SET_FPREG;
}

/* Save of a non-volatile GPR at disp relative to the current frame base.  With
   a frame register, disp is relative to the frame base, otherwise to the RSP
   value established by the preceding allocations.  */
static inline void mir_win64_unwind_save_nonvol (struct mir_win64_unwind_builder *b,
                                                 uint8_t code_offset, uint8_t reg, uint32_t disp) {
  struct mir_win64_unwind_op *o = mir_win64_unwind_new_op (b, code_offset);

  o->op = MIR_UNWOP_SAVE_NONVOL;
  o->info = reg;
  if (disp % 8 == 0 && disp / 8 <= 0xffff) {
    o->extra = disp / 8;
  } else {
    o->op = MIR_UNWOP_SAVE_NONVOL_FAR;
    o->far_p = 1;
    o->extra = disp;
  }
}

/* Save of a volatile XMM register (full 128 bits) at disp relative to the
   current frame base.  */
static inline void mir_win64_unwind_save_xmm128 (struct mir_win64_unwind_builder *b,
                                                 uint8_t code_offset, uint8_t xmm_num,
                                                 uint32_t disp) {
  struct mir_win64_unwind_op *o = mir_win64_unwind_new_op (b, code_offset);

  o->op = MIR_UNWOP_SAVE_XMM128;
  o->info = xmm_num;
  if (disp % 16 == 0 && disp / 16 <= 0xffff) {
    o->extra = disp / 16;
  } else {
    o->op = MIR_UNWOP_SAVE_XMM128_FAR;
    o->far_p = 1;
    o->extra = disp;
  }
}

/* Return the number of 16-bit slots taken by the operation.  */
static inline size_t mir_win64_unwind_op_slots (const struct mir_win64_unwind_op *o) {
  switch (o->op) {
  case MIR_UNWOP_PUSH_NONVOL:
  case MIR_UNWOP_ALLOC_SMALL:
  case MIR_UNWOP_SET_FPREG: return 1;
  case MIR_UNWOP_ALLOC_LARGE: return o->info == 0 ? 2 : 3;
  case MIR_UNWOP_SAVE_NONVOL:
  case MIR_UNWOP_SAVE_XMM128: return 2;
  default: return 3; /* _FAR forms */
  }
}

/* Encode UNWIND_INFO into out (which must have MIR_WIN64_UNWIND_MAX_BYTES bytes).
   With inherited_p the metadata describes a frame whose prologue has already
   been executed somewhere else (a bb fragment or an internal thunk): the
   operations keep their order and frame register, but the prologue size and all
   code offsets become zero.  Return the length or 0 on failure.  */
static inline size_t mir_win64_unwind_encode (const struct mir_win64_unwind_builder *b,
                                              int inherited_p, uint8_t *out, size_t out_len) {
  uint8_t body[6 * MIR_WIN64_UNWIND_MAX_OPS];
  size_t n = 0, nslots = 0;
  int i;

  if (b->bad_p || out_len < 4) return 0;
  for (i = (int) b->nops - 1; i >= 0; i--) {
    const struct mir_win64_unwind_op *o = &b->ops[i];
    uint8_t off = inherited_p ? 0 : o->code_offset;
    size_t slots = mir_win64_unwind_op_slots (o);

    if (n + 2 * slots > sizeof (body)) return 0;
    nslots += slots;
    body[n++] = off;
    body[n++] = (uint8_t) ((o->op & 0xf) | ((o->info & 0xf) << 4));
    if (slots == 2) {
      body[n++] = (uint8_t) (o->extra & 0xff);
      body[n++] = (uint8_t) ((o->extra >> 8) & 0xff);
    } else if (slots == 3) {
      body[n++] = (uint8_t) (o->extra & 0xff);
      body[n++] = (uint8_t) ((o->extra >> 8) & 0xff);
      body[n++] = (uint8_t) ((o->extra >> 16) & 0xff);
      body[n++] = (uint8_t) ((o->extra >> 24) & 0xff);
    }
  }
  if (nslots > MIR_WIN64_UNWIND_MAX_OPS) return 0;
  if (n % 4 != 0) { /* the unwind code array is a multiple of 4 bytes */
    if (n + 2 > sizeof (body)) return 0;
    body[n] = body[n + 1] = 0;
    n += 2;
  }
  if (n + 4 > out_len) return 0; /* the padding slot is part of the output too */
  out[0] = 1; /* Version 1, Flags 0 (no exception handler, no chained info) */
  out[1] = inherited_p ? 0 : b->size_of_prolog;
  out[2] = (uint8_t) nslots;
  out[3] = (uint8_t) ((b->frame_register & 0xf)
                      | (((b->frame_offset_bytes / 16) & 0xf) << 4));
  memcpy (out + 4, body, n);
  return 4 + n;
}

#endif /* #ifndef MIR_WIN64_UNWIND_H */
