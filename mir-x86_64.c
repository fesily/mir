/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.
*/

#include "mir-x86_64.h"
#include "mir-unwind-target.h"
#if defined(MIR_WIN64_UNWIND)
#include "mir-win64-unwind.h"
#endif

/* Linux x86-64 (x32 excluded): the runtime stubs carry DWARF call frame
   information, see mir-dwarf-cfi.h.  */
#if defined(MIR_DWARF_UNWIND)
#include "mir-dwarf-cfi.h"
#endif

#if !defined(MIR_DWARF_UNWIND)
/* Publish a runtime stub together with its unwind info (Windows x64) or
   without any metadata (the other targets).  EXEC_END is the end of the
   executable code in CODE; anything after it is data.  */
/* B is the Windows x64 unwind builder; the parameter is untyped so that the
   plain targets do not have to know the Windows unwind header.  */
static void *publish_stub (MIR_context_t ctx, VARR (uint8_t) * code, size_t exec_end,
                           const void *b) {
#if defined(MIR_WIN64_UNWIND)
  uint8_t info[MIR_WIN64_UNWIND_MAX_BYTES];
  struct _MIR_code_unwind uw;
  size_t len = mir_win64_unwind_encode ((const struct mir_win64_unwind_builder *) b, 0, info,
                                        sizeof (info));

  if (len == 0) {
    MIR_get_error_func (ctx) (MIR_wrong_param_value_error,
                              "cannot encode Windows x64 unwind information");
    return NULL;
  }
  uw.begin = 0;
  uw.end = exec_end;
  uw.info = info;
  uw.info_len = len;
  return _MIR_publish_code_with_unwind (ctx, VARR_ADDR (uint8_t, code),
                                        VARR_LENGTH (uint8_t, code), 1, &uw);
#else
  (void) exec_end;
  (void) b;
  return _MIR_publish_code (ctx, VARR_ADDR (uint8_t, code), VARR_LENGTH (uint8_t, code));
#endif
}
#endif /* !MIR_DWARF_UNWIND */

#if defined(MIR_DWARF_UNWIND)
/* Emit one call frame information row for the instruction which has just been
   emitted: every row is at an instruction end, so that the lookup of the return
   PC minus one lands in the right range.  */
static void dwarf_row (VARR (uint8_t) * cfi, size_t *last_off, size_t off, uint64_t cfa) {
  mir_dwarf_cfi_advance (cfi, *last_off, off);
  *last_off = off;
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, cfa);
}

/* Publish a runtime stub with one described range [0, EXEC_END).  With CFI ==
   NULL the default leaf rules are described (an empty instruction stream); with
   CFI == NULL and EXEC_END == 0 no registration is done at all.  */
static void *publish_stub_dwarf (MIR_context_t ctx, VARR (uint8_t) * code, size_t exec_end,
                                 VARR (uint8_t) * cfi) {
  struct _MIR_code_unwind uw;

  if (cfi == NULL && exec_end == 0)
    return _MIR_publish_code (ctx, VARR_ADDR (uint8_t, code), VARR_LENGTH (uint8_t, code));
  uw.begin = 0;
  uw.end = exec_end;
  uw.info = cfi == NULL ? NULL : VARR_ADDR (uint8_t, cfi);
  uw.info_len = cfi == NULL ? 0 : VARR_LENGTH (uint8_t, cfi);
  return _MIR_publish_code_with_unwind (ctx, VARR_ADDR (uint8_t, code),
                                        VARR_LENGTH (uint8_t, code), 1, &uw);
}
#endif

static uint8_t *push_insns (VARR (uint8_t) * insn_varr, const uint8_t *pat, size_t pat_len);

/* RBLK args are always passed by address.
   BLK0 first is copied on the caller stack and passed implicitly.
   BLK1 is passed in general regs
   BLK2 is passed in fp regs
   BLK3 is passed in gpr and then fpr
   BLK4 is passed in fpr and then gpr
   If there are no enough regs, they work as BLK.
   Windows: 1, 2, 4 and 8-byte BLKs are passed by value in an integer
            register; all other BLKs are passed by pointer as a regular
            int arg (and returned through a hidden pointer).  */

#define VA_LIST_IS_ARRAY_P 1

void *_MIR_get_bstart_builtin (MIR_context_t ctx) {
  static const uint8_t bstart_code[] = {
    0x48, 0x8d, 0x44, 0x24, 0x08, /* rax = rsp + 8 (lea) */
    0xc3,                         /* ret */
  };
#if defined(MIR_DWARF_UNWIND)
  /* A leaf which only reads RSP: the default rules describe it completely.  */
  {
    VARR (uint8_t) * code;

    VARR_CREATE (uint8_t, code, ctx->alloc, 16);
    push_insns (code, bstart_code, sizeof (bstart_code));
    void *res = publish_stub_dwarf (ctx, code, sizeof (bstart_code), NULL);

    VARR_DESTROY (uint8_t, code);
    return res;
  }
#else
  return _MIR_publish_code (ctx, bstart_code, sizeof (bstart_code));
#endif
}
void *_MIR_get_bend_builtin (MIR_context_t ctx) {
  static const uint8_t bend_code[] = {
#ifndef _WIN32
    0x48, 0x8b, 0x04, 0x24, /* rax = (rsp) */
    0x48, 0x89, 0xfc,       /* rsp = rdi */
    0xff, 0xe0,             /* jmp *rax */
#else
    0x48, 0x8b, 0x04, 0x24, /* rax = (rsp) */
    0x48, 0x89, 0xcc,       /* rsp = rcx */
    0xff, 0xe0,             /* jmp *rax */
#endif
  };
#if defined(MIR_DWARF_UNWIND)
  /* Only the first instruction is described: the frame is the normal one until
     `mov %rdi,%rsp` switches the stack, and the switched stack (and the tail
     jump into it) has no describable relation to the caller.  */
  {
    static const size_t described_len = 4;
    VARR (uint8_t) * code;

    VARR_CREATE (uint8_t, code, ctx->alloc, 16);
    push_insns (code, bend_code, sizeof (bend_code));
    void *res = publish_stub_dwarf (ctx, code, described_len, NULL);

    VARR_DESTROY (uint8_t, code);
    return res;
  }
#else
  return _MIR_publish_code (ctx, bend_code, sizeof (bend_code));
#endif
}

#ifndef _WIN32
struct x86_64_va_list {
  uint32_t gp_offset, fp_offset;
  uint64_t *overflow_arg_area, *reg_save_area;
};

void *va_arg_builtin (void *p, uint64_t t) {
  struct x86_64_va_list *va = p;
  MIR_type_t type = t;
  int fp_p = type == MIR_T_F || type == MIR_T_D;
  void *a;

  if (fp_p && va->fp_offset <= 160) {
    a = (char *) va->reg_save_area + va->fp_offset;
    va->fp_offset += 16;
  } else if (!fp_p && type != MIR_T_LD && va->gp_offset <= 40) {
    a = (char *) va->reg_save_area + va->gp_offset;
    va->gp_offset += 8;
  } else {
    /* SysV 3.5.7 step 7: a long double takes a 16-byte ALIGNED slot of the
       overflow area (gcc/clang callers place it there) */
    if (type == MIR_T_LD)
      va->overflow_arg_area = (uint64_t *) (((uint64_t) va->overflow_arg_area + 15) / 16 * 16);
    a = va->overflow_arg_area;
    va->overflow_arg_area += type == MIR_T_LD ? 2 : 1;
  }
  return a;
}

void va_block_arg_builtin (void *res, void *p, size_t s, uint64_t ncase) {
  struct x86_64_va_list *va = p;
  size_t size = ((s + 7) / 8) * 8;
  void *a = va->overflow_arg_area;
  union {
    uint64_t i;
    double d;
  } u[2];

  switch (ncase) {
  case 1:
    if (va->gp_offset + size > 48) break;
    u[0].i = *(uint64_t *) ((char *) va->reg_save_area + va->gp_offset);
    va->gp_offset += 8;
    if (size > 8) {
      u[1].i = *(uint64_t *) ((char *) va->reg_save_area + va->gp_offset);
      va->gp_offset += 8;
    }
    if (res != NULL) memcpy (res, &u, s);
    return;
  case 2:
    /* Each SSE eightbyte takes a 16-byte slot of the 48..176 save area; a
       block that doesn't fit is in the overflow area. */
    if (va->fp_offset + size * 2 > 176) break;
    u[0].d = *(double *) ((char *) va->reg_save_area + va->fp_offset);
    va->fp_offset += 16;
    if (size > 8) {
      u[1].d = *(double *) ((char *) va->reg_save_area + va->fp_offset);
      va->fp_offset += 16;
    }
    if (res != NULL) memcpy (res, &u, s);
    return;
  case 3:
  case 4:
    if (va->fp_offset > 160 || va->gp_offset > 40) break;
    if (ncase == 3) {
      u[0].i = *(uint64_t *) ((char *) va->reg_save_area + va->gp_offset);
      u[1].d = *(double *) ((char *) va->reg_save_area + va->fp_offset);
    } else {
      u[0].d = *(double *) ((char *) va->reg_save_area + va->fp_offset);
      u[1].i = *(uint64_t *) ((char *) va->reg_save_area + va->gp_offset);
    }
    /* An SSE eightbyte occupies a 16-byte slot in the register save area
       (each XMM is stored in 16 bytes), so fp_offset must advance by 16 --
       matching the SSE-only path (case 2) and va_arg_builtin.  Advancing by
       only 8 made the next mixed-class struct's SSE field read an
       overlapping/stale slot.  The INTEGER eightbyte is 8 bytes. */
    va->fp_offset += 16;
    va->gp_offset += 8;
    if (res != NULL) memcpy (res, &u, s);
    return;
  default: break;
  }
  if (res != NULL) memcpy (res, a, s);
  va->overflow_arg_area += size / 8;
}

void va_start_interp_builtin (MIR_context_t ctx MIR_UNUSED, void *p, void *a) {
  struct x86_64_va_list *va = p;
  va_list *vap = a;

  assert (sizeof (struct x86_64_va_list) == sizeof (va_list));
  *va = *(struct x86_64_va_list *) vap;
}

#else

struct x86_64_va_list {
  uint64_t *arg_area;
};

void *va_arg_builtin (void *p, uint64_t t) {
  struct x86_64_va_list *va = p;
  void *a = va->arg_area;
  va->arg_area++;
  return a;
}

void va_block_arg_builtin (void *res, void *p, size_t s, uint64_t ncase) {
  struct x86_64_va_list *va = p;
  /* Win64 passes only 1/2/4/8-byte aggregates by value; the others occupy a
     pointer slot (same rule as the call/prologue side).  */
  void *a = win_blk_by_value_p (s) ? va->arg_area : *(void **) va->arg_area;
  if (res != NULL) memcpy (res, a, s);
  va->arg_area++;
}

void va_start_interp_builtin (MIR_context_t ctx, void *p, void *a) {
  struct x86_64_va_list **va = p;
  va_list *vap = a;

  assert (sizeof (struct x86_64_va_list) == sizeof (va_list));
  *va = (struct x86_64_va_list *) vap;
}

#endif

void va_end_interp_builtin (MIR_context_t ctx MIR_UNUSED, void *p MIR_UNUSED) {}

static const uint8_t short_jmp_pattern[] = {
  0xe9, 0, 0, 0, 0,         /* 0x0: jmp rel32 */
  0,    0, 0, 0, 0, 0, 0, 0 /* 0x5: abs address holder */
};
static const uint8_t long_jmp_pattern[] = {
  0x49, 0xbb, 0,    0, 0, 0, 0, 0, 0, 0, /* 0x0: movabsq 0, r11 */
  0x41, 0xff, 0xe3,                      /* 0xa: jmpq   *%r11 */
};

/* r11=<address to go to>; jump *r11  */
void *_MIR_get_thunk (MIR_context_t ctx) {
  void *res;
  assert (sizeof (short_jmp_pattern) == sizeof (long_jmp_pattern));
  res = _MIR_publish_code (ctx, short_jmp_pattern, sizeof (short_jmp_pattern));
  return res;
}

void *_MIR_get_thunk_addr (MIR_context_t ctx MIR_UNUSED, void *thunk) {
  void *addr;
  int short_p = *(unsigned char *) thunk == 0xe9;
  memcpy ((char *) &addr, (char *) thunk + (short_p ? 5 : 2), sizeof (addr));
  return addr;
}

void _MIR_redirect_thunk (MIR_context_t ctx, void *thunk, void *to) {
  int64_t disp = (char *) to - ((char *) thunk + 5);
  int short_p = INT32_MIN <= disp && disp <= INT32_MAX;
  uint8_t pattern[sizeof (short_jmp_pattern)];
  if (short_p) {
    memcpy (pattern, short_jmp_pattern, sizeof (short_jmp_pattern));
    memcpy (pattern + 1, &disp, 4); /* little endian */
    memcpy (pattern + 5, &to, 8);
  } else {
    memcpy (pattern, long_jmp_pattern, sizeof (long_jmp_pattern));
    memcpy (pattern + 2, &to, 8);
  }
  _MIR_change_code (ctx, thunk, pattern, sizeof (short_jmp_pattern));
}

static uint8_t *push_insns (VARR (uint8_t) * insn_varr, const uint8_t *pat, size_t pat_len) {
  for (size_t i = 0; i < pat_len; i++) VARR_PUSH (uint8_t, insn_varr, pat[i]);
  return VARR_ADDR (uint8_t, insn_varr) + VARR_LENGTH (uint8_t, insn_varr) - pat_len;
}

static void gen_mov (VARR (uint8_t) * insn_varr, uint32_t offset, uint32_t reg, int ld_p) {
  static const uint8_t ld_gp_reg[] = {0x48, 0x8b, 0x83, 0, 0, 0, 0 /* mov <offset>(%rbx),%reg */};
  static const uint8_t st_gp_reg[] = {0x48, 0x89, 0x83, 0, 0, 0, 0 /* mov %reg,<offset>(%rbx) */};
  uint8_t *addr = push_insns (insn_varr, ld_p ? ld_gp_reg : st_gp_reg,
                              ld_p ? sizeof (ld_gp_reg) : sizeof (st_gp_reg));
  memcpy (addr + 3, &offset, sizeof (uint32_t));
  assert (reg <= 15);
  addr[0] |= (reg >> 1) & 4;
  addr[2] |= (reg & 7) << 3;
}

static void gen_mov2 (VARR (uint8_t) * insn_varr, uint32_t offset, uint32_t reg, int ld_p) {
  static const uint8_t ld_gp_reg[] = {0x49, 0x8b, 0x44, 0x24, 0 /* mov <offset>(%r12),%reg */};
  static const uint8_t st_gp_reg[] = {0x49, 0x89, 0x44, 0x24, 0 /* mov %reg,<offset>(%r12) */};
  uint8_t *addr = push_insns (insn_varr, ld_p ? ld_gp_reg : st_gp_reg,
                              ld_p ? sizeof (ld_gp_reg) : sizeof (st_gp_reg));
  addr[4] = offset;
  assert (reg <= 15);
  addr[0] |= (reg >> 1) & 4;
  addr[2] |= (reg & 7) << 3;
}

static void gen_blk_mov (VARR (uint8_t) * insn_varr, uint32_t offset, uint32_t addr_offset,
                         uint32_t qwords) {
  static const uint8_t blk_mov_pat[] = {
    /*0:*/ 0x4c,  0x8b, 0xa3, 0,    0, 0, 0,    /*mov <addr_offset>(%rbx),%r12*/
    /*7:*/ 0x48,  0xc7, 0xc0, 0,    0, 0, 0,    /*mov <qwords>,%rax*/
    /*e:*/ 0x48,  0x83, 0xe8, 0x01,             /*sub $0x1,%rax*/
    /*12:*/ 0x4d, 0x8b, 0x14, 0xc4,             /*mov (%r12,%rax,8),%r10*/
    /*16:*/ 0x4c, 0x89, 0x94, 0xc4, 0, 0, 0, 0, /*mov %r10,<offset>(%rsp,%rax,8)*/
    /*1e:*/ 0x48, 0x85, 0xc0,                   /*test %rax,%rax*/
    /*21:*/ 0x7f, 0xeb,                         /*jg e <L0>*/
  };
  uint8_t *addr = push_insns (insn_varr, blk_mov_pat, sizeof (blk_mov_pat));
  memcpy (addr + 3, &addr_offset, sizeof (uint32_t));
  memcpy (addr + 10, &qwords, sizeof (uint32_t));
  memcpy (addr + 26, &offset, sizeof (uint32_t));
}

static void gen_movxmm (VARR (uint8_t) * insn_varr, uint32_t offset, uint32_t reg, int b32_p,
                        int ld_p) {
  static const uint8_t ld_xmm_reg_pat[] = {
    0xf2, 0x0f, 0x10, 0x83, 0, 0, 0, 0 /* movs[sd] <offset>(%rbx),%xmm */
  };
  static const uint8_t st_xmm_reg_pat[] = {
    0xf2, 0x0f, 0x11, 0x83, 0, 0, 0, 0 /* movs[sd] %xmm, <offset>(%rbx) */
  };
  uint8_t *addr = push_insns (insn_varr, ld_p ? ld_xmm_reg_pat : st_xmm_reg_pat,
                              ld_p ? sizeof (ld_xmm_reg_pat) : sizeof (st_xmm_reg_pat));
  memcpy (addr + 4, &offset, sizeof (uint32_t));
  assert (reg <= 7);
  addr[3] |= reg << 3;
  if (b32_p) addr[0] |= 1;
}

static void gen_movxmm2 (VARR (uint8_t) * insn_varr, uint32_t offset, uint32_t reg, int ld_p) {
  static const uint8_t ld_xmm_reg_pat[] = {
    0xf2, 0x41, 0x0f, 0x10, 0x44, 0x24, 0 /* movsd <offset>(%r12),%xmm */
  };
  static const uint8_t st_xmm_reg_pat[] = {
    0xf2, 0x41, 0x0f, 0x11, 0x44, 0x24, 0 /* movsd %xmm, <offset>(%r12) */
  };
  uint8_t *addr = push_insns (insn_varr, ld_p ? ld_xmm_reg_pat : st_xmm_reg_pat,
                              ld_p ? sizeof (ld_xmm_reg_pat) : sizeof (st_xmm_reg_pat));
  addr[6] = offset;
  assert (reg <= 7);
  addr[4] |= reg << 3;
}

#ifdef _WIN32
static void gen_add (VARR (uint8_t) * insn_varr, uint32_t sp_offset, int reg) {
  static const uint8_t lea_pat[] = {
    0x48, 0x8d, 0x84, 0x24, 0, 0, 0, 0, /* lea    <sp_offset>(%sp),reg */
  };
  uint8_t *addr = push_insns (insn_varr, lea_pat, sizeof (lea_pat));
  memcpy (addr + 4, &sp_offset, sizeof (uint32_t));
  addr[2] |= (reg & 7) << 3;
  if (reg > 7) addr[0] |= 4;
}
#endif

static void gen_st (VARR (uint8_t) * insn_varr, uint32_t sp_offset, int b64_p) {
  static const uint8_t st_pat[] = {
    0x44, 0x89, 0x94, 0x24, 0, 0, 0, 0, /* mov    %r10,<sp_offset>(%sp) */
  };
  uint8_t *addr = push_insns (insn_varr, st_pat, sizeof (st_pat));
  memcpy (addr + 4, &sp_offset, sizeof (uint32_t));
  if (b64_p) addr[0] |= 8;
}

static void gen_ldst (VARR (uint8_t) * insn_varr, uint32_t sp_offset, uint32_t src_offset,
                      int b64_p) {
  static const uint8_t ld_pat[] = {
    0x44, 0x8b, 0x93, 0, 0, 0, 0, /* mov    <src_offset>(%rbx),%r10 */
  };
  uint8_t *addr = push_insns (insn_varr, ld_pat, sizeof (ld_pat));
  memcpy (addr + 3, &src_offset, sizeof (uint32_t));
  if (b64_p) addr[0] |= 8;
  gen_st (insn_varr, sp_offset, b64_p);
}

static void gen_ldst80 (VARR (uint8_t) * insn_varr, uint32_t sp_offset, uint32_t src_offset) {
  static uint8_t const ldst80_pat[] = {
    0xdb, 0xab, 0,    0, 0, 0,    /* fldt   <src_offset>(%rbx) */
    0xdb, 0xbc, 0x24, 0, 0, 0, 0, /* fstpt  <sp_offset>(%sp) */
  };
  uint8_t *addr = push_insns (insn_varr, ldst80_pat, sizeof (ldst80_pat));
  memcpy (addr + 2, &src_offset, sizeof (uint32_t));
  memcpy (addr + 9, &sp_offset, sizeof (uint32_t));
}

static void gen_st80 (VARR (uint8_t) * insn_varr, uint32_t src_offset) {
  static const uint8_t st80_pat[] = {0xdb, 0xbb, 0, 0, 0, 0 /* fstpt   <src_offset>(%rbx) */};
  memcpy (push_insns (insn_varr, st80_pat, sizeof (st80_pat)) + 2, &src_offset, sizeof (uint32_t));
}

/* Generation: fun (fun_addr, res_arg_addresses):
   push r12, push rbx; sp-=sp_offset; r11=fun_addr; rbx=res/arg_addrs
   r10=mem[rbx,<offset>]; (arg_reg=mem[r10] or r10=mem[r10];mem[sp,sp_offset]=r10
                           or r12=mem[rbx,arg_offset]; arg_reg=mem[r12]
                                                       [;(arg_reg + 1)=mem[r12 + 8]]
                           ...
                           or r12=mem[rbx,arg_offset];rax=qwords;
                              L:rax-=1;r10=mem[r12,rax]; mem[sp,sp_offset,rax]=r10;
                                goto L if rax > 0) ...
   rax=8; call *r11; sp+=offset
   r10=mem[rbx,<offset>]; res_reg=mem[r10]; ...
   pop rbx; pop r12; ret. */
void *_MIR_get_ff_call (MIR_context_t ctx, size_t nres, MIR_type_t *res_types, size_t nargs,
                        _MIR_arg_desc_t *arg_descs, size_t arg_vars_num MIR_UNUSED) {
#ifdef _WIN32
  static const uint8_t prolog[] = {
    /* 0x0: */ 0x41,  0x54,                   /* pushq %r12 */
    /* 0x2: */ 0x53,                          /* pushq %rbx */
    /* 0x3: */ 0x55,                          /* push %rbp */
    /* 0x4: */ 0x48,  0x89, 0xe5,             /* mov %rsp,%rbp */
    /* 0x7: */ 0x48,  0x81, 0xec, 0, 0, 0, 0, /* subq <sp_offset>, %rsp */
    /* 0xe: */ 0x49,  0x89, 0xcb,             /* mov $rcx, $r11 -- fun addr */
    /* 0x11: */ 0x48, 0x89, 0xd3,             /* mov $rdx, $rbx -- result/arg addresses */
  };
#else
  /* The non-Windows prologue is emitted piece by piece: every instruction which
     moves RSP gets its own call frame information row.  */
  static const uint8_t ff_push_r12[] = {0x41, 0x54};                  /* pushq %r12 */
  static const uint8_t ff_push_rbx[] = {0x53};                        /* pushq %rbx */
  static const uint8_t ff_sub_rsp[] = {0x48, 0x81, 0xec, 0, 0, 0, 0}; /* subq <sp_offset>,%rsp */
  static const uint8_t ff_mov_fun[] = {0x49, 0x89, 0xfb};             /* mov $rdi,$r11 */
  static const uint8_t ff_mov_tab[] = {0x48, 0x89, 0xf3};             /* mov $rsi,$rbx */
#endif
  static const uint8_t call_end[] = {
#ifndef _WIN32
    0x48, 0xc7, 0xc0, 0x08, 0, 0, 0, /* mov $8, rax -- to save xmm varargs */
#endif
    0x41, 0xff, 0xd3, /* callq  *%r11	   */
#ifndef _WIN32
    0x48, 0x81, 0xc4, 0,    0, 0, 0, /* addq <sp_offset>, %rsp */
#endif
  };
#ifndef _WIN32 /* the strict Windows epilogue is win_epilog below */
  static const uint8_t epilog[] = {
    0x5b,       /* pop %rbx */
    0x41, 0x5c, /* pop %r12 */
    0xc3,       /* ret */
  };
#endif
#ifndef _WIN32
  static const uint8_t iregs[] = {7, 6, 2, 1, 8, 9}; /* rdi, rsi, rdx, rcx, r8, r9 */
  static const uint32_t max_iregs = 6, max_xregs = 8;
  uint32_t sp_offset = 0;
#else
  static const uint8_t iregs[] = {1, 2, 8, 9}; /* rcx, rdx, r8, r9 */
  static const uint32_t max_iregs = 4, max_xregs = 4;
  uint32_t blk_offset = nargs < 4 ? 32 : (uint32_t) nargs * 8, sp_offset = 32; /* spill area */
#endif
  uint32_t n_iregs = 0, n_xregs = 0, n_fregs, qwords;
  uint8_t *addr;
  VARR (uint8_t) * code;
  void *res;
#ifdef _WIN32
  struct mir_win64_unwind_builder unw;
  /* Strict Windows epilogue (see below): add rsp,<sp_offset>; pop rbp;
     pop rbx; pop r12; ret */
  uint8_t win_epilog[] = {0x48, 0x81, 0xc4, 0, 0, 0, 0, 0x5d, 0x5b, 0x41, 0x5c, 0xc3};

  mir_win64_unwind_init (&unw);
#endif

#ifdef _WIN32
  VARR_CREATE (uint8_t, code, ctx->alloc, 128);
  push_insns (code, prolog, sizeof (prolog));
#else
  VARR (uint8_t) * cfi;
  size_t cfi_off = 0, off_after_sub, off_after_add;

  VARR_CREATE (uint8_t, code, ctx->alloc, 128);
#if defined(MIR_DWARF_UNWIND)
  VARR_CREATE (uint8_t, cfi, ctx->alloc, 64);
#endif
  push_insns (code, ff_push_r12, sizeof (ff_push_r12));
#if defined(MIR_DWARF_UNWIND)
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), 16);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (R12_HARD_REG), -16);
#endif
  push_insns (code, ff_push_rbx, sizeof (ff_push_rbx));
#if defined(MIR_DWARF_UNWIND)
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), 24);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (BX_HARD_REG), -24);
#endif
  push_insns (code, ff_sub_rsp, sizeof (ff_sub_rsp));
  off_after_sub = VARR_LENGTH (uint8_t, code);
  push_insns (code, ff_mov_fun, sizeof (ff_mov_fun));
  push_insns (code, ff_mov_tab, sizeof (ff_mov_tab));
#if !defined(MIR_DWARF_UNWIND)
  (void) cfi;
  (void) cfi_off;
  (void) off_after_sub;
  (void) off_after_add;
#endif
#endif
  for (size_t i = 0; i < nargs; i++) {
    MIR_type_t type = arg_descs[i].type;

    if ((MIR_T_I8 <= type && type <= MIR_T_U64) || type == MIR_T_P || type == MIR_T_RBLK) {
      if (n_iregs < max_iregs) {
        gen_mov (code, (uint32_t) ((i + nres) * sizeof (long double)), iregs[n_iregs++], TRUE);
#ifdef _WIN32
        n_xregs++;
#endif
      } else {
        gen_ldst (code, sp_offset, (uint32_t) ((i + nres) * sizeof (long double)), TRUE);
        sp_offset += 8;
      }
    } else if (type == MIR_T_F || type == MIR_T_D) {
      if (n_xregs < max_xregs) {
        gen_movxmm (code, (uint32_t) ((i + nres) * sizeof (long double)), n_xregs++,
                    type == MIR_T_F, TRUE);
#ifdef _WIN32
        gen_mov (code, (uint32_t) ((i + nres) * sizeof (long double)), iregs[n_iregs++], TRUE);
#endif
      } else {
        gen_ldst (code, sp_offset, (uint32_t) ((i + nres) * sizeof (long double)), type == MIR_T_D);
        sp_offset += 8;
      }
    } else if (type == MIR_T_LD) {
      /* a 16-byte aligned stack slot (SysV 3.2.3); the area below is 16-byte
         aligned at the call */
      sp_offset = (sp_offset + 15) / 16 * 16;
      gen_ldst80 (code, sp_offset, (uint32_t) ((i + nres) * sizeof (long double)));
      sp_offset += 16;
    } else if (MIR_blk_type_p (type)) {
      qwords = (uint32_t) ((arg_descs[i].size + 7) / 8);
#ifndef _WIN32
      if (type == MIR_T_BLK + 1 && n_iregs + qwords <= max_iregs) {
        assert (qwords <= 2);
        gen_mov (code, (i + nres) * sizeof (long double), 12, TRUE);   /* r12 = block addr */
        gen_mov2 (code, 0, iregs[n_iregs], TRUE);                      /* arg_reg = mem[r12] */
        if (qwords == 2) gen_mov2 (code, 8, iregs[n_iregs + 1], TRUE); /* arg_reg = mem[r12 + 8] */
        n_iregs += qwords; /* an all-INTEGER block consumes no SSE registers */
        continue;
      } else if (type == MIR_T_BLK + 2 && n_xregs + qwords <= max_xregs) {
        assert (qwords <= 2);
        gen_mov (code, (i + nres) * sizeof (long double), 12, TRUE); /* r12 = block addr */
        gen_movxmm2 (code, 0, n_xregs, TRUE);                        /* xmm = mem[r12] */
        if (qwords == 2) gen_movxmm2 (code, 8, n_xregs + 1, TRUE);   /* xmm = mem[r12 +  8] */
        n_xregs += qwords;
        continue;
      } else if (type == MIR_T_BLK + 3 && n_iregs < max_iregs && n_xregs < max_xregs) {
        assert (qwords == 2);
        gen_mov (code, (i + nres) * sizeof (long double), 12, TRUE); /* r12 = block addr */
        gen_mov2 (code, 0, iregs[n_iregs], TRUE);                    /* arg_reg = mem[r12] */
        n_iregs++;
        gen_movxmm2 (code, 8, n_xregs, TRUE); /* xmm = mem[r12 + 8] */
        n_xregs++;
        continue;
      } else if (type == MIR_T_BLK + 4 && n_iregs < max_iregs && n_xregs < max_xregs) {
        assert (qwords == 2);
        gen_mov (code, (i + nres) * sizeof (long double), 12, TRUE); /* r12 = block addr */
        gen_movxmm2 (code, 0, n_xregs, TRUE);                        /* xmm = mem[r12] */
        n_xregs++;
        gen_mov2 (code, 8, iregs[n_iregs], TRUE); /* arg_reg = mem[r12 + 8] */
        n_iregs++;
        continue;
      }
      gen_blk_mov (code, sp_offset, (i + nres) * sizeof (long double), qwords);
      sp_offset += qwords * 8;
#else
      if (win_blk_by_value_p (arg_descs[i].size)) {
        assert (qwords == 1);
        gen_mov (code, (uint32_t) ((i + nres) * sizeof (long double)), 12,
                 TRUE); /* r12 = mem[disp + rbx] */
        if (n_iregs < max_iregs) {
          gen_mov2 (code, 0, iregs[n_iregs++], TRUE); /* arg_reg = mem[r12] */
          n_xregs++;
        } else {
          gen_mov2 (code, 0, 10, TRUE);   /* r10 = mem[r12] */
          gen_st (code, sp_offset, TRUE); /* mem[sp+sp_offset] = r10; */
          sp_offset += 8;
        }
      } else {
        /* r12 = mem[disp + rbx]; mem[rsp+blk_offset + nw] = r10 = mem[r12 + nw]; */
        gen_blk_mov (code, blk_offset, (uint32_t) ((i + nres) * sizeof (long double)), qwords);
        if (n_iregs < max_iregs) {
          gen_add (code, blk_offset, iregs[n_iregs++]); /* arg_reg = sp + blk_offset */
          n_xregs++;
        } else {
          gen_add (code, blk_offset, 10); /* r10 = sp + blk_offset */
          gen_st (code, sp_offset, TRUE); /* mem[sp+sp_offset] = r10; */
          sp_offset += 8;
        }
        blk_offset += qwords * 8;
      }
#endif
    } else {
      MIR_get_error_func (ctx) (MIR_call_op_error, "wrong type of arg value");
    }
  }
#ifdef _WIN32
  if (blk_offset > sp_offset) sp_offset = blk_offset;
#endif
  sp_offset = (sp_offset + 15) / 16 * 16;
#ifndef _WIN32
  sp_offset += 8; /* align */
#endif
  addr = VARR_ADDR (uint8_t, code);
#ifndef _WIN32
  /* push r12; push rbx; sub <sp_offset>,%rsp -- the immediate is the third byte
     of the sub */
  memcpy (addr + sizeof (ff_push_r12) + sizeof (ff_push_rbx) + 3, &sp_offset,
          sizeof (uint32_t));
#else
  memcpy (addr + 10, &sp_offset, sizeof (uint32_t));
#endif
  addr = push_insns (code, call_end, sizeof (call_end));
#ifndef _WIN32
  memcpy (addr + sizeof (call_end) - 4, &sp_offset, sizeof (uint32_t));
  off_after_add = VARR_LENGTH (uint8_t, code); /* after `add <sp_offset>,%rsp` */
#if defined(MIR_DWARF_UNWIND)
  dwarf_row (cfi, &cfi_off, off_after_sub, 24 + (uint64_t) sp_offset);
  dwarf_row (cfi, &cfi_off, off_after_add, 24);
#endif
#else
  if (nres > 1)
    MIR_get_error_func (ctx) (MIR_call_op_error,
                              "Windows x86-64 doesn't support multiple return values");
#endif
  n_iregs = n_xregs = n_fregs = 0;
  for (size_t i = 0; i < nres; i++) {
    if (((MIR_T_I8 <= res_types[i] && res_types[i] <= MIR_T_U64) || res_types[i] == MIR_T_P)
        && n_iregs < 2) {
      gen_mov (code, (uint32_t) (i * sizeof (long double)), n_iregs++ == 0 ? 0 : 2,
               FALSE); /* rax or rdx */
    } else if ((res_types[i] == MIR_T_F || res_types[i] == MIR_T_D) && n_xregs < 2) {
      gen_movxmm (code, (uint32_t) (i * sizeof (long double)), n_xregs++, res_types[i] == MIR_T_F,
                  FALSE);
    } else if (res_types[i] == MIR_T_LD && n_fregs < 2) {
      gen_st80 (code, (uint32_t) (i * sizeof (long double)));
    } else {
      MIR_get_error_func (ctx) (MIR_ret_error,
                                "x86-64 can not handle this combination of return values");
    }
  }
#ifdef _WIN32
  /* Strict Windows epilogue: add rsp,<sp_offset>; pop rbp; pop rbx; pop r12;
     ret.  It has to be the exact mirror of the prologue (there is no frame
     register in the unwind information).  */
  memcpy (win_epilog + 3, &sp_offset, sizeof (uint32_t));
  push_insns (code, win_epilog, sizeof (win_epilog));
  /* Prologue: push r12; push rbx; push rbp; mov rbp,rsp; sub rsp,<sp_offset> */
  mir_win64_unwind_push_nonvol (&unw, 2, MIR_UNWREG_R12);
  mir_win64_unwind_push_nonvol (&unw, 3, MIR_UNWREG_RBX);
  mir_win64_unwind_push_nonvol (&unw, 4, MIR_UNWREG_RBP);
  mir_win64_unwind_alloc (&unw, 0xe, sp_offset);
  res = publish_stub (ctx, code, VARR_LENGTH (uint8_t, code), &unw);
#else
  {
#if defined(MIR_DWARF_UNWIND)
    size_t off_epilog = VARR_LENGTH (uint8_t, code);
#endif

    push_insns (code, epilog, sizeof (epilog)); /* pop rbx; pop r12; ret */
#if defined(MIR_DWARF_UNWIND)
    dwarf_row (cfi, &cfi_off, off_epilog + 1, 16); /* after `pop %rbx` */
    mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (BX_HARD_REG));
    dwarf_row (cfi, &cfi_off, off_epilog + 3, 8); /* after `pop %r12` */
    mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (R12_HARD_REG));
    res = publish_stub_dwarf (ctx, code, VARR_LENGTH (uint8_t, code), cfi);
    VARR_DESTROY (uint8_t, cfi);
#else
    res = publish_stub (ctx, code, 0, NULL);
#endif
  }
#endif
  VARR_DESTROY (uint8_t, code);
  return res;
}

#ifndef _WIN32
/* The Linux interp shim prologue is emitted piece by piece: every instruction
   which moves RSP gets its own call frame information row.  */
static const uint32_t isave_xmm_area = 0x80; /* must match the sub below */
static const uint8_t isave_sp[] = {0x48, 0x81, 0xec, 0x80, 0, 0, 0}; /* sub $0x80,%rsp */
static const uint8_t isave_xmm[] = {
  0xf3, 0x0f, 0x7f, 0x04, 0x24,       /* movdqu %xmm0,(%rsp)     */
  0xf3, 0x0f, 0x7f, 0x4c, 0x24, 0x10, /* movdqu %xmm1,0x10(%rsp) */
  0xf3, 0x0f, 0x7f, 0x54, 0x24, 0x20, /* movdqu %xmm2,0x20(%rsp) */
  0xf3, 0x0f, 0x7f, 0x5c, 0x24, 0x30, /* movdqu %xmm3,0x30(%rsp) */
  0xf3, 0x0f, 0x7f, 0x64, 0x24, 0x40, /* movdqu %xmm4,0x40(%rsp) */
  0xf3, 0x0f, 0x7f, 0x6c, 0x24, 0x50, /* movdqu %xmm5,0x50(%rsp) */
  0xf3, 0x0f, 0x7f, 0x74, 0x24, 0x60, /* movdqu %xmm6,0x60(%rsp) */
  0xf3, 0x0f, 0x7f, 0x7c, 0x24, 0x70, /* movdqu %xmm7,0x70(%rsp) */
};
static const uint8_t isave_push_r9[] = {0x41, 0x51};  /* push %r9  */
static const uint8_t isave_push_r8[] = {0x41, 0x50};  /* push %r8  */
static const uint8_t isave_push_rcx[] = {0x51};       /* push %rcx */
static const uint8_t isave_push_rdx[] = {0x52};       /* push %rdx */
static const uint8_t isave_push_rsi[] = {0x56};       /* push %rsi */
static const uint8_t isave_push_rdi[] = {0x57};       /* push %rdi */
#else
static const uint8_t save_pat[] = {
  0x48, 0x89, 0x4c, 0x24, 0x08, /*mov  %rcx,0x08(%rsp) */
  0x48, 0x89, 0x54, 0x24, 0x10, /*mov  %rdx,0x10(%rsp) */
  0x4c, 0x89, 0x44, 0x24, 0x18, /*mov  %r8, 0x18(%rsp) */
  0x4c, 0x89, 0x4c, 0x24, 0x20, /*mov  %r9, 0x20(%rsp) */
};
#endif

/* Transform C call to call of void handler (MIR_context_t ctx, MIR_item_t func_item,
                                             va_list va, MIR_val_t *results) */
void *_MIR_get_interp_shim (MIR_context_t ctx, MIR_item_t func_item, void *handler) {
#ifndef _WIN32
  static const uint8_t push_rbx[] = {0x53, /*push   %rbx  */};
#endif
  static const uint8_t prepare_pat[] = {
#ifndef _WIN32
    /*  0: */ 0x48, 0x83, 0xec, 0x20,                      /* sub    32,%rsp	     */
    /*  4: */ 0x48, 0x89, 0xe2,                            /* mov    %rsp,%rdx	     */
    /*  7: */ 0xc7, 0x02, 0,    0,    0,    0,             /* movl   0,(%rdx)	     */
    /*  d: */ 0xc7, 0x42, 0x04, 0x30, 0,    0, 0,          /* movl   48, 4(%rdx)     */
    /* 14: */ 0x48, 0x8d, 0x44, 0x24, 0x20,                /* lea    32(%rsp),%rax   */
    /* 19: */ 0x48, 0x89, 0x42, 0x10,                      /* mov    %rax,16(%rdx)   */
    /* 1d: */ 0x48, 0x8d, 0x84, 0x24, 0xe0, 0, 0, 0,       /* lea    224(%rsp),%rax  */
    /* 25: */ 0x48, 0x89, 0x42, 0x08,                      /* mov    %rax,8(%rdx)    */
    /* 29: */ 0x48, 0x81, 0xec, 0,    0,    0, 0,          /* sub    <n>,%rsp	     */
    /* 30: */ 0x48, 0x89, 0xe3,                            /* mov    %rsp,%rbx	     */
    /* 33: */ 0x48, 0x89, 0xe1,                            /* mov    %rsp,%rcx	     */
    /* 36: */ 0x48, 0xbf, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <ctx>,%rdi      */
    /* 40: */ 0x48, 0xbe, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <func_item>,%rsi*/
    /* 4a: */ 0x48, 0xb8, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <handler>,%rax  */
    /* 54: */ 0xff, 0xd0,                                  /* callq  *%rax           */
  };
  static const uint32_t nres_offset = 0x2c;
  static const uint32_t ctx_offset = 0x38;
  static const uint32_t func_offset = 0x42;
  static const uint32_t hndl_offset = 0x4c;
  static const uint32_t prep_stack_size = 208;
#else
    /*  0: */ 0x53,                                        /* push   %rbx            */
    /*  1: */ 0x55,                                        /* push %rbp */
    /*  2: */ 0x48, 0x89, 0xe5,                            /* mov %rsp,%rbp */
    /*  5: */ 0x4c, 0x8d, 0x44, 0x24, 0x18,                /* lea    24(%rsp),%r8     */
    /*  a: */ 0x48, 0x81, 0xec, 0,    0,    0, 0,          /* sub    <n>,%rsp        */
    /* 11: */ 0x48, 0x89, 0xe3,                            /* mov    %rsp,%rbx       */
    /* 14: */ 0x49, 0x89, 0xe1,                            /* mov    %rsp,%r9        */
    /* 17: */ 0x48, 0x83, 0xec, 0x20,                      /* sub    32,%rsp         */
    /* 1b: */ 0x48, 0xb9, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <ctx>,%rcx      */
    /* 25: */ 0x48, 0xba, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <func_item>,%rdx*/
    /* 2f: */ 0x48, 0xb8, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <handler>,%rax  */
    /* 39: */ 0xff, 0xd0,                                  /* callq  *%rax           */
  };
  static const uint32_t nres_offset = 0x0d;
  static const uint32_t ctx_offset = 0x1d;
  static const uint32_t func_offset = 0x27;
  static const uint32_t hndl_offset = 0x31;
  static const uint32_t prep_stack_size = 32;
#endif
  static const uint8_t shim_end[] = {
#ifndef _WIN32
    /* 0: */ 0x48, 0x81, 0xc4, 0, 0, 0, 0, /*add    prep_stack_size+n,%rsp*/
    0x5b,                                 /*pop   %rbx*/
#else
    /* Strict Windows epilogue: the exact mirror of the prologue (there is no
       frame register in the unwind data): add rsp,<n+32>; pop rbp; pop rbx; ret */
    0x48, 0x81, 0xc4, 0, 0, 0, 0, /* add rsp,<n+prep_stack_size> */
    0x5d,                         /* pop %rbp */
    0x5b,                         /* pop %rbx */
#endif
    0xc3, /*retq                         */
  };
  static const uint8_t ld_pat[] = {0x48, 0x8b, 0x83, 0, 0, 0, 0}; /* mov <offset>(%rbx), %reg */
  static const uint8_t movss_pat[]
    = {0xf3, 0x0f, 0x10, 0x83, 0, 0, 0, 0}; /* movss <offset>(%rbx), %xmm[01] */
  static const uint8_t movsd_pat[]
    = {0xf2, 0x0f, 0x10, 0x83, 0, 0, 0, 0};                   /* movsd <offset>(%rbx), %xmm[01] */
  static const uint8_t fldt_pat[] = {0xdb, 0xab, 0, 0, 0, 0}; /* fldt <offset>(%rbx) */
  static const uint8_t fxch_pat[] = {0xd9, 0xc9};             /* fxch */
  uint8_t *addr;
  uint32_t imm, n_iregs, n_xregs, n_fregs, offset;
  uint32_t nres = func_item->u.func->nres;
  MIR_type_t *results = func_item->u.func->res_types;
  VARR (uint8_t) * code;
  void *res;
#ifdef _WIN32
  struct mir_win64_unwind_builder unw;

  mir_win64_unwind_init (&unw);
#endif
#if defined(MIR_DWARF_UNWIND)
  VARR (uint8_t) * cfi;
  size_t cfi_off = 0, off_save;
  uint64_t cfa = 8; /* CFA = rsp+8 at the entry */

  VARR_CREATE (uint8_t, cfi, ctx->alloc, 128);
#endif
  VARR_CREATE (uint8_t, code, ctx->alloc, 128);
#ifdef _WIN32
  push_insns (code, save_pat, sizeof (save_pat));
#else
  /* push %rbx, then the argument save area, then the volatile registers; every
     instruction which moves RSP gets its own call frame information row */
  push_insns (code, push_rbx, sizeof (push_rbx));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (BX_HARD_REG), -16);
#endif
  push_insns (code, isave_sp, sizeof (isave_sp));
#if defined(MIR_DWARF_UNWIND)
  cfa += isave_xmm_area;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
#endif
  push_insns (code, isave_xmm, sizeof (isave_xmm)); /* the stores move nothing */
  push_insns (code, isave_push_r9, sizeof (isave_push_r9));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
#endif
  push_insns (code, isave_push_r8, sizeof (isave_push_r8));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
#endif
  push_insns (code, isave_push_rcx, sizeof (isave_push_rcx));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
#endif
  push_insns (code, isave_push_rdx, sizeof (isave_push_rdx));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
#endif
  push_insns (code, isave_push_rsi, sizeof (isave_push_rsi));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
#endif
  push_insns (code, isave_push_rdi, sizeof (isave_push_rdi));
#if defined(MIR_DWARF_UNWIND)
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  off_save = VARR_LENGTH (uint8_t, code); /* the state after all the saves */
#endif
#endif
  addr = push_insns (code, prepare_pat, sizeof (prepare_pat));
  imm = nres * 16;
#ifdef _WIN32
  imm += 8; /*align */
#endif
  memcpy (addr + nres_offset, &imm, sizeof (uint32_t));
  memcpy (addr + ctx_offset, &ctx, sizeof (void *));
  memcpy (addr + func_offset, &func_item, sizeof (void *));
  memcpy (addr + hndl_offset, &handler, sizeof (void *));
  /* move results: */
#ifdef _WIN32
  if (nres > 1)
    MIR_get_error_func (ctx) (MIR_call_op_error,
                              "Windows x86-64 doesn't support multiple return values");
#endif
  n_iregs = n_xregs = n_fregs = offset = 0;
  for (uint32_t i = 0; i < nres; i++) {
    if (results[i] == MIR_T_F && n_xregs < 2) {
      addr = push_insns (code, movss_pat, sizeof (movss_pat));
      addr[3] |= n_xregs << 3;
      memcpy (addr + 4, &offset, sizeof (uint32_t));
      n_xregs++;
    } else if (results[i] == MIR_T_D && n_xregs < 2) {
      addr = push_insns (code, movsd_pat, sizeof (movsd_pat));
      addr[3] |= n_xregs << 3;
      memcpy (addr + 4, &offset, sizeof (uint32_t));
      n_xregs++;
    } else if (results[i] == MIR_T_LD && n_fregs < 2) {
      addr = push_insns (code, fldt_pat, sizeof (fldt_pat));
      memcpy (addr + 2, &offset, sizeof (uint32_t));
      if (n_fregs == 1) push_insns (code, fxch_pat, sizeof (fxch_pat));
      n_fregs++;
    } else if (n_iregs < 2) {
      addr = push_insns (code, ld_pat, sizeof (ld_pat));
      addr[2] |= n_iregs << 4;
      memcpy (addr + 3, &offset, sizeof (uint32_t));
      n_iregs++;
    } else {
      MIR_get_error_func (ctx) (MIR_ret_error,
                                "x86-64 can not handle this combination of return values");
    }
    offset += 16;
  }
  addr = push_insns (code, shim_end, sizeof (shim_end));
#ifndef _WIN32
  /* the epilogue releases exactly what the saves and the preparation pushed */
  (void) isave_xmm_area; /* referenced only here and in the CFI rows */
  mir_assert (prep_stack_size == 32 + isave_xmm_area + 6 * 8);
  imm = prep_stack_size + nres * 16;
  memcpy (addr + 3, &imm, sizeof (uint32_t));
#if defined(MIR_DWARF_UNWIND)
  {
    size_t shim_off = VARR_LENGTH (uint8_t, code) - sizeof (shim_end);
    size_t off_add = shim_off + 7; /* after `add <0xd0+n>,%rsp` (7 bytes) */
    size_t off_pop = shim_off + 8; /* after `pop %rbx` (1 byte) */

    /* `sub $32,%rsp` and then `sub <n>,%rsp` of the va_list preparation */
    cfa += 32;
    dwarf_row (cfi, &cfi_off, off_save + 4, cfa);
    cfa += (uint64_t) nres * 16;
    dwarf_row (cfi, &cfi_off, off_save + nres_offset + 4, cfa);
    /* the epilogue releases everything at once and then pops %rbx */
    dwarf_row (cfi, &cfi_off, off_add, 16);
    dwarf_row (cfi, &cfi_off, off_pop, 8);
    mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (BX_HARD_REG));
    res = publish_stub_dwarf (ctx, code, VARR_LENGTH (uint8_t, code), cfi);
    VARR_DESTROY (uint8_t, cfi);
  }
#else
  res = publish_stub (ctx, code, 0, NULL);
#endif
#else
  imm = nres * 16 + 8 /* n */ + prep_stack_size /* outgoing area */;
  memcpy (addr + 3, &imm, sizeof (uint32_t));
  /* Prologue: <save_pat>; push rbx; push rbp; mov rbp,rsp; lea 24(rsp),r8;
     sub rsp,<n>; ...; sub rsp,32 (the offsets are counted from the very first
     generated instruction, i.e. they include the save_pat prefix) */
  mir_win64_unwind_push_nonvol (&unw, (uint8_t) (sizeof (save_pat) + 1), MIR_UNWREG_RBX);
  mir_win64_unwind_push_nonvol (&unw, (uint8_t) (sizeof (save_pat) + 2), MIR_UNWREG_RBP);
  mir_win64_unwind_alloc (&unw, (uint8_t) (sizeof (save_pat) + 0x11), nres * 16 + 8);
  mir_win64_unwind_alloc (&unw, (uint8_t) (sizeof (save_pat) + 0x1b), prep_stack_size);
  res = publish_stub (ctx, code, VARR_LENGTH (uint8_t, code), &unw);
#endif
  VARR_DESTROY (uint8_t, code);
  return res;
}

/* push rsi,rdi;rsi=called_func,rdi=ctx;r10=hook_address;jmp wrapper_end; */
void *_MIR_get_wrapper (MIR_context_t ctx, MIR_item_t called_func, void *hook_address) {
#ifndef _WIN32
  static const uint8_t start_pat[] = {
    0x56,                               /* push   %rsi			   */
    0x57,                               /* push   %rdi			   */
    0x48, 0xbe, 0, 0, 0, 0, 0, 0, 0, 0, /* movabs called_func,%rsi  	   */
    0x48, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, /* movabs ctx,%rdi  	   */
    0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, /* movabs <hook_address>,%r10  	   */
    0xe9, 0,    0, 0, 0,                /* 0x0: jmp rel32 */
  };
  size_t call_func_offset = 4, ctx_offset = 14, hook_offset = 24, rel32_offset = 33;
#else
  /* The wrapper_end is published by _MIR_init, in a code holder which is not
     necessarily within +-2GB of this one (there is no address space
     reservation on Windows), so the jump to it is indirect.  */
  static const uint8_t start_pat[] = {
    0x48, 0x89, 0x4c, 0x24, 0x08,                /* mov  %rcx,0x08(%rsp) */
    0x48, 0x89, 0x54, 0x24, 0x10,                /* mov  %rdx,0x10(%rsp) */
    0x48, 0xba, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs called_func,%rdx    */
    0x48, 0xb9, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs ctx,%rcx            */
    0x49, 0xba, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <hook_address>,%r10 */
    0x49, 0xbb, 0,    0,    0,    0, 0, 0, 0, 0, /* movabs <wrapper_end>,%r11  */
    0x41, 0xff, 0xe3,                            /* jmp *%r11                  */
  };
  size_t call_func_offset = 12, ctx_offset = 22, hook_offset = 32
#ifdef _WIN32
    ,
    wrapper_offset = 42
#endif
    ;
#endif
  uint8_t *addr;
  VARR (uint8_t) * code;
  void *res;

  VARR_CREATE (uint8_t, code, ctx->alloc, 128);
  addr = push_insns (code, start_pat, sizeof (start_pat));
  memcpy (addr + call_func_offset, &called_func, sizeof (void *));
  memcpy (addr + ctx_offset, &ctx, sizeof (void *));
  memcpy (addr + hook_offset, &hook_address, sizeof (void *));
#ifdef _WIN32
  memcpy (addr + wrapper_offset, &wrapper_end_addr, sizeof (void *));
#endif
#if defined(MIR_DWARF_UNWIND)
  {
    /* The stub pushes rsi and rdi and jumps into wrapper_end, which describes
       the frame from there on with CFA = rsp+24 at its entry.  */
    static const uint8_t push_rsi[] = {0x56};
    VARR (uint8_t) * cfi;
    size_t off_push_rsi = sizeof (push_rsi), off_push_rdi = 2 * sizeof (push_rsi);

    VARR_CREATE (uint8_t, cfi, ctx->alloc, 32);
    mir_dwarf_cfi_advance (cfi, 0, off_push_rsi);
    mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (SI_HARD_REG), -16);
    mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 16);
    mir_dwarf_cfi_advance (cfi, off_push_rsi, off_push_rdi);
    mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (DI_HARD_REG), -24);
    mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 24);
    res = publish_stub_dwarf (ctx, code, sizeof (start_pat), cfi);
    VARR_DESTROY (uint8_t, cfi);
  }
#else
  res = _MIR_publish_code (ctx, VARR_ADDR (uint8_t, code), VARR_LENGTH (uint8_t, code));
#endif
  VARR_DESTROY (uint8_t, code);
#ifndef _WIN32
  int64_t off = (uint8_t *) wrapper_end_addr - ((uint8_t *) res + rel32_offset + 4);
  assert (INT32_MIN <= off && off <= INT32_MAX);
  _MIR_change_code (ctx, (uint8_t *) res + rel32_offset, (uint8_t *) &off, 4); /* LE */
#endif
  return res;
}

void *_MIR_get_wrapper_end (MIR_context_t ctx) {
#ifdef _WIN32
  /* The wrapper is entered by a jump from _MIR_get_wrapper, so RSP%16 == 8.
     The stack is adjusted by a fixed amount: the hook shadow space (0..31) must
     stay free, the saved XMM registers live above it, and the incoming
     argument registers are reloaded from the caller home area (offsets 96..120
     from the frame RSP) before the stack is released.  The tail is a strict
     epilogue: add rsp; pop; pop; tail jump.  */
  static const uint8_t wrap_end[] = {
    /* 0x00 */ 0x4c, 0x89, 0x44, 0x24, 0x18,       /* mov %r8,0x18(%rsp)  */
    /* 0x05 */ 0x4c, 0x89, 0x4c, 0x24, 0x20,       /* mov %r9,0x20(%rsp)  */
    /* 0x0a */ 0x50,                               /* push %rax           */
    /* 0x0b */ 0x55,                               /* push %rbp           */
    /* 0x0c */ 0x48, 0x83, 0xec, 0x48,             /* sub $0x48,%rsp      */
    /* 0x10 */ 0x66, 0x0f, 0xd6, 0x44, 0x24, 0x20, /* movq %xmm0,0x20(%rsp) */
    /* 0x16 */ 0x66, 0x0f, 0xd6, 0x4c, 0x24, 0x28, /* movq %xmm1,0x28(%rsp) */
    /* 0x1c */ 0x66, 0x0f, 0xd6, 0x54, 0x24, 0x30, /* movq %xmm2,0x30(%rsp) */
    /* 0x22 */ 0x66, 0x0f, 0xd6, 0x5c, 0x24, 0x38, /* movq %xmm3,0x38(%rsp) */
    /* 0x28 */ 0x41, 0xff, 0xd2,                   /* call *%r10          */
    /* 0x2b */ 0x49, 0x89, 0xc2,                   /* mov %rax,%r10       */
    /* 0x2e */ 0xf3, 0x0f, 0x7e, 0x44, 0x24, 0x20, /* movq 0x20(%rsp),%xmm0 */
    /* 0x34 */ 0xf3, 0x0f, 0x7e, 0x4c, 0x24, 0x28, /* movq 0x28(%rsp),%xmm1 */
    /* 0x3a */ 0xf3, 0x0f, 0x7e, 0x54, 0x24, 0x30, /* movq 0x30(%rsp),%xmm2 */
    /* 0x40 */ 0xf3, 0x0f, 0x7e, 0x5c, 0x24, 0x38, /* movq 0x38(%rsp),%xmm3 */
    /* 0x46 */ 0x48, 0x8b, 0x4c, 0x24, 0x60,       /* mov 0x60(%rsp),%rcx */
    /* 0x4b */ 0x48, 0x8b, 0x54, 0x24, 0x68,       /* mov 0x68(%rsp),%rdx */
    /* 0x50 */ 0x4c, 0x8b, 0x44, 0x24, 0x70,       /* mov 0x70(%rsp),%r8  */
    /* 0x55 */ 0x4c, 0x8b, 0x4c, 0x24, 0x78,       /* mov 0x78(%rsp),%r9  */
    /* 0x5a */ 0x48, 0x83, 0xc4, 0x48,             /* add $0x48,%rsp      */
    /* 0x5e */ 0x5d,                               /* pop %rbp            */
    /* 0x5f */ 0x58,                               /* pop %rax            */
    /* 0x60 */ 0x49, 0xff, 0xe2,                   /* jmp *%r10           */
  };
  VARR (uint8_t) * code;
  struct mir_win64_unwind_builder unw;
  void *res;

  mir_win64_unwind_init (&unw);
  VARR_CREATE (uint8_t, code, ctx->alloc, 128);
  push_insns (code, wrap_end, sizeof (wrap_end));
  mir_win64_unwind_push_nonvol (&unw, 0x0b, MIR_UNWREG_RAX);
  mir_win64_unwind_push_nonvol (&unw, 0x0c, MIR_UNWREG_RBP);
  mir_win64_unwind_alloc (&unw, 0x10, 0x48);
  res = publish_stub (ctx, code, sizeof (wrap_end), &unw);
  VARR_DESTROY (uint8_t, code);
  return res;
#else
  /* The wrapper stub (_MIR_get_wrapper) pushes rsi and rdi and jumps here, so
     the frame is entered with CFA = rsp+24 and those two registers saved.  The
     stack is aligned dynamically, so from `mov %rax,%rbx` on the frame is
     described through rbx: rbx is rsp before the alignment and CFA = rbx+40
     (the stub's two pushes and rsi/rdi of the entry frame).  The CFA has to go
     back to the rsp form before rbx is restored.  The volatile registers and
     the XMMs need no rules: the epilogue restores them before the tail jump.  */
  static const uint8_t we_push_rax[] = {0x50};                                /* push %rax */
  static const uint8_t we_push_rbx[] = {0x53};                                /* push %rbx */
  static const uint8_t we_set_frame[] = {0x48, 0x89, 0xe0, 0x48, 0x89, 0xc3}; /* rbx = rsp */
  static const uint8_t we_align[] = {
    0x48, 0x83, 0xe0, 0x0f,          /* and    $0xf,%rax */
    0x48, 0x05, 0x80, 0, 0, 0,       /* add    $0x80,%rax */
    0x48, 0x29, 0xc4,                /* sub    %rax,%rsp -- aligned now */
  };
  static const uint8_t we_save_xmm[] = {
    0xf3, 0x0f, 0x7f, 0x04, 0x24,       /* movdqu %xmm0,(%rsp)           */
    0xf3, 0x0f, 0x7f, 0x4c, 0x24, 0x10, /* movdqu %xmm1,0x10(%rsp)       */
    0xf3, 0x0f, 0x7f, 0x54, 0x24, 0x20, /* movdqu %xmm2,0x20(%rsp)       */
    0xf3, 0x0f, 0x7f, 0x5c, 0x24, 0x30, /* movdqu %xmm3,0x30(%rsp)       */
    0xf3, 0x0f, 0x7f, 0x64, 0x24, 0x40, /* movdqu %xmm4,0x40(%rsp)       */
    0xf3, 0x0f, 0x7f, 0x6c, 0x24, 0x50, /* movdqu %xmm5,0x50(%rsp)       */
    0xf3, 0x0f, 0x7f, 0x74, 0x24, 0x60, /* movdqu %xmm6,0x60(%rsp)       */
    0xf3, 0x0f, 0x7f, 0x7c, 0x24, 0x70, /* movdqu %xmm7,0x70(%rsp)       */
  };
  static const uint8_t we_push_args[] = {
    0x41, 0x51, /* push %r9  */
    0x41, 0x50, /* push %r8  */
    0x51,       /* push %rcx */
    0x52,       /* push %rdx */
  };
  static const uint8_t we_call[] = {0x41, 0xff, 0xd2};    /* callq *%r10 */
  static const uint8_t we_get_res[] = {0x49, 0x89, 0xc2}; /* mov %rax,%r10 */
  static const uint8_t we_pop_args[] = {
    0x5a,       /* pop %rdx */
    0x59,       /* pop %rcx */
    0x41, 0x58, /* pop %r8  */
    0x41, 0x59, /* pop %r9  */
  };
  static const uint8_t we_restore_xmm[] = {
    0xf3, 0x0f, 0x6f, 0x04, 0x24,       /* movdqu (%rsp),%xmm0           */
    0xf3, 0x0f, 0x6f, 0x4c, 0x24, 0x10, /* movdqu 0x10(%rsp),%xmm1       */
    0xf3, 0x0f, 0x6f, 0x54, 0x24, 0x20, /* movdqu 0x20(%rsp),%xmm2       */
    0xf3, 0x0f, 0x6f, 0x5c, 0x24, 0x30, /* movdqu 0x30(%rsp),%xmm3       */
    0xf3, 0x0f, 0x6f, 0x64, 0x24, 0x40, /* movdqu 0x40(%rsp),%xmm4       */
    0xf3, 0x0f, 0x6f, 0x6c, 0x24, 0x50, /* movdqu 0x50(%rsp),%xmm5       */
    0xf3, 0x0f, 0x6f, 0x74, 0x24, 0x60, /* movdqu 0x60(%rsp),%xmm6       */
    0xf3, 0x0f, 0x6f, 0x7c, 0x24, 0x70, /* movdqu 0x70(%rsp),%xmm7       */
  };
  static const uint8_t we_restore_sp[] = {0x48, 0x89, 0xdc}; /* mov %rbx,%rsp */
  static const uint8_t we_pop_rbx[] = {0x5b};                /* pop %rbx */
  static const uint8_t we_pop_rax[] = {0x58};                /* pop %rax */
  static const uint8_t we_pop_rdi[] = {0x5f};                /* pop %rdi */
  static const uint8_t we_pop_rsi[] = {0x5e};                /* pop %rsi */
  static const uint8_t we_jmp[] = {0x41, 0xff, 0xe2};        /* jmpq *%r10 */
  VARR (uint8_t) * code;
  void *res;
#if defined(MIR_DWARF_UNWIND)
  VARR (uint8_t) * cfi;
  size_t off = 0;

  /* The rules of the entry state come first: the two pushes of the wrapper stub
     are already executed when the tail jump lands here.  */
  VARR_CREATE (uint8_t, cfi, ctx->alloc, 96);
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 24);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (SI_HARD_REG), -16);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (DI_HARD_REG), -24);
#endif
  VARR_CREATE (uint8_t, code, ctx->alloc, 192);
#if defined(MIR_DWARF_UNWIND)
  push_insns (code, we_push_rax, sizeof (we_push_rax));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (AX_HARD_REG), -32);
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 32);
  push_insns (code, we_push_rbx, sizeof (we_push_rbx));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_offset (cfi, mir_dwarf_cfi_reg (BX_HARD_REG), -40);
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 40);
  push_insns (code, we_set_frame, sizeof (we_set_frame));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_def_cfa (cfi, mir_dwarf_cfi_reg (BX_HARD_REG), 40);
  push_insns (code, we_align, sizeof (we_align));
  push_insns (code, we_save_xmm, sizeof (we_save_xmm));
  push_insns (code, we_push_args, sizeof (we_push_args));
  push_insns (code, we_call, sizeof (we_call));
  push_insns (code, we_get_res, sizeof (we_get_res));
  push_insns (code, we_pop_args, sizeof (we_pop_args));
  push_insns (code, we_restore_xmm, sizeof (we_restore_xmm));
  push_insns (code, we_restore_sp, sizeof (we_restore_sp));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 40);
  push_insns (code, we_pop_rbx, sizeof (we_pop_rbx));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (BX_HARD_REG));
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 32);
  push_insns (code, we_pop_rax, sizeof (we_pop_rax));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (AX_HARD_REG));
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 24);
  push_insns (code, we_pop_rdi, sizeof (we_pop_rdi));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (DI_HARD_REG));
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 16);
  push_insns (code, we_pop_rsi, sizeof (we_pop_rsi));
  mir_dwarf_cfi_advance (cfi, off, VARR_LENGTH (uint8_t, code));
  off = VARR_LENGTH (uint8_t, code);
  mir_dwarf_cfi_restore (cfi, mir_dwarf_cfi_reg (SI_HARD_REG));
  mir_dwarf_cfi_def_cfa (cfi, MIR_DWARF_RSP, 8);
  push_insns (code, we_jmp, sizeof (we_jmp));
  res = publish_stub_dwarf (ctx, code, VARR_LENGTH (uint8_t, code), cfi);
  VARR_DESTROY (uint8_t, cfi);
#else
  push_insns (code, we_push_rax, sizeof (we_push_rax));
  push_insns (code, we_push_rbx, sizeof (we_push_rbx));
  push_insns (code, we_set_frame, sizeof (we_set_frame));
  push_insns (code, we_align, sizeof (we_align));
  push_insns (code, we_save_xmm, sizeof (we_save_xmm));
  push_insns (code, we_push_args, sizeof (we_push_args));
  push_insns (code, we_call, sizeof (we_call));
  push_insns (code, we_get_res, sizeof (we_get_res));
  push_insns (code, we_pop_args, sizeof (we_pop_args));
  push_insns (code, we_restore_xmm, sizeof (we_restore_xmm));
  push_insns (code, we_restore_sp, sizeof (we_restore_sp));
  push_insns (code, we_pop_rbx, sizeof (we_pop_rbx));
  push_insns (code, we_pop_rax, sizeof (we_pop_rax));
  push_insns (code, we_pop_rdi, sizeof (we_pop_rdi));
  push_insns (code, we_pop_rsi, sizeof (we_pop_rsi));
  push_insns (code, we_jmp, sizeof (we_jmp));
  res = publish_stub (ctx, code, 0, NULL);
#endif
  VARR_DESTROY (uint8_t, code);
  return res;
#endif
}

#if defined(MIR_DWARF_UNWIND)
/* Layout of a Linux bb thunk (the literal with the wrapper address follows the
   executable code):

   0x00: movabs r10,<bb_version>                    10 bytes
   0x0a: sub rsp,<stack_adjust>                      7 bytes (imm32: 128 and 136
                                                            do not fit imm8)
   0x11: call *<wrapper>(%rip)                       6 bytes
   0x17: add rsp,<stack_adjust>                      7 bytes
   0x1e: jmp r10                                     3 bytes (a plain jmp)
   0x21: <padding to 0x28>, <wrapper address>

   The thunk calls the shared wrapper, so the wrapper has a real return address
   and describes its own frame; the reservation keeps the 128-byte red zone of
   the enclosing function free for the wrapper.  */
#define BB_DWARF_THUNK_CODE_LEN 0x21
#define BB_DWARF_THUNK_LITERAL 0x28
void *_MIR_get_bb_thunk_dwarf (MIR_context_t ctx, void *bb_version, void *handler,
                               size_t stack_adjust, int describe_p, const uint8_t *inherited,
                               size_t inherited_len, const uint8_t *adjusted,
                               size_t adjusted_len) {
  uint8_t code[BB_DWARF_THUNK_LITERAL + 8];
  struct _MIR_code_unwind uw[3];
  int32_t disp;
  size_t n = 0;

  /* 136 keeps the call 16-byte aligned when the enclosing RSP is 8 modulo 16
     (a function entry and the body of a real leaf), 128 when it is 16-byte
     aligned (the body of any function with a prologue); both leave the 128-byte
     red zone of the enclosing frame untouched.  */
  mir_assert (stack_adjust == 128 || stack_adjust == 136);
  memset (code, 0, sizeof (code));
  code[0] = 0x49; /* movabs r10,<bb_version> */
  code[1] = 0xba;
  memcpy (code + 2, &bb_version, sizeof (void *));
  code[10] = 0x48; /* sub rsp,<stack_adjust> */
  code[11] = 0x81;
  code[12] = 0xec;
  disp = (int32_t) stack_adjust;
  memcpy (code + 13, &disp, sizeof (int32_t));
  code[17] = 0xff; /* call *<wrapper>(%rip) */
  code[18] = 0x15;
  memcpy (code + BB_DWARF_THUNK_LITERAL, &handler, sizeof (void *));
  /* The call is relative to the end of the call instruction. */
  disp = (int32_t) (BB_DWARF_THUNK_LITERAL - 0x17);
  memcpy (code + 19, &disp, sizeof (int32_t));
  code[23] = 0x48; /* add rsp,<stack_adjust> */
  code[24] = 0x81;
  code[25] = 0xc4;
  disp = (int32_t) stack_adjust;
  memcpy (code + 26, &disp, sizeof (int32_t));
  code[30] = 0x41; /* jmp r10 */
  code[31] = 0xff;
  code[32] = 0xe2;
  if (!describe_p) /* a jcall/jret continuation: no standard call chain entries */
    return _MIR_publish_code (ctx, code, sizeof (code));
  /* Three ranges: the thunk stack is not adjusted yet, adjusted (the call and
     everything the wrapper does), and the continuation after the release.  */
  if (inherited == NULL) inherited_len = 0;
  if (adjusted == NULL) adjusted_len = 0;
  uw[n].begin = 0;
  uw[n].end = 0x11;
  uw[n].info = inherited;
  uw[n].info_len = inherited_len;
  n++;
  uw[n].begin = 0x11;
  uw[n].end = 0x1e;
  uw[n].info = adjusted;
  uw[n].info_len = adjusted_len;
  n++;
  uw[n].begin = 0x1e;
  uw[n].end = BB_DWARF_THUNK_CODE_LEN;
  uw[n].info = inherited;
  uw[n].info_len = inherited_len;
  n++;
  return _MIR_publish_code_with_unwind (ctx, code, sizeof (code), n, uw);
}
#elif !defined(MIR_WIN64_UNWIND)
/* r10=<bb_version>; jump rex32  ??? mutex free */
void *_MIR_get_bb_thunk (MIR_context_t ctx, void *bb_version, void *handler) {
  void *res;
  int32_t disp;
  static const uint8_t pattern[] = {
    0x49, 0xba, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x0: movabsq 0, r10 */
    0xe9, 0,    0, 0, 0,                /* 0xa: jmpq <rel32> */
  };
  res = _MIR_publish_code (ctx, pattern, sizeof (pattern));
  _MIR_update_code (ctx, res, 1, 2, bb_version);
  disp = (int32_t) ((char *) handler - ((char *) res + sizeof (pattern)));
  _MIR_change_code (ctx, (uint8_t *) res + 11, (uint8_t *) &disp, 4);
  return res;
}
#else
/* Layout of a Windows x64 bb thunk (the literal with the wrapper address
   follows the executable code):

   0x00: movabs r10,<bb_version>     10 bytes
   0x0a: sub rsp,<adjust>             4 bytes
   0x0e: call *<wrapper>(rip)         6 bytes
   0x14: add rsp,<adjust>             4 bytes
   0x18: nop                          1 byte
   0x19: jmp r10                      3 bytes (a plain jmp: not an enclosing tail)
   0x1c: <padding to 16>, <wrapper address>                               */
#define BB_THUNK_CODE_LEN 0x1c
#define BB_THUNK_LITERAL 0x20
static void *make_bb_thunk (MIR_context_t ctx, void *bb_version, void *handler,
                            size_t stack_adjust, const uint8_t *inherited, size_t inherited_len,
                            const uint8_t *adjusted, size_t adjusted_len) {
  uint8_t code[BB_THUNK_LITERAL + 8];
  uint8_t info[MIR_WIN64_UNWIND_MAX_BYTES];
  struct _MIR_code_unwind uw[3];
  struct mir_win64_unwind_builder b;
  size_t n = 0, info_len = 0;
  int32_t disp;
  uint8_t *res;

  mir_assert (stack_adjust == 32 || stack_adjust == 40);
  memset (code, 0, sizeof (code));
  code[0] = 0x49; /* movabs r10,<bb_version> */
  code[1] = 0xba;
  memcpy (code + 2, &bb_version, sizeof (void *));
  code[10] = 0x48; /* sub rsp,<stack_adjust> */
  code[11] = 0x83;
  code[12] = 0xec;
  code[13] = (uint8_t) stack_adjust;
  code[14] = 0xff; /* call *<wrapper>(rip) */
  code[15] = 0x15;
  code[20] = 0x48; /* add rsp,<stack_adjust> */
  code[21] = 0x83;
  code[22] = 0xc4;
  code[23] = (uint8_t) stack_adjust;
  code[0x18] = 0x90; /* nop */
  code[0x19] = 0x41; /* jmp r10 */
  code[0x1a] = 0xff;
  code[0x1b] = 0xe2;
  memcpy (code + BB_THUNK_LITERAL, &handler, sizeof (void *));
  /* The call is relative to the end of the call instruction. */
  disp = (int32_t) (BB_THUNK_LITERAL - 0x14);
  memcpy (code + 16, &disp, sizeof (int32_t));
  if (inherited == NULL) { /* entry thunk: the stack adjustment alone */
    mir_win64_unwind_init (&b);
    mir_win64_unwind_alloc (&b, 0, stack_adjust);
    if ((info_len = mir_win64_unwind_encode (&b, 1, info, sizeof (info))) == 0) {
      MIR_get_error_func (ctx) (MIR_wrong_param_value_error,
                                "cannot encode Windows x64 unwind information");
      return NULL;
    }
    adjusted = info;
    adjusted_len = info_len;
  }
  if (adjusted != NULL) { /* from the call on: the sub has been executed then */
    uw[n].begin = 0x0e;
    uw[n].end = 0x18; /* past the add: the stack is released there */
    uw[n].info = adjusted;
    uw[n].info_len = adjusted_len;
    n++;
  }
  if (inherited != NULL) {
    uw[n].begin = 0; /* up to the call: the thunk stack is not adjusted yet */
    uw[n].end = 0x0e;
    uw[n].info = inherited;
    uw[n].info_len = inherited_len;
    n++;
    uw[n].begin = 0x18;
    uw[n].end = BB_THUNK_CODE_LEN;
    uw[n].info = inherited;
    uw[n].info_len = inherited_len;
    n++;
  }
  if (n != 0) { /* the ranges have to be given in the increasing order */
    struct _MIR_code_unwind tmp;
    for (size_t i = 0; i + 1 < n; i++)
      for (size_t j = i + 1; j < n; j++)
        if (uw[j].begin < uw[i].begin) {
          tmp = uw[i];
          uw[i] = uw[j];
          uw[j] = tmp;
        }
    res = _MIR_publish_code_with_unwind (ctx, code, sizeof (code), n, uw);
  } else {
    res = _MIR_publish_code (ctx, code, sizeof (code));
  }
  return res;
}

void *_MIR_get_bb_thunk_win64 (MIR_context_t ctx, void *bb_version, void *handler,
                               size_t stack_adjust, const uint8_t *inherited, size_t inherited_len,
                               const uint8_t *adjusted, size_t adjusted_len) {
  return make_bb_thunk (ctx, bb_version, handler, stack_adjust, inherited, inherited_len, adjusted,
                        adjusted_len);
}

/* A Windows x64 bb thunk always has to adjust the stack for the wrapper call,
   so the generic entry cannot be used for it.  */
void *_MIR_get_bb_thunk (MIR_context_t ctx, void *bb_version, void *handler) {
  return make_bb_thunk (ctx, bb_version, handler, 40, NULL, 0, NULL, 0);
}
#endif

/* change to jmp rex32(to) or, when the target is out of the rel32 range, to
   movabs r11,to; jmp r11.  The long form overwrites exactly 13 bytes, which ends
   inside the thunk header on every target, so the tail which the wrapper returns
   into stays intact and merely becomes unreachable:
     Linux bb thunk: `movabs r10` + the `sub` opcode (its imm32 and the call at
                     0x11 and the continuation at 0x17/0x1e survive);
     Windows thunk:  byte 13 is the imm8 of `sub rsp,<adjust>` (call at 0x0e,
                     continuation at 0x18/0x19 survive);
     legacy thunk:   `movabs r10` and 3 bytes of the `jmp rel32`.
   Only the header is touched: neither the allocation immediates nor the return
   continuation of any of these thunks are overwritten.  */
void _MIR_replace_bb_thunk (MIR_context_t ctx, void *thunk, void *to) {
  int64_t off = (char *) to - ((char *) thunk + 5);
  if (off < INT32_MIN || off > INT32_MAX) {
    static const uint8_t long_jmp[] = {
      0x49, 0xbb, 0, 0, 0, 0, 0, 0, 0, 0, /* movabsq to,%r11 */
      0x41, 0xff, 0xe3,                   /* jmpq   *%r11 */
    };
    uint8_t pattern[sizeof (long_jmp)];

    memcpy (pattern, long_jmp, sizeof (long_jmp));
    memcpy (pattern + 2, &to, sizeof (void *));
    _MIR_change_code (ctx, (uint8_t *) thunk, pattern, sizeof (long_jmp));
    return;
  }
  {
    uint8_t op = 0xe9; /* jmpq */
    int32_t disp = (int32_t) off;

    _MIR_change_code (ctx, (uint8_t *) thunk, &op, 1); /* jmpq <disp32> */
    _MIR_change_code (ctx, (uint8_t *) thunk + 1, (uint8_t *) &disp, 4);
  }
}

#if !defined(MIR_WIN64_UNWIND) && !defined(MIR_DWARF_UNWIND)
/* The legacy SysV wrapper: the bb thunk TAIL JUMPS into it (see
   _MIR_get_bb_thunk), so it has no return address of its own: it restores the
   hooked function's stack and continues with a jump.  */
static const uint8_t save_pat2[] = {
  0x48, 0x81, 0xec, 0x80, 0,    0,    0, /*sub    $0x80,%rsp		   */
  0xf3, 0x0f, 0x7f, 0x04, 0x24,          /*movdqu %xmm0,(%rsp)		   */
  0xf3, 0x0f, 0x7f, 0x4c, 0x24, 0x10,    /*movdqu %xmm1,0x10(%rsp)	   */
  0xf3, 0x0f, 0x7f, 0x54, 0x24, 0x20,    /*movdqu %xmm2,0x20(%rsp)	   */
  0xf3, 0x0f, 0x7f, 0x5c, 0x24, 0x30,    /*movdqu %xmm3,0x30(%rsp)	   */
  0xf3, 0x0f, 0x7f, 0x64, 0x24, 0x40,    /*movdqu %xmm4,0x40(%rsp)	   */
  0xf3, 0x0f, 0x7f, 0x6c, 0x24, 0x50,    /*movdqu %xmm5,0x50(%rsp)	   */
  0xf3, 0x0f, 0x7f, 0x74, 0x24, 0x60,    /*movdqu %xmm6,0x60(%rsp)	   */
  0xf3, 0x0f, 0x7f, 0x7c, 0x24, 0x70,    /*movdqu %xmm7,0x70(%rsp)	   */
  0x41, 0x51,                            /*push   %r9			   */
  0x41, 0x50,                            /*push   %r8			   */
  0x51,                                  /*push   %rcx			   */
  0x52,                                  /*push   %rdx			   */
  0x56,                                  /*push   %rsi			   */
  0x57,                                  /*push   %rdi			   */
  0x50,                                  /*push   %rax			   */
  0x41, 0x53,                            /*push   %r11			   */
};

static const uint8_t restore_pat2[] = {
  0x41, 0x5b, /*pop    %r11			   */
  0x58,       /*pop    %rax			   */
  0x5f,                                  /*pop    %rdi			   */
  0x5e,                                  /*pop    %rsi			   */
  0x5a,                                  /*pop    %rdx			   */
  0x59,                                  /*pop    %rcx			   */
  0x41, 0x58,                            /*pop    %r8			   */
  0x41, 0x59,                            /*pop    %r9			   */
  0xf3, 0x0f, 0x6f, 0x04, 0x24,          /*movdqu (%rsp),%xmm0		   */
  0xf3, 0x0f, 0x6f, 0x4c, 0x24, 0x10,    /*movdqu 0x10(%rsp),%xmm1	   */
  0xf3, 0x0f, 0x6f, 0x54, 0x24, 0x20,    /*movdqu 0x20(%rsp),%xmm2	   */
  0xf3, 0x0f, 0x6f, 0x5c, 0x24, 0x30,    /*movdqu 0x30(%rsp),%xmm3	   */
  0xf3, 0x0f, 0x6f, 0x64, 0x24, 0x40,    /*movdqu 0x40(%rsp),%xmm4	   */
  0xf3, 0x0f, 0x6f, 0x6c, 0x24, 0x50,    /*movdqu 0x50(%rsp),%xmm5	   */
  0xf3, 0x0f, 0x6f, 0x74, 0x24, 0x60,    /*movdqu 0x60(%rsp),%xmm6	   */
  0xf3, 0x0f, 0x6f, 0x7c, 0x24, 0x70,    /*movdqu 0x70(%rsp),%xmm7	   */
  0x48, 0x81, 0xc4, 0x80, 0,    0,    0, /*add    $0x80,%rsp		   */
};
#endif

#if defined(MIR_DWARF_UNWIND)
/* The bb wrapper of a Linux build is CALLED by the bb thunk: it has a real
   return address, saves the volatile registers, calls the hook and returns to
   the thunk, which then releases its red zone reservation.  Every piece is
   emitted separately so that every RSP changing instruction gets its own call
   frame information row.  */
static const uint32_t bbw_xmm_area = 0x80; /* must match bbw_sub_sp */
static const uint8_t bbw_sub_sp[] = {0x48, 0x81, 0xec, 0x80, 0, 0, 0}; /* sub $0x80,%rsp */
static const uint8_t bbw_save_xmm[] = {
  0xf3, 0x0f, 0x7f, 0x04, 0x24,       /* movdqu %xmm0,(%rsp)       */
  0xf3, 0x0f, 0x7f, 0x4c, 0x24, 0x10, /* movdqu %xmm1,0x10(%rsp)   */
  0xf3, 0x0f, 0x7f, 0x54, 0x24, 0x20, /* movdqu %xmm2,0x20(%rsp)   */
  0xf3, 0x0f, 0x7f, 0x5c, 0x24, 0x30, /* movdqu %xmm3,0x30(%rsp)   */
  0xf3, 0x0f, 0x7f, 0x64, 0x24, 0x40, /* movdqu %xmm4,0x40(%rsp)   */
  0xf3, 0x0f, 0x7f, 0x6c, 0x24, 0x50, /* movdqu %xmm5,0x50(%rsp)   */
  0xf3, 0x0f, 0x7f, 0x74, 0x24, 0x60, /* movdqu %xmm6,0x60(%rsp)   */
  0xf3, 0x0f, 0x7f, 0x7c, 0x24, 0x70, /* movdqu %xmm7,0x70(%rsp)   */
};
static const uint8_t bbw_push_r9[] = {0x41, 0x51};   /* push %r9  */
static const uint8_t bbw_push_r8[] = {0x41, 0x50};   /* push %r8  */
static const uint8_t bbw_push_rcx[] = {0x51};        /* push %rcx */
static const uint8_t bbw_push_rdx[] = {0x52};        /* push %rdx */
static const uint8_t bbw_push_rsi[] = {0x56};        /* push %rsi */
static const uint8_t bbw_push_rdi[] = {0x57};        /* push %rdi */
static const uint8_t bbw_push_rax[] = {0x50};        /* push %rax */
static const uint8_t bbw_push_r11[] = {0x41, 0x53};  /* push %r11 */
/* The wrapper is entered by the CALL of the bb thunk, i.e. with RSP 8 modulo
   16.  The XMM area is 0x80 bytes and the eight pushes move RSP by 64 bytes, so
   a further 8 bytes make the hook call 16-byte aligned.  (The imm8 forms are
   enough here; the thunk reservations need imm32, see
   _MIR_get_bb_thunk_dwarf.)  */
static const uint32_t bbw_align = 8; /* the sub/add of the alignment */
static const uint8_t bbw_pre[] = {
  0x4c, 0x89, 0xd6,                         /* mov %r10,%rsi */
  0x48, 0xbf, 0,    0,    0, 0, 0, 0, 0, 0, /* movabs data,%rdi */
  0x49, 0xba, 0,    0,    0, 0, 0, 0, 0, 0, /* movabs <hook_address>,%r10 */
};
static const uint8_t bbw_sub_align[] = {0x48, 0x83, 0xec, 0x08}; /* sub $8,%rsp */
static const uint8_t bbw_call[] = {0x41, 0xff, 0xd2};            /* callq *%r10 */
static const uint8_t bbw_add_align[] = {0x48, 0x83, 0xc4, 0x08}; /* add $8,%rsp */
static const uint8_t bbw_get_res[] = {0x49, 0x89, 0xc2};         /* mov %rax,%r10 */
static const uint8_t bbw_pop_r11[] = {0x41, 0x5b};               /* pop %r11 */
static const uint8_t bbw_pop_rax[] = {0x58};                     /* pop %rax */
static const uint8_t bbw_pop_rdi[] = {0x5f};                     /* pop %rdi */
static const uint8_t bbw_pop_rsi[] = {0x5e};                     /* pop %rsi */
static const uint8_t bbw_pop_rdx[] = {0x5a};                     /* pop %rdx */
static const uint8_t bbw_pop_rcx[] = {0x59};                     /* pop %rcx */
static const uint8_t bbw_pop_r8[] = {0x41, 0x58};                /* pop %r8  */
static const uint8_t bbw_pop_r9[] = {0x41, 0x59};                /* pop %r9  */
static const uint8_t bbw_restore_xmm[] = {
  0xf3, 0x0f, 0x6f, 0x04, 0x24,       /* movdqu (%rsp),%xmm0       */
  0xf3, 0x0f, 0x6f, 0x4c, 0x24, 0x10, /* movdqu 0x10(%rsp),%xmm1   */
  0xf3, 0x0f, 0x6f, 0x54, 0x24, 0x20, /* movdqu 0x20(%rsp),%xmm2   */
  0xf3, 0x0f, 0x6f, 0x5c, 0x24, 0x30, /* movdqu 0x30(%rsp),%xmm3   */
  0xf3, 0x0f, 0x6f, 0x64, 0x24, 0x40, /* movdqu 0x40(%rsp),%xmm4   */
  0xf3, 0x0f, 0x6f, 0x6c, 0x24, 0x50, /* movdqu 0x50(%rsp),%xmm5   */
  0xf3, 0x0f, 0x6f, 0x74, 0x24, 0x60, /* movdqu 0x60(%rsp),%xmm6   */
  0xf3, 0x0f, 0x6f, 0x7c, 0x24, 0x70, /* movdqu 0x70(%rsp),%xmm7   */
};
static const uint8_t bbw_add_sp[] = {0x48, 0x81, 0xc4, 0x80, 0, 0, 0}; /* add $0x80,%rsp */
static const uint8_t bbw_ret[] = {0xc3};
#endif

/* Save all clobbered regs but r10; r10 = call hook_address (data, r10); restore
   regs; continue with r10.  r10 is a generator temp reg which is not used across
   bb borders.  */
void *_MIR_get_bb_wrapper (MIR_context_t ctx, void *data, void *hook_address) {
#if defined(MIR_WIN64_UNWIND)
  /* The Windows x64 wrapper is entered by CALL (see _MIR_get_bb_thunk_win64) and
     leaves by RET, so it must follow the Win64 conventions itself: fixed stack
     frame, the hook shadow space kept free of saved registers, and all volatile
     argument registers restored before returning to the thunk.  */
  static const uint8_t wrap_end[] = {
    /* 0x00 */ 0x48, 0x81, 0xec, 0xb8, 0x00, 0x00, 0x00, /* sub $0xb8,%rsp      */
    /* 0x07 */ 0x0f, 0x11, 0x44, 0x24, 0x20,             /* movups %xmm0,0x20(%rsp) */
    /* 0x0c */ 0x0f, 0x11, 0x4c, 0x24, 0x30,             /* movups %xmm1,0x30(%rsp) */
    /* 0x11 */ 0x0f, 0x11, 0x54, 0x24, 0x40,             /* movups %xmm2,0x40(%rsp) */
    /* 0x16 */ 0x0f, 0x11, 0x5c, 0x24, 0x50,             /* movups %xmm3,0x50(%rsp) */
    /* 0x1b */ 0x0f, 0x11, 0x64, 0x24, 0x60,             /* movups %xmm4,0x60(%rsp) */
    /* 0x20 */ 0x0f, 0x11, 0x6c, 0x24, 0x70,             /* movups %xmm5,0x70(%rsp) */
    /* 0x25 */ 0x48, 0x89, 0x8c, 0x24, 0x80, 0x00, 0x00, 0x00, /* mov %rcx,0x80(%rsp) */
    /* 0x2d */ 0x48, 0x89, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00, /* mov %rdx,0x88(%rsp) */
    /* 0x35 */ 0x4c, 0x89, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, /* mov %r8,0x90(%rsp) */
    /* 0x3d */ 0x4c, 0x89, 0x8c, 0x24, 0x98, 0x00, 0x00, 0x00, /* mov %r9,0x98(%rsp) */
    /* 0x45 */ 0x48, 0x89, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, /* mov %rax,0xa0(%rsp) */
    /* 0x4d */ 0x4c, 0x89, 0x9c, 0x24, 0xa8, 0x00, 0x00, 0x00, /* mov %r11,0xa8(%rsp) */
    /* 0x55 */ 0x48, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0,        /* movabs data,%rcx    */
    /* 0x5f */ 0x4c, 0x89, 0xd2,                         /* mov %r10,%rdx       */
    /* 0x62 */ 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,        /* movabs hook,%rax    */
    /* 0x6c */ 0xff, 0xd0,                               /* call *%rax          */
    /* 0x6e */ 0x49, 0x89, 0xc2,                         /* mov %rax,%r10       */
    /* 0x71 */ 0x4c, 0x8b, 0x9c, 0x24, 0xa8, 0x00, 0x00, 0x00, /* mov 0xa8(%rsp),%r11 */
    /* 0x79 */ 0x48, 0x8b, 0x84, 0x24, 0xa0, 0x00, 0x00, 0x00, /* mov 0xa0(%rsp),%rax */
    /* 0x81 */ 0x4c, 0x8b, 0x8c, 0x24, 0x98, 0x00, 0x00, 0x00, /* mov 0x98(%rsp),%r9  */
    /* 0x89 */ 0x4c, 0x8b, 0x84, 0x24, 0x90, 0x00, 0x00, 0x00, /* mov 0x90(%rsp),%r8  */
    /* 0x91 */ 0x48, 0x8b, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00, /* mov 0x88(%rsp),%rdx */
    /* 0x99 */ 0x48, 0x8b, 0x8c, 0x24, 0x80, 0x00, 0x00, 0x00, /* mov 0x80(%rsp),%rcx */
    /* 0xa1 */ 0x0f, 0x28, 0x6c, 0x24, 0x70,             /* movaps 0x70(%rsp),%xmm5 */
    /* 0xa6 */ 0x0f, 0x28, 0x64, 0x24, 0x60,             /* movaps 0x60(%rsp),%xmm4 */
    /* 0xab */ 0x0f, 0x28, 0x5c, 0x24, 0x50,             /* movaps 0x50(%rsp),%xmm3 */
    /* 0xb0 */ 0x0f, 0x28, 0x54, 0x24, 0x40,             /* movaps 0x40(%rsp),%xmm2 */
    /* 0xb5 */ 0x0f, 0x28, 0x4c, 0x24, 0x30,             /* movaps 0x30(%rsp),%xmm1 */
    /* 0xba */ 0x0f, 0x28, 0x44, 0x24, 0x20,             /* movaps 0x20(%rsp),%xmm0 */
    /* 0xbf */ 0x48, 0x81, 0xc4, 0xb8, 0x00, 0x00, 0x00, /* add $0xb8,%rsp      */
    /* 0xc6 */ 0xc3,                                     /* ret                 */
  };
  static const uint32_t data_offset = 0x57, hook_offset = 0x64;
  uint8_t *addr;
  VARR (uint8_t) * code;
  struct mir_win64_unwind_builder unw;
  void *res;

  mir_win64_unwind_init (&unw);
  VARR_CREATE (uint8_t, code, ctx->alloc, 256);
  addr = push_insns (code, wrap_end, sizeof (wrap_end));
  memcpy (addr + data_offset, &data, sizeof (void *));
  memcpy (addr + hook_offset, &hook_address, sizeof (void *));
  mir_win64_unwind_alloc (&unw, 0x07, 0xb8);
  res = publish_stub (ctx, code, sizeof (wrap_end), &unw);
  VARR_DESTROY (uint8_t, code);
  return res;
#elif defined(MIR_DWARF_UNWIND)
  /* The wrapper is entered by the CALL of the bb thunk, so it has a real return
     address and a normal frame of its own: CFA = rsp+8 at the entry, the XMM
     save area and the eight pushed volatile registers below it.  The hook call
     is 16-byte aligned by the fixed sub/add of bbw_align, the result goes to r10
     and RET returns to the thunk, which then releases its red zone reservation
     and jumps to the bb fragment.  */
  uint8_t *addr;
  VARR (uint8_t) * code;
  VARR (uint8_t) * cfi;
  void *res;
  size_t cfi_off = 0;
  uint64_t cfa = 8; /* CFA = rsp+8 at the entry */

  VARR_CREATE (uint8_t, cfi, ctx->alloc, 128);
  VARR_CREATE (uint8_t, code, ctx->alloc, 256);
  push_insns (code, bbw_sub_sp, sizeof (bbw_sub_sp));
  cfa += bbw_xmm_area;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_save_xmm, sizeof (bbw_save_xmm)); /* the stores move nothing */
  push_insns (code, bbw_push_r9, sizeof (bbw_push_r9));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_r8, sizeof (bbw_push_r8));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_rcx, sizeof (bbw_push_rcx));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_rdx, sizeof (bbw_push_rdx));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_rsi, sizeof (bbw_push_rsi));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_rdi, sizeof (bbw_push_rdi));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_rax, sizeof (bbw_push_rax));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_push_r11, sizeof (bbw_push_r11));
  cfa += 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  addr = push_insns (code, bbw_pre, sizeof (bbw_pre));
  {
    const size_t data_offset = 5, hook_offset = 15; /* the two movabs immediates */

    memcpy (addr + data_offset, &data, sizeof (void *));
    memcpy (addr + hook_offset, &hook_address, sizeof (void *));
  }
  push_insns (code, bbw_sub_align, sizeof (bbw_sub_align));
  cfa += bbw_align;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_call, sizeof (bbw_call));
  push_insns (code, bbw_add_align, sizeof (bbw_add_align));
  cfa -= bbw_align;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_get_res, sizeof (bbw_get_res));
  push_insns (code, bbw_pop_r11, sizeof (bbw_pop_r11));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_rax, sizeof (bbw_pop_rax));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_rdi, sizeof (bbw_pop_rdi));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_rsi, sizeof (bbw_pop_rsi));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_rdx, sizeof (bbw_pop_rdx));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_rcx, sizeof (bbw_pop_rcx));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_r8, sizeof (bbw_pop_r8));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_pop_r9, sizeof (bbw_pop_r9));
  cfa -= 8;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_restore_xmm, sizeof (bbw_restore_xmm)); /* nothing moves */
  push_insns (code, bbw_add_sp, sizeof (bbw_add_sp));
  cfa -= bbw_xmm_area;
  dwarf_row (cfi, &cfi_off, VARR_LENGTH (uint8_t, code), cfa);
  push_insns (code, bbw_ret, sizeof (bbw_ret));
  res = publish_stub_dwarf (ctx, code, VARR_LENGTH (uint8_t, code), cfi);
  VARR_DESTROY (uint8_t, cfi);
  VARR_DESTROY (uint8_t, code);
  return res;
#else
  /* The legacy SysV wrapper for the tail jumping bb thunk: it is entered by a
     jump, so it must return with a jump to the address the hook returned.  */
  static const uint8_t wrap_end[] = {
    0x41, 0xff, 0xe2, /*jmpq   *%r10			   */
  };
  static const uint8_t call_pat[] = {
    0x4c, 0x89, 0xd6,                         /* mov %r10,%rsi */
    0x48, 0xbf, 0,    0,    0, 0, 0, 0, 0, 0, /* movabs data,%rdi */
    0x49, 0xba, 0,    0,    0, 0, 0, 0, 0, 0, /* movabs <hook_address>,%r10 */
    0x48, 0x89, 0xe2,                         /* mov    %rsp,%rdx */
    0x48, 0x83, 0xe2, 0x0f,                   /* and    $0xf,%rdx */
    0x74, 0x07,                               /* je     10 <l> */
    0x52,                                     /* push   %rdx */
    0x41, 0xff, 0xd2,                         /* callq  *%r10 */
    0x5a,                                     /* pop    %rdx */
    0xeb, 0x03,                               /* jmp    13 <l2> */
    0x41, 0xff, 0xd2,                         /* l: callq  *%r10 */
    0x49, 0x89, 0xc2,                         /* l2:mov %rax,%r10 */
  };
  const size_t data_offset = 5, hook_offset = 15;
  uint8_t *addr;
  VARR (uint8_t) * code;
  void *res;

  VARR_CREATE (uint8_t, code, ctx->alloc, 128);
  push_insns (code, save_pat2, sizeof (save_pat2));
  addr = push_insns (code, call_pat, sizeof (call_pat));
  memcpy (addr + data_offset, &data, sizeof (void *));
  memcpy (addr + hook_offset, &hook_address, sizeof (void *));
  push_insns (code, restore_pat2, sizeof (restore_pat2));
  push_insns (code, wrap_end, sizeof (wrap_end));
  res = _MIR_publish_code (ctx, VARR_ADDR (uint8_t, code), VARR_LENGTH (uint8_t, code));
  VARR_DESTROY (uint8_t, code);
  return res;
#endif
}
