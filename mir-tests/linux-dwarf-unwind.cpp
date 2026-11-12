/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   Linux x86-64 JIT stack unwinding tests.  Every scenario generates MIR code,
   calls it from a C++ host, and walks the real system stack from a native probe
   with _Unwind_Backtrace.  The checks are about observable behaviour only:
   exception delivery into a host catch, the RAII destructor count, unwound
   return addresses (asserted by code range, not by symbol names), the restored
   SysV non-volatile registers, the red zone, and the frame information lookup
   after the context is destroyed.

   Two checks encode libgcc's conventions on purpose (the feature is libgcc_s
   based and the documented one): `_Unwind_GetCFA` in a trace callback reports
   the CFA computed while unwinding *into* the current frame, so the CFA of frame
   k is in `frames[k + 1].cfa`; and a frame entered by a jump (a bb thunk) is
   merged with the frame it was jumped from.

   Command line (the first one or more of):
     full | lazy | bb     the three code generation modes, both optimize levels
     hook                 the wrapper and the bb wrapper (generation hooks)
     thunk                the bb thunk protocol, the red zone, the far patch
     interp               the interpreter bridge (interp shim and ff call)
     leaf                 the frame information of leaf functions
     growth               many functions, several holders, context recreation
     allocator            a custom code allocator (unregistration before unmap)
   With no arguments everything is run.  */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <unwind.h>

extern "C" {
#include "../mir.h"
#include "../mir-gen.h"
#include "../c2mir/c2mir.h"
}

#include <sys/mman.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "the Linux x86-64 JIT frame information tests need Linux x86-64 LP64"
#endif
#ifndef MAP_FIXED_NOREPLACE /* glibc before 2.28 */
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* libgcc_s: the frame information of a PC (the interface the unwinder uses
   internally).  */
struct dwarf_eh_bases {
  void *tbase, *dbase, *func;
};
extern "C" void *_Unwind_Find_FDE (void *pc, struct dwarf_eh_bases *bases);

/* ---------- the frame information of leaf functions ---------- */

static size_t uleb_read (const unsigned char *p, uint64_t *v) {
  uint64_t r = 0;
  size_t n = 0;

  for (;;) {
    unsigned char b = p[n++];

    r |= (uint64_t) (b & 0x7f) << (7 * (n - 1));
    if ((b & 0x80) == 0) break;
  }
  *v = r;
  return n;
}

struct fde_info {
  uintptr_t start, end;
  const unsigned char *insns;
  size_t insns_len;
};

/* Parse the FDE of PC.  The layout is the one mir-dwarf-cfi.h emits: an 8-byte
   absolute address, an 8-byte range, a zero augmentation length and the
   instruction stream.  */
static int fde_get (void *pc, struct fde_info *fi) {
  struct dwarf_eh_bases bases;
  const unsigned char *f = (const unsigned char *) _Unwind_Find_FDE (pc, &bases);
  uint32_t len;
  uint64_t aug;
  size_t n;

  if (f == NULL) return 0;
  memcpy (&len, f, sizeof (len));
  memcpy (&fi->start, f + 8, sizeof (fi->start));
  memcpy (&fi->end, f + 16, sizeof (fi->end));
  fi->end += fi->start;
  n = uleb_read (f + 24, &aug);
  fi->insns = f + 24 + n + aug;
  fi->insns_len = len + 4 - (size_t) (fi->insns - f);
  return 1;
}

static int fde_stream_is_default (const struct fde_info *fi) {
  size_t i;

  for (i = 0; i < fi->insns_len; i++)
    if (fi->insns[i] != 0) return 0; /* only DW_CFA_nop padding */
  return 1;
}

/* The stream of FI starts with PREFIX and only DW_CFA_nop padding follows.  The
   reported length includes the padding the encoder adds to keep the entries at
   a multiple of 8, so the prefix can not be compared with the whole stream.  */
/* The stream of FI begins with PREFIX (the rows after the inherited body state
   are real rules, not nops, so this is a plain prefix test).  */
static int fde_stream_has_prefix (const struct fde_info *fi, const unsigned char *prefix,
                                  size_t len) {
  return fi->insns_len >= len && memcmp (fi->insns, prefix, len) == 0;
}

static int fde_stream_starts_with (const struct fde_info *fi, const unsigned char *prefix,
                                   size_t len) {
  size_t i;

  if (fi->insns_len < len || memcmp (fi->insns, prefix, len) != 0) return 0;
  for (i = len; i < fi->insns_len; i++)
    if (fi->insns[i] != 0) return 0;
  return 1;
}

static int fails = 0;

static void check (const char *what, long long got, long long want) {
  if (got != want) {
    printf ("FAIL %-56s got=%lld want=%lld\n", what, got, want);
    fails++;
  }
}

static void check_true (const char *what, int cond) {
  if (!cond) {
    printf ("FAIL %s\n", what);
    fails++;
  }
}

/* ---------- the native side ---------- */

#define SENT_RBX 0x1111111122222222ull
#define SENT_RBP 0x3333333344444444ull
#define SENT_R12 0x5555555566666666ull
#define SENT_R13 0x7777777788888888ull
#define SENT_R14 0x99999999aaaaaaaaull
#define SENT_R15 0xbbbbbbbbccccccccull

#define SENT_XOR (SENT_RBX ^ SENT_RBP ^ SENT_R12 ^ SENT_R13 ^ SENT_R14 ^ SENT_R15)

#define MAX_FRAMES 96
struct frame_rec {
  void *pc;
  unsigned long long cfa, rbx, rbp, r12, r13, r14, r15;
};

static struct frame_rec frames[MAX_FRAMES];
static int nframes;
static int probe_calls;
static int raise_value; /* when nonzero the probe throws instead of walking */

static _Unwind_Reason_Code bt_cb (struct _Unwind_Context *c, void *arg) {
  int *n = (int *) arg;

  if (*n >= MAX_FRAMES) return _URC_END_OF_STACK;
  frames[*n].pc = (void *) (uintptr_t) _Unwind_GetIP (c);
  frames[*n].cfa = (unsigned long long) _Unwind_GetCFA (c);
  frames[*n].rbx = (unsigned long long) _Unwind_GetGR (c, 3);
  frames[*n].rbp = (unsigned long long) _Unwind_GetGR (c, 6);
  frames[*n].r12 = (unsigned long long) _Unwind_GetGR (c, 12);
  frames[*n].r13 = (unsigned long long) _Unwind_GetGR (c, 13);
  frames[*n].r14 = (unsigned long long) _Unwind_GetGR (c, 14);
  frames[*n].r15 = (unsigned long long) _Unwind_GetGR (c, 15);
  (*n)++;
  return _URC_NO_REASON;
}

static void walk_stack (void) {
  nframes = 0;
  _Unwind_Backtrace (bt_cb, &nframes);
}

static int in_range (const void *pc, const void *lo, const void *hi) {
  return lo != NULL && (uintptr_t) pc >= (uintptr_t) lo && (uintptr_t) pc < (uintptr_t) hi;
}

static int find_frame_in (const void *lo, const void *hi) {
  int i;

  for (i = 0; i < nframes; i++)
    if (in_range (frames[i].pc, lo, hi)) return i;
  return -1;
}

/* The return address the JIT code will return to: it is inside the JIT range
   and it is exactly the address which is looked up by the unwinder.  */
static void start_probe (void *ret) {
  probe_calls++;
  if (raise_value != 0) throw (int) raise_value; /* the probe throws instead */
  (void) ret;
  walk_stack ();
}

static void *ret0, *ret8;

extern "C" long long h_probe0 (void) {
  ret0 = __builtin_return_address (0);
  start_probe (ret0);
  return 0;
}

extern "C" long long h_probe8 (long long a0, long long a1, long long a2, long long a3, long long a4,
                               long long a5, long long a6, long long a7) {
  ret8 = __builtin_return_address (0);
  start_probe (ret8);
  return a0 + 2 * a1 + 3 * a2 + 4 * a3 + 5 * a4 + 6 * a5 + 7 * a6 + 8 * a7;
}

/* A native callback which throws: the exception has to travel through every
   JIT frame between here and the host catch.  */
extern "C" long long h_throw (long long v) {
  throw (int) v;
  return -1;
}

extern "C" long long h_add (long long a, long long b) { return a + b; }

extern "C" double h_dadd (double a, double b) { return a + b; }

/* ---------- the sentinel caller (machine code with real CFI) ----------

   long long sentinel_call (void *fn, long long a, double d):
   sets the SysV non-volatile registers to the sentinels, calls fn, stores the
   result into mc_result and returns the xor of the observed registers (0 when
   the caller of fn preserved all of them).  The .cfi directives give it a frame
   description, so exceptions can pass it too.  */

/* The sentinel caller is assembly: it needs the unmangled name.  */
extern "C" {
long long mc_result;
/* The return address sentinel_call was entered with: it is exactly the PC the
   unwinder reports for the host frame which called the JIT code.  */
void *sc_caller_pc;
}

#define MIR_STR2(x) #x
#define MIR_STR(x) MIR_STR2 (x)

extern "C" long long sentinel_call (void *fn, long long a, double d);

__asm__ (
  ".text\n"
  ".globl sentinel_call\n"
  ".type sentinel_call, @function\n"
  "sentinel_call:\n"
  "  .cfi_startproc\n"
  "  movq (%rsp), %rdx\n"
  "  movq %rdx, sc_caller_pc(%rip)\n"
  "  pushq %rbp\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %rbp, -16\n"
  "  pushq %rbx\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %rbx, -24\n"
  "  pushq %r12\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %r12, -32\n"
  "  pushq %r13\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %r13, -40\n"
  "  pushq %r14\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %r14, -48\n"
  "  pushq %r15\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %r15, -56\n"
  "  subq $8, %rsp\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  movq %rdi, %rax\n"
  "  movq %rsi, %rdi\n"
  "  movabsq $" MIR_STR (SENT_RBX) ", %rbx\n"
  "  movabsq $" MIR_STR (SENT_RBP) ", %rbp\n"
  "  movabsq $" MIR_STR (SENT_R12) ", %r12\n"
  "  movabsq $" MIR_STR (SENT_R13) ", %r13\n"
  "  movabsq $" MIR_STR (SENT_R14) ", %r14\n"
  "  movabsq $" MIR_STR (SENT_R15) ", %r15\n"
  "  callq *%rax\n"
  "  movq %rax, mc_result(%rip)\n"
  "  xorq %rax, %rax\n"
  "  xorq %rbx, %rax\n"
  "  xorq %rbp, %rax\n"
  "  xorq %r12, %rax\n"
  "  xorq %r13, %rax\n"
  "  xorq %r14, %rax\n"
  "  xorq %r15, %rax\n"
  "  addq $8, %rsp\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  popq %r15\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %r15\n"
  "  popq %r14\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %r14\n"
  "  popq %r13\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %r13\n"
  "  popq %r12\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %r12\n"
  "  popq %rbx\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %rbx\n"
  "  popq %rbp\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %rbp\n"
  "  ret\n"
  "  .cfi_endproc\n"
  ".size sentinel_call, .-sentinel_call\n");


static long long call_and_catch (void *fn, long long v);
static void run_interp_tests (void);
static void run_hook_tests (void);


/* ---------- the MIR program ---------- */

#define BIG_LOCALS 64
#define GROWTH_FUNCS 620

static char prog_buf[1 << 21];
static size_t prog_len;

static void pstr (const char *s) {
  size_t l = strlen (s);

  if (prog_len + l + 1 >= sizeof (prog_buf)) {
    printf ("test program buffer overflow\n");
    exit (1);
  }
  memcpy (prog_buf + prog_len, s, l + 1);
  prog_len += l;
}

static void pf (const char *fmt, ...) {
  char buf[256];
  va_list ap;

  va_start (ap, fmt);
  vsnprintf (buf, sizeof (buf), fmt, ap);
  va_end (ap);
  pstr (buf);
}

static void build_program (void) {
  int i;

  prog_len = 0;
  prog_buf[0] = '\0';
  pstr ("m: module\n"
        "import h_probe0, h_probe8, h_throw, h_add, h_dadd\n"
        "p_probe0: proto i64\n"
        "p_probe8: proto i64, i64:a, i64:b, i64:c, i64:d, i64:e, i64:f, i64:g, i64:h\n"
        "p_throw: proto i64, i64:v\n"
        "p_add: proto i64, i64:a, i64:b\n"
        "p_work: proto i64, i64:k\n"
        "p_big: proto i64, i64:k\n"
        "p_var: proto i64, i64:n, ...\n"
        "p_all: proto i64, i64:k\n"
        "p_bst: proto i64, i64:k\n"
        "p_nofp: proto i64, i64:k\n"
        "p_leaf: proto i64, i64:a, i64:b\n"
        "p_leaf2: proto i64, i64:a, i64:b\n"
        "p_two: proto i64, i64:k\n"
        "p_thr: proto i64, i64:v\n"
        "p_thr2: proto i64, i64:v\n"
        "p_ffn: proto d, d:x, d:y\n"
        "p_g: proto i64, i64:k\n");
  /* eight values live across the probe call: they need non-volatile registers */
  pstr ("work: func i64, i64:k\n"
        " local i64:a0, i64:a1, i64:a2, i64:a3, i64:a4, i64:a5, i64:a6, i64:a7, i64:r\n"
        " mov a0, 1\n mov a1, 2\n mov a2, 3\n mov a3, 4\n"
        " mov a4, 5\n mov a5, 6\n mov a6, 7\n mov a7, 8\n"
        " call p_probe8, h_probe8, r, a0, a1, a2, a3, a4, a5, a6, a7\n"
        " add r, r, k\n add r, r, a0\n add r, r, a1\n add r, r, a2\n add r, r, a3\n"
        " add r, r, a4\n add r, r, a5\n add r, r, a6\n add r, r, a7\n"
        " ret r\n endfunc\n");
  /* a frame which does not fit the small stack offset forms */
  pstr ("big: func i64, i64:k\n local i64:r");
  for (i = 0; i < BIG_LOCALS; i++) pf (", i64:b%d", i);
  pstr ("\n");
  for (i = 0; i < BIG_LOCALS; i++) pf (" mov b%d, %d\n", i, i + 1);
  pstr (" call p_probe8, h_probe8, r, b0, b1, b2, b3, b4, b5, b6, b7\n");
  for (i = 0; i < BIG_LOCALS; i++) pf (" add r, r, b%d\n", i);
  pstr (" ret r\n endfunc\n");
  /* varargs: the argument save area is set up after the frame allocation */
  pstr ("varfn: func i64, i64:n, ...\n"
        " local i64:va, i64:s, i64:i, i64:v, i64:p, i64:x\n"
        " alloca va, 16\n"
        " va_start va\n"
        " mov s, 0\n mov i, 0\n"
        "vloop: bge vfin, i, n\n"
        " va_arg v, va, i32:0\n"
        " mov x, i32:0(v)\n"
        " add s, s, x\n add i, i, 1\n jmp vloop\n"
        "vfin: call p_probe8, h_probe8, p, 1, 2, 3, 4, 5, 6, 7, 8\n"
        " add s, s, p\n"
        " va_end va\n"
        " ret s\n endfunc\n");
  /* a dynamic (alloca) frame: the CFA has to stay RBP based */
  pstr ("allfn: func i64, i64:k\n"
        " local i64:a, i64:r\n"
        " alloca a, 128\n"
        " mov i64:0(a), 42\n"
        " call p_probe8, h_probe8, r, 1, 2, 3, 4, 5, 6, 7, 8\n"
        " add r, r, i64:0(a)\n"
        " ret r\n endfunc\n");
  /* an inlined callee uses bstart/bend */
  pstr ("addf: func i64, i64:a, i64:b\n"
        " local i64:p\n"
        " alloca p, 64\n"
        " mov i64:(p), b\n"
        " add a, a, i64:(p)\n"
        " ret a\n endfunc\n"
        "bstfn: func i64, i64:k\n"
        " local i64:r, i64:t\n"
        " inline p_add, addf, r, 5, 6\n"
        " call p_probe8, h_probe8, t, 1, 2, 3, 4, 5, 6, 7, 8\n"
        " add r, r, t\n"
        " ret r\n endfunc\n");
  /* a function without a frame pointer and without calls */
  pstr ("nofp: func i64, i64:k\n local i64:r, i64:t");
  for (i = 0; i < 20; i++) pf (", i64:c%d", i);
  for (i = 0; i < 10; i++) pf (", i64:u%d", i);
  pstr ("\n");
  for (i = 0; i < 20; i++) pf (" mov c%d, %d\n", i, i + 1);
  for (i = 0; i < 10; i++) pf (" add u%d, k, c%d\n", i, i);
  pstr (" mov r, 0\n");
  for (i = 0; i < 10; i++) pf (" add r, r, u%d\n", i);
  for (i = 10; i < 20; i++) pf (" add r, r, c%d\n", i);
  pstr (" ret r\n endfunc\n");
  /* real leaves: they change neither RSP nor a non-volatile register */
  pstr ("leaf: func i64, i64:a, i64:b\n"
        " local i64:r\n"
        " add r, a, b\n"
        " mul r, r, 3\n"
        " ret r\n endfunc\n"
        "leaf2: func i64, i64:a, i64:b\n"
        " local i64:r\n"
        " mul r, a, b\n"
        " ble l2end, r, 100\n"
        " add r, r, 7\n"
        "l2end: ret r\n endfunc\n");
  /* two JIT frames in a row */
  pstr ("two: func i64, i64:k\n"
        " local i64:r\n"
        " call p_work, work, r, k\n"
        " ret r\n endfunc\n");
  /* the native throw is called from a JIT frame (and through two frames) */
  pstr ("thr: func i64, i64:v\n"
        " local i64:r\n"
        " call p_throw, h_throw, r, v\n"
        " add r, r, 1\n"
        " ret r\n endfunc\n"
        "thr2: func i64, i64:v\n"
        " local i64:r\n"
        " call p_thr, thr, r, v\n"
        " add r, r, 2\n"
        " ret r\n endfunc\n");
  /* floating point values live across the probe call */
  pstr ("ffn: func d, d:x, d:y\n"
        " local i64:r\n"
        " call p_probe0, h_probe0, r\n"
        " dadd x, x, y\n"
        " ret x\n endfunc\n");
  for (i = 0; i < GROWTH_FUNCS; i++)
    pf ("g%d: func i64, i64:k\n local i64:r\n"
        " call p_probe0, h_probe0, r\n add r, r, k\n ret r\n endfunc\n",
        i);
  pstr ("endmodule\n");
}

/* ---------- the context ---------- */

static MIR_context_t ctx;
static MIR_module_t module;
static MIR_item_t f_work, f_big, f_var, f_all, f_bst, f_nofp, f_leaf, f_leaf2, f_two, f_thr, f_thr2,
  f_ffn;
static MIR_item_t g_funcs[GROWTH_FUNCS];

static MIR_item_t find_func (const char *name) {
  MIR_item_t item;

  for (item = DLIST_HEAD (MIR_item_t, module->items); item != NULL;
       item = DLIST_NEXT (MIR_item_t, item))
    if (item->item_type == MIR_func_item && strcmp (item->u.func->name, name) == 0) return item;
  return NULL;
}

static void reset_probe (void) {
  nframes = 0;
  probe_calls = 0;
  raise_value = 0;
  mc_result = 0;
  ret0 = ret8 = NULL; /* a stale return address must not validate a walk */
}

static int setup (const char *mode, int opt_level, MIR_code_alloc_t code_alloc) {
  int i;
  char name[32];

  build_program ();
  ctx = MIR_init2 (NULL, code_alloc);
  MIR_scan_string (ctx, prog_buf);
  module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  f_work = find_func ("work");
  f_big = find_func ("big");
  f_var = find_func ("varfn");
  f_all = find_func ("allfn");
  f_bst = find_func ("bstfn");
  f_nofp = find_func ("nofp");
  f_leaf = find_func ("leaf");
  f_leaf2 = find_func ("leaf2");
  f_two = find_func ("two");
  f_thr = find_func ("thr");
  f_thr2 = find_func ("thr2");
  f_ffn = find_func ("ffn");
  for (i = 0; i < GROWTH_FUNCS; i++) {
    snprintf (name, sizeof (name), "g%d", i);
    g_funcs[i] = find_func (name);
  }
  if (f_work == NULL || f_big == NULL || f_var == NULL || f_all == NULL || f_bst == NULL
      || f_nofp == NULL || f_leaf == NULL || f_leaf2 == NULL || f_two == NULL || f_thr == NULL
      || f_thr2 == NULL || f_ffn == NULL || g_funcs[GROWTH_FUNCS - 1] == NULL) {
    printf ("unwind test: item lookup failed\n");
    fails++;
    MIR_finish (ctx);
    return 0;
  }
  MIR_load_module (ctx, module);
  MIR_load_external (ctx, "h_probe0", (void *) h_probe0);
  MIR_load_external (ctx, "h_probe8", (void *) h_probe8);
  MIR_load_external (ctx, "h_throw", (void *) h_throw);
  MIR_load_external (ctx, "h_add", (void *) h_add);
  MIR_load_external (ctx, "h_dadd", (void *) h_dadd);
  MIR_gen_init (ctx);
  MIR_gen_set_optimize_level (ctx, (unsigned) opt_level);
  if (strcmp (mode, "full") == 0) {
    MIR_link (ctx, MIR_set_gen_interface, NULL);
  } else if (strcmp (mode, "lazy") == 0) {
    MIR_link (ctx, MIR_set_lazy_gen_interface, NULL);
  } else if (strcmp (mode, "bb") == 0) {
    MIR_link (ctx, MIR_set_lazy_bb_gen_interface, NULL);
  } else if (strcmp (mode, "interp") == 0) {
    MIR_link (ctx, MIR_set_interp_interface, NULL);
  } else {
    printf ("unknown mode %s\n", mode);
    fails++;
    MIR_gen_finish (ctx);
    MIR_finish (ctx);
    return 0;
  }
  return 1;
}

static void finish (void) {
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
  ctx = NULL;
}

/* ---------- checks shared by the modes ---------- */

static int dtors;
static int caught;

struct raii_guard {
  int *counter;
  explicit raii_guard (int *c) : counter (c) {}
  ~raii_guard () { ++*counter; }
};

/* The host frame which catches: the exception has to cross the JIT frames. */
static long long call_and_catch (void *fn, long long v) {
  raii_guard guard (&dtors);

  try {
    return ((long long (*) (long long)) fn) (v);
  } catch (int code) {
    caught = code;
    return -1;
  }
}

/* Check the walk started by the probe of ITEM.  RET is the probe's return
   address (it has to be reported as a frame) and HOST_LO..HOST_HI the code range
   of the host function which called the JIT code; with HOST_LO == NULL the
   exact return address published by the sentinel caller is used instead.  */
static void check_walk (const char *what, MIR_item_t item, void *ret, const void *host_lo,
                        size_t host_size, int sentinels_p) {
  char buf[160];
  int i, seen = 0;
  void *lo, *hi;

  snprintf (buf, sizeof (buf), "%s: probe called", what);
  check_true (buf, probe_calls > 0);
  lo = item->u.func->machine_code != NULL ? (void *) item->u.func->machine_code
                                          : (void *) item->addr;
  hi = (void *) ((uintptr_t) lo + 65536);
  snprintf (buf, sizeof (buf), "%s: JIT frame in the walk", what);
  check_true (buf, find_frame_in (lo, hi) >= 0);
  snprintf (buf, sizeof (buf), "%s: probe return address in the walk", what);
  check_true (buf, find_frame_in (ret, (void *) ((uintptr_t) ret + 1)) >= 0);
  snprintf (buf, sizeof (buf), "%s: host frame in the walk", what);
  if (host_lo == NULL)
    check_true (buf, find_frame_in (sc_caller_pc, (void *) ((uintptr_t) sc_caller_pc + 1)) >= 0);
  else
    check_true (buf, find_frame_in (host_lo, (const char *) host_lo + host_size) >= 0);
  for (i = 0; i < nframes; i++)
    if (frames[i].rbx == SENT_RBX && frames[i].rbp == SENT_RBP && frames[i].r12 == SENT_R12
        && frames[i].r13 == SENT_R13 && frames[i].r14 == SENT_R14 && frames[i].r15 == SENT_R15)
      seen = 1;
  if (sentinels_p) {
    snprintf (buf, sizeof (buf), "%s: non-volatile sentinels in some frame", what);
    check_true (buf, seen);
  }
}

/* The probe throws (see raise_value): the exception has to travel through the
   JIT frames and the machine code sentinel caller into this catch.  */
static long long catch_through_sentinel (MIR_item_t item, long long k) {
  raii_guard guard (&dtors);

  raise_value = 55;
  try {
    return (long long) sentinel_call (item->addr, k, 0.0);
  } catch (int code) {
    caught = code;
    return -1;
  }
}

/* Run one item through the sentinel caller and check the result, the preserved
   registers and the walked stack.  */
static void run_item (const char *what, MIR_item_t item, long long k, long long want,
                      int probe_p) {
  char buf[160];
  unsigned long long x;

  reset_probe ();
  x = sentinel_call (item->addr, k, 0.0);

  snprintf (buf, sizeof (buf), "%s: sentinels restored", what);
  check_true (buf, x == SENT_XOR);
  snprintf (buf, sizeof (buf), "%s: result", what);
  check (buf, mc_result, want);
  if (probe_p) check_walk (what, item, ret8 != NULL ? ret8 : ret0, NULL, 0, 1);
  else {
    snprintf (buf, sizeof (buf), "%s: no probe call expected", what);
    check_true (buf, probe_calls == 0);
  }
}

static void run_matrix (const char *mode, int opt) {
  char what[96];
  long long want;

  snprintf (what, sizeof (what), "%s/%d work", mode, opt);
  run_item (what, f_work, 1, 204 + 1 + 36, 1);

  /* the probe is called with the first eight locals: 1+2*2+..+8*8 = 204 */
  snprintf (what, sizeof (what), "%s/%d big", mode, opt);
  want = 204; /* the probe of the first eight locals */
  for (int i = 0; i < BIG_LOCALS; i++) want += i + 1;
  run_item (what, f_big, 0, want, 1);

  snprintf (what, sizeof (what), "%s/%d nofp", mode, opt);
  /* u_i = k + c_i for i in 0..9, then all c_i are added */
  want = 10 * 0 + 55;                      /* sum (k + 1..10) */
  for (int i = 10; i < 20; i++) want += i + 1; /* c_10..c_19 */
  run_item (what, f_nofp, 0, want, 0);

  snprintf (what, sizeof (what), "%s/%d allfn", mode, opt);
  run_item (what, f_all, 0, 42 + 204, 1);

  snprintf (what, sizeof (what), "%s/%d bstfn", mode, opt);
  run_item (what, f_bst, 0, 11 + 204, 1);

  /* two JIT frames in a row: the walk has to cross both */
  snprintf (what, sizeof (what), "%s/%d two", mode, opt);
  run_item (what, f_two, 1, 204 + 1 + 36, 1);

  snprintf (what, sizeof (what), "%s/%d leaf", mode, opt);
  reset_probe ();
  check (what, ((long long (*) (long long, long long)) f_leaf->addr) (3, 4), 21);
  snprintf (what, sizeof (what), "%s/%d leaf2", mode, opt);
  check (what, ((long long (*) (long long, long long)) f_leaf2->addr) (3, 4), 12);
  check (what, ((long long (*) (long long, long long)) f_leaf2->addr) (30, 4), 127);

  /* varargs: 1+2+3+4 = 10 plus the probe sum.  The probe is called from the loop
     exit block, i.e. from a non-entry lazy bb fragment (kind 2), so the whole
     frame rule of a vararg function (which keeps a frame register) is exercised
     here and nowhere else.  */
  snprintf (what, sizeof (what), "%s/%d varargs", mode, opt);
  reset_probe ();
  check (what, ((long long (*) (long long, ...)) f_var->addr) (4, 1, 2, 3, 4), 10 + 204);
  snprintf (what, sizeof (what), "%s/%d varargs result", mode, opt);
  check_true (what, probe_calls > 0);
  /* the walk has to cross the JIT frame which called the probe and reach the
     host frame of this function */
  check_walk (what, f_var, ret8, (void *) &run_matrix, 8192, 0);
  if (strcmp (mode, "bb") == 0) {
    /* In the lazy bb mode the probe sits in a *non-entry* fragment, whose frame
       description has to *begin* with the body state of the function: `-8(sp)=rbp`
       (the caller RBP at CFA-16) and then `bp = sp-8` (CFA = rbp+16).  Asserting
       the stream of the FDE which covers the call site proves that the fragment
       inherits the whole body state and not only the CFA. */
    static const unsigned char rbp_body_prefix[] = {0x86, 0x02, /* offset rbp, 2 */
                                                    0x0c, 0x06, 0x10}; /* def_cfa rbp, 16 */
    struct fde_info fi;

    snprintf (what, sizeof (what), "%s/%d varargs fragment inherits the body state", mode, opt);
    if (ret8 == NULL || !fde_get ((void *) ((uintptr_t) ret8 - 1), &fi)) {
      check_true (what, 0);
    } else {
      check_true (what, (uintptr_t) ret8 >= fi.start && (uintptr_t) ret8 < fi.end);
      check_true (what, fde_stream_has_prefix (&fi, rbp_body_prefix, sizeof (rbp_body_prefix)));
    }
  }

  /* floating point arguments through the wrapper */
  snprintf (what, sizeof (what), "%s/%d ffn", mode, opt);
  reset_probe ();
  {
    double r = ((double (*) (double, double)) f_ffn->addr) (1.5, 2.25);

    check_true (what, r > 3.7499 && r < 3.7501);
    check_true (what, probe_calls > 0);
  }

  /* exceptions: one and two JIT frames, caught in the host */
  snprintf (what, sizeof (what), "%s/%d throw", mode, opt);
  dtors = caught = 0;
  check (what, call_and_catch (f_thr->addr, 7), -1);
  snprintf (what, sizeof (what), "%s/%d throw value", mode, opt);
  check (what, caught, 7);
  snprintf (what, sizeof (what), "%s/%d throw dtor", mode, opt);
  check (what, dtors, 1);

  snprintf (what, sizeof (what), "%s/%d throw2", mode, opt);
  dtors = caught = 0;
  check (what, call_and_catch (f_thr2->addr, 9), -1);
  snprintf (what, sizeof (what), "%s/%d throw2 value", mode, opt);
  check (what, caught, 9);
  snprintf (what, sizeof (what), "%s/%d throw2 dtor", mode, opt);
  check (what, dtors, 1);

  /* a throw from the probe: it has to cross the JIT frames *and* the machine
     code sentinel caller, whose .cfi directives are the only description of its
     frame.  */
  snprintf (what, sizeof (what), "%s/%d throw through the sentinel caller", mode, opt);
  dtors = caught = 0;
  check (what, catch_through_sentinel (f_two, 1), -1);
  snprintf (what, sizeof (what), "%s/%d probe throw value", mode, opt);
  check (what, caught, 55);
  snprintf (what, sizeof (what), "%s/%d probe throw dtor", mode, opt);
  check (what, dtors, 1);
}


static void check_leaf_item (const char *what, MIR_item_t item) {
  char buf[160];
  struct fde_info fi;
  void *code = (void *) item->u.func->machine_code;
  const unsigned char *last;

  if (code == NULL) return; /* the bb mode has no whole function code */
  snprintf (buf, sizeof (buf), "%s: FDE at the first byte", what);
  if (!fde_get (code, &fi)) {
    check_true (buf, 0);
    return;
  }
  check_true (buf, 1);
  snprintf (buf, sizeof (buf), "%s: FDE starts at the code", what);
  check_true (buf, fi.start == (uintptr_t) code);
  snprintf (buf, sizeof (buf), "%s: only CIE default rules", what);
  check_true (buf, fde_stream_is_default (&fi));
  last = (const unsigned char *) (fi.end - 1);
  snprintf (buf, sizeof (buf), "%s: the described range ends at a ret", what);
  check_true (buf, fi.end > fi.start && *last == 0xc3);
}

/* Scan [lo, hi) for the frame descriptions of leaf code.  A bb thunk is
   recognized by the stack adjustment of its middle range (a unique 4-byte
   stream); an FDE outside the thunk ranges whose stream is empty (only
   DW_CFA_nop padding) describes exactly the CIE default rules, i.e. code which
   changes neither RSP nor a non-volatile register.  */
static int scan_leaf_fdes (const char *what, void *lo, void *hi) {
  static const unsigned char adjusted[] = {0x0c, 0x07, 0x90, 0x01}; /* def_cfa rsp,144 */
  char buf[160];
  uintptr_t thunks[512], seen[64];
  int nth = 0, n = 0, i;
  uintptr_t a;

  /* the ranges are not necessarily 4-byte aligned (a thunk's middle range
     starts at its offset 0x11), so every byte is probed */
  for (a = (uintptr_t) lo; a < (uintptr_t) hi; a++) {
    struct fde_info fi;

    if (!fde_get ((void *) a, &fi) || fi.start != a) continue;
    if (fde_stream_starts_with (&fi, adjusted, sizeof (adjusted))
        && nth < (int) (sizeof (thunks) / sizeof (thunks[0])))
      thunks[nth++] = a - 0x11; /* the middle range starts at the thunk + 0x11 */
  }
  for (a = (uintptr_t) lo; a < (uintptr_t) hi; a++) {
    struct fde_info fi;
    int in_thunk = 0, dup = 0;

    if (!fde_get ((void *) a, &fi) || fi.start != a) continue;
    for (i = 0; i < nth; i++)
      if (in_range ((void *) a, (void *) thunks[i], (char *) thunks[i] + 0x21)) in_thunk = 1;
    if (in_thunk || !fde_stream_is_default (&fi)) continue;
    for (i = 0; i < n; i++)
      if (seen[i] == fi.start) dup = 1;
    if (dup) continue;
    if (n >= (int) (sizeof (seen) / sizeof (seen[0]))) break;
    seen[n++] = fi.start;
    snprintf (buf, sizeof (buf), "%s: fragment %d at %p has only the default rules", what, n - 1,
              (void *) fi.start);
    check_true (buf, 1);
  }
  return n;
}

static void run_leaf_tests (void) {
  const char *modes[3] = {"full", "lazy", "bb"};
  int mi;

  for (mi = 0; mi < 3; mi++) {
    char what[64];
    void *code;

    if (!setup (modes[mi], 2, NULL)) continue;
    /* the generation is lazy in two of the modes: run the functions first */
    check ("leaf run", ((long long (*) (long long, long long)) f_leaf->addr) (3, 4), 21);
    check ("leaf2 run", ((long long (*) (long long, long long)) f_leaf2->addr) (3, 4), 12);
    check ("leaf2 run 2", ((long long (*) (long long, long long)) f_leaf2->addr) (30, 4), 127);
    snprintf (what, sizeof (what), "%s/leaf", modes[mi]);
    check_leaf_item (what, f_leaf);
    snprintf (what, sizeof (what), "%s/leaf2", modes[mi]);
    check_leaf_item (what, f_leaf2);
    if (f_leaf->u.func->machine_code == NULL) {
      /* The bb mode has no whole function code.  A closed minimal program is
         used instead of the big one, so that the set of frame descriptions in
         the code holder is known exactly: the bb wrapper, the interface wrapper
         of each function (both carry rules) and the leaf fragments (which must
         carry only the CIE defaults).  */
      static const char *mini
        = "m: module\n"
          "p_leaf: proto i64, i64:a, i64:b\n"
          "p_leaf2: proto i64, i64:a, i64:b\n"
          "leaf: func i64, i64:a, i64:b\n local i64:r\n"
          " add r, a, b\n mul r, r, 3\n ret r\n endfunc\n"
          "leaf2: func i64, i64:a, i64:b\n local i64:r\n"
          " mul r, a, b\n ble l2end, r, 100\n add r, r, 7\n"
          " l2end: ret r\n endfunc\n"
          "endmodule\n";
      MIR_context_t c = MIR_init ();
      MIR_module_t mm;
      MIR_item_t l1 = NULL, l2 = NULL, it;
      int n;

      MIR_scan_string (c, mini);
      mm = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (c));
      for (it = DLIST_HEAD (MIR_item_t, mm->items); it != NULL; it = DLIST_NEXT (MIR_item_t, it))
        if (it->item_type == MIR_func_item && it->u.func->nres == 1 && it->u.func->nargs == 2) {
          if (strcmp (it->u.func->name, "leaf") == 0) l1 = it;
          if (strcmp (it->u.func->name, "leaf2") == 0) l2 = it;
        }
      MIR_load_module (c, mm);
      MIR_gen_init (c);
  MIR_link (c, MIR_set_lazy_bb_gen_interface, NULL);
      snprintf (what, sizeof (what), "%s/leaf run", modes[mi]);
      check (what, l1 != NULL ? ((long long (*) (long long, long long)) l1->addr) (3, 4) : -1, 21);
      snprintf (what, sizeof (what), "%s/leaf2 run", modes[mi]);
      check (what, l2 != NULL ? ((long long (*) (long long, long long)) l2->addr) (30, 4) : -1, 127);
      snprintf (what, sizeof (what), "%s/leaf2 internal run", modes[mi]);
      check (what, l2 != NULL ? ((long long (*) (long long, long long)) l2->addr) (3, 4) : -1, 12);
      /* The fragments of the two leaves are: the whole body of `leaf`, the first
         basic block of `leaf2`, its fall-through block (add; jmp) and the block
         of the trailing `ret`.  Both functions are leaves, so each of those
         frame descriptions may only hold the CIE default rules; a description
         with any rule would be skipped here and the count below would be too
         small.  The scan covers the whole holder of the two functions, so it
         also sees (and excludes) the bb thunks.  */
      snprintf (what, sizeof (what), "%s/leaf: the leaf fragment frame descriptions", modes[mi]);
      n = scan_leaf_fdes (what, (char *) l1->addr, (char *) l1->addr + 0x10000);
      check (what, n, 4);
      MIR_gen_finish (c);
      MIR_finish (c);
    }
    finish ();
  }
}

/* ---------- many functions, several holders, context recreation ---------- */

static void call_all_g (const char *what) {
  char buf[160];
  int i;

  for (i = 0; i < GROWTH_FUNCS; i++) {
    reset_probe ();
    snprintf (buf, sizeof (buf), "%s: g%d result", what, i);
    check (buf, ((long long (*) (long long)) g_funcs[i]->addr) (i), i);
  }
  /* the last function is in the last holder: walk through it */
  reset_probe ();
  (void) sentinel_call (g_funcs[GROWTH_FUNCS - 1]->addr, 1, 0.0);
  snprintf (buf, sizeof (buf), "%s: walk called the probe", what);
  check_true (buf, probe_calls > 0);
  snprintf (buf, sizeof (buf), "%s: walk reached the host caller", what);
  check_true (buf, find_frame_in (sc_caller_pc, (void *) ((uintptr_t) sc_caller_pc + 1)) >= 0);
  snprintf (buf, sizeof (buf), "%s: walk crossed a JIT frame", what);
  check_true (buf, find_frame_in ((void *) g_funcs[GROWTH_FUNCS - 1]->u.func->machine_code,
                                  (void *) ((uintptr_t) g_funcs[GROWTH_FUNCS - 1]
                                              ->u.func->machine_code
                                            + 65536))
                     >= 0);
}

static void run_growth_tests (void) {
  int round;

  for (round = 0; round < 3; round++) {
    char what[96];

    if (!setup ("full", 2, NULL)) return;
    snprintf (what, sizeof (what), "growth/%d", round);
    call_all_g (what);
    /* the code has to stay callable after the generator is gone */
    MIR_gen_finish (ctx);
    snprintf (what, sizeof (what), "growth/%d after gen_finish", round);
    reset_probe ();
    check (what, ((long long (*) (long long)) g_funcs[7]->addr) (7), 7);
    snprintf (what, sizeof (what), "growth/%d walk after gen_finish", round);
    check_true (what, probe_calls > 0);
    dtors = caught = 0;
    snprintf (what, sizeof (what), "growth/%d throw after gen_finish", round);
    check (what, call_and_catch (f_thr2->addr, 3 * round + 1), -1);
    snprintf (what, sizeof (what), "growth/%d throw value after gen_finish", round);
    check (what, caught, 3 * round + 1);
    snprintf (what, sizeof (what), "growth/%d dtor after gen_finish", round);
    check (what, dtors, 1);
    MIR_finish (ctx);
    ctx = NULL;
  }
}

/* ---------- a custom code allocator: unregistration before unmap ---------- */

static void *unmap_check_pc;
static int unmap_checks, unmap_violations, fde_before_unmap;

static void *alloc_map (size_t len, void *user_data) {
  void *m;

  (void) user_data;
  m = mmap (NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  return m == MAP_FAILED ? NULL : m;
}

static int alloc_unmap (void *addr, size_t len, void *user_data) {
  (void) user_data;
  if (unmap_check_pc != NULL && in_range (unmap_check_pc, addr, (char *) addr + len)) {
    struct dwarf_eh_bases bases;

    unmap_checks++;
    if (_Unwind_Find_FDE (unmap_check_pc, &bases) != NULL) unmap_violations++;
  }
  return munmap (addr, len);
}

static int alloc_protect (void *addr, size_t len, MIR_mem_protect_t prot, void *user_data) {
  int native = prot == PROT_WRITE_EXEC ? (PROT_READ | PROT_WRITE | PROT_EXEC)
                                       : (PROT_READ | PROT_EXEC);

  (void) user_data;
  return mprotect (addr, len, native);
}

static void run_allocator_test (void) {
  static struct MIR_code_alloc alloc = {alloc_map, alloc_unmap, alloc_protect, NULL};
  struct dwarf_eh_bases bases;

  if (!setup ("full", 2, &alloc)) return;
  ((long long (*) (long long)) f_work->addr) (1);
  reset_probe ();
  ((long long (*) (long long)) f_work->addr) (1);
  check_true ("allocator: walk", probe_calls > 0);
  dtors = caught = 0;
  check ("allocator: throw", call_and_catch (f_thr2->addr, 4), -1);
  check ("allocator: throw value", caught, 4);
  check ("allocator: dtor", dtors, 1);
  unmap_check_pc = (void *) f_work->u.func->machine_code;
  fde_before_unmap = _Unwind_Find_FDE (unmap_check_pc, &bases) != NULL;
  check_true ("allocator: FDE present before finish", fde_before_unmap);
  unmap_checks = unmap_violations = 0;
  finish ();
  check_true ("allocator: unmap checked", unmap_checks > 0);
  check_true ("allocator: FDEs unregistered before unmap", unmap_violations == 0);
  check_true ("allocator: FDE gone after finish", _Unwind_Find_FDE (unmap_check_pc, &bases) == NULL);
  unmap_check_pc = NULL;
}

/* ---------- the interpreter bridge (interp shim and ff call) ---------- */

static void run_interp_tests (void) {
  if (!setup ("interp", 0, NULL)) return;
  reset_probe ();
  check ("interp: work result", ((long long (*) (long long)) f_work->addr) (1), 204 + 1 + 36);
  check_true ("interp: probe called", probe_calls > 0);
  check_true ("interp: host frame in the walk",
              find_frame_in ((void *) &run_interp_tests,
                             (void *) ((uintptr_t) &run_interp_tests + 8192))
                >= 0);
  reset_probe ();
  check ("interp: big result", ((long long (*) (long long)) f_big->addr) (0), 2284);
  check_true ("interp: the interpreted call reached the native callback", probe_calls > 0);
  dtors = caught = 0;
  check ("interp: throw", call_and_catch (f_thr->addr, 11), -1);
  check ("interp: throw value", caught, 11);
  check ("interp: dtor", dtors, 1);
  dtors = caught = 0;
  check ("interp: throw2", call_and_catch (f_thr2->addr, 13), -1);
  check ("interp: throw2 value", caught, 13);
  check ("interp: throw2 dtor", dtors, 1);
  finish ();
}

/* ---------- the generation hooks (the wrapper and the bb wrapper) ---------- */

extern "C" {
extern void *body_rbp; /* the frame register of the emulated internal_body */
}

static int hook_calls;
static int hook_action; /* 0: return hook_ret, 1: walk, 2: throw */
static void *hook_ret;
/* the caller RBP of the emulated body, read from its frame during the walk (the
   slot is gone once the body has returned) */
static uint64_t walk_saved_rbp;

static void *hook_body (void) {
  hook_calls++;
  switch (hook_action) {
  case 1:
    if (body_rbp != NULL) { /* the internal thunk scenario: read the caller RBP */
      uintptr_t cfa = (uintptr_t) body_rbp + 32;

      memcpy (&walk_saved_rbp, (void *) (cfa - 16), sizeof (walk_saved_rbp));
    }
    walk_stack ();
    return hook_ret;
  case 2: throw (int) 42;
  default: return hook_ret;
  }
}

extern "C" void *int_hook (void *d0, void *d1) {
  (void) d0;
  (void) d1;
  return hook_body ();
}

static void run_hook_tests (void) {
  char buf[128];
  void *w;

  if (!setup ("full", 2, NULL)) return;
  /* A: the hook returns the real entry point: the arguments (integer and
     floating point) survive the wrapper. */
  w = _MIR_get_wrapper (ctx, f_work, (void *) int_hook);
  hook_calls = 0;
  hook_action = 0;
  hook_ret = f_work->u.func->machine_code;
  check ("hook: integer result", ((long long (*) (long long)) w) (2), 204 + 2 + 36);
  check ("hook: called once", hook_calls, 1);

  w = _MIR_get_wrapper (ctx, f_ffn, (void *) int_hook);
  hook_calls = 0;
  hook_ret = f_ffn->u.func->machine_code;
  {
    double r = ((double (*) (double, double)) w) (1.5, 2.25);

    check_true ("hook: float arguments survive", r > 3.7499 && r < 3.7501);
  }
  check ("hook: float call", hook_calls, 1);

  /* B: a backtrace taken inside the hook crosses the wrapper frame and reaches
     the host */
  hook_action = 1;
  hook_ret = f_work->u.func->machine_code;
  reset_probe ();
  check_true ("hook: walk result", ((long long (*) (long long)) w) (0) >= 0);
  snprintf (buf, sizeof (buf), "hook: the walk has at least three frames");
  check_true (buf, nframes >= 3);
  check_true ("hook: host frame in the walk",
              find_frame_in ((void *) &run_hook_tests, (void *) ((uintptr_t) &run_hook_tests + 8192))
                >= 0);

  /* C: a throw from inside the hook crosses the wrapper frame into the host */
  hook_action = 2;
  dtors = caught = 0;
  check ("hook: throw", call_and_catch (w, 5), -1);
  check ("hook: throw value", caught, 42);
  check ("hook: throw dtor", dtors, 1);
  finish ();
}

/* ---------- the JCALL/JRET continuation ----------

   `__builtin_jcall`/`__builtin_jret` (a documented c2mir extension, see
   c2mir/README.md) are the only way to get a `MIR_JCALL`/`MIR_JRET`
   continuation, so normal C code never produces one.  Such a function is entered
   by a jump with RSP 16-byte aligned and has no return address on its stack, so
   its bb thunk has to reserve 128 bytes (not 136) and must get no frame
   description at all.

   The continuation itself is executed by c-tests/new/jcall.c in all three gen
   modes of the c-tests run (it can not be driven from here: the jcall/jret pair
   is only balanced when the JIT code owns the whole call, i.e. when it is the
   program entry).  What is asserted here is the part which belongs to this
   feature: c2mir marks the function as a continuation, and the thunk contract is
   128 bytes with no FDE.  */

static const char *jret_src;
static size_t jret_pos;

static int jret_getc (void *data) {
  (void) data;
  return jret_src[jret_pos] == '\0' ? EOF : (unsigned char) jret_src[jret_pos++];
}

static void run_jret_tests (void) {
  /* A continuation with ordinary C inside: `double` locals live across a call,
     so the generator spills them to movaps/movapd stack slots.  A thunk which
     reserves 136 bytes (i.e. one that assumes a return address was pushed) puts
     every such slot 8 bytes off and the continuation faults -- this is what
     catches the H selection (verified against the 136 mutant: `-eb` segfaults).
     The address of the continuation label travels in a global, precisely so that
     no fixed hard register is involved: the pair is driven from C++ here.  */
  static const char *src
    = "void *g_ret;\n"
      "double dv[16];\n"
      "static double gsink (double a, double b, double c, double d, double e, double f,\n"
      "                     double g, double h, double i, double j, double k, double l) {\n"
      "  return a + b + c + d + e + f + g + h + i + j + k + l;\n"
      "}\n"
      "void f (void) {\n"
      "  double a = dv[0], b = dv[1], c = dv[2], d = dv[3], e = dv[4], f2 = dv[5],\n"
      "         g = dv[6], h = dv[7], i = dv[8], j = dv[9], k = dv[10], l = dv[11],\n"
      "         m = dv[12], n = dv[13], o = dv[14], p = dv[15];\n"
      "  double s = gsink (a, b, c, d, e, f2, g, h, i, j, k, l);\n"
      "  dv[0] = s + m + n + o + p;\n"
      "  __builtin_jret (g_ret);\n"
      "}\n"
      "int main (void) {\n"
      "  g_ret = &&lab;\n"
      "  __builtin_jcall (f);\n"
      "  return 1;\n"
      "lab:\n"
      "  return 0;\n"
      "}\n";
  /* the thunk contract of a continuation: 128 bytes, and no frame description */
  static const unsigned char adjusted[] = {0x0c, 0x07, 0x90, 0x01}; /* def_cfa rsp, 144 */
  MIR_context_t c = MIR_init ();
  struct c2mir_options ops;
  MIR_item_t jret_func = NULL, main_func = NULL;
  uint8_t *thunk;
  int i;

  memset (&ops, 0, sizeof (ops));
  ops.message_file = stderr;
  c2mir_init (c);
  jret_pos = 0;
  jret_src = src;
  c2mir_compile (c, &ops, jret_getc, NULL, "<jret>", NULL);
  for (MIR_module_t m = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (c)); m != NULL;
       m = DLIST_NEXT (MIR_module_t, m)) {
    MIR_load_module (c, m); /* c2mir_compile does not do it, the driver does */
    for (MIR_item_t item = DLIST_HEAD (MIR_item_t, m->items); item != NULL;
         item = DLIST_NEXT (MIR_item_t, item))
      if (item->item_type != MIR_func_item)
        continue;
      else if (strcmp (item->u.func->name, "f") == 0)
        jret_func = item;
      else if (strcmp (item->u.func->name, "main") == 0)
        main_func = item;
  }
  check_true ("jret: c2mir marks the function as a continuation",
              jret_func != NULL && jret_func->u.func->jret_p != 0);
  MIR_gen_init (c);
  MIR_link (c, MIR_set_lazy_bb_gen_interface, NULL);
  /* run it: the continuation spills `double` locals across a call, so a thunk
     which reserves 136 bytes (an entry state that assumes a pushed return
     address) makes every movaps/movapd slot 8 bytes off and the program dies
     before it can return 0 */
  check_true ("jret: main is linked", main_func != NULL);
  if (main_func != NULL)
    check ("jret: the spilling continuation runs", ((int (*) (void)) main_func->addr) (), 0);
  MIR_gen_finish (c);
  c2mir_finish (c);
  MIR_finish (c);

  MIR_context_t ctx2 = MIR_init ();

  MIR_gen_init (ctx2);
  thunk = (uint8_t *) _MIR_get_bb_thunk_dwarf (ctx2, (void *) 0x1234, (void *) 0, 128, 0, NULL, 0,
                                               adjusted, sizeof (adjusted));
  check_true ("jret: the continuation thunk is published", thunk != NULL);
  if (thunk != NULL) {
    /* movabs r10; sub rsp,<imm32>: the reservation of a continuation is 128 and
       it must not be reachable through 136 either */
    check ("jret: the thunk movabs", thunk[0], 0x49);
    check ("jret: the thunk movabs opcode", thunk[1], 0xba);
    check ("jret: the thunk sub", thunk[10], 0x48);
    check ("jret: the thunk sub opcode", thunk[11], 0x81);
    check ("jret: the thunk sub rsp", thunk[12], 0xec);
    for (i = 0; i < 4; i++) check ("jret: the thunk reserves 128 bytes", thunk[13 + i], i == 0 ? 0x80 : 0);
    {
      struct dwarf_eh_bases bases;

      check_true ("jret: a continuation gets no frame description",
                  _Unwind_Find_FDE ((void *) thunk, &bases) == NULL);
    }
  }
  MIR_gen_finish (ctx2);
  MIR_finish (ctx2);
}

/* ---------- the bb thunk protocol ---------- */

extern "C" long long bb_target (long long x) { return x + 100; }

static void *bb_wrapper_addr, *bb_thunk_addr, *bb_patch_target;
static int bb_patch_p;

extern "C" void *bb_hook (void *data, void *r10) {
  hook_calls++;
  if (bb_patch_p && bb_patch_target != NULL) {
    _MIR_replace_bb_thunk (ctx, bb_thunk_addr, bb_patch_target);
    bb_patch_p = 0;
    /* the continuation after the hook return jumps to the same target */
    hook_ret = bb_patch_target;
  }
  if (hook_action == 1) {
    if (body_rbp != NULL) { /* read the caller RBP while its slot still exists */
      uintptr_t cfa = (uintptr_t) body_rbp + 32;

      memcpy (&walk_saved_rbp, (void *) (cfa - 16), sizeof (walk_saved_rbp));
    }
    walk_stack ();
  }
  if (hook_action == 2) throw (int) 7;
  (void) data;
  (void) r10;
  return hook_ret;
}

/* long long redzone_call (void *fn, long long a): fills [rsp-128, rsp-8) with
   a pattern, calls fn and returns 1 when the pattern is intact.  */
extern "C" long long redzone_call (void *fn, long long a);

__asm__ (
  ".text\n"
  ".globl redzone_call\n"
  ".type redzone_call, @function\n"
  "redzone_call:\n"
  "  .cfi_startproc\n"
  "  pushq %rbp\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %rbp, -16\n"
  "  pushq %rbx\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %rbx, -24\n"
  "  subq $8, %rsp\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  movq %rdi, %rbx\n"
  "  movq %rsi, %rbp\n"
  "  movabsq $0x5a5a5a5a5a5a5a5a, %rax\n"
  "  movq %rax, -16(%rsp)\n"
  "  movq %rax, -24(%rsp)\n"
  "  movq %rax, -32(%rsp)\n"
  "  movq %rax, -40(%rsp)\n"
  "  movq %rax, -48(%rsp)\n"
  "  movq %rax, -56(%rsp)\n"
  "  movq %rax, -64(%rsp)\n"
  "  movq %rax, -72(%rsp)\n"
  "  movq %rax, -80(%rsp)\n"
  "  movq %rax, -88(%rsp)\n"
  "  movq %rax, -96(%rsp)\n"
  "  movq %rax, -104(%rsp)\n"
  "  movq %rax, -112(%rsp)\n"
  "  movq %rax, -120(%rsp)\n"
  "  movq %rax, -128(%rsp)\n"
  "  movq %rbp, %rdi\n"
  "  callq *%rbx\n"
  "  xorq %rax, %rax\n"
  "  xorq -16(%rsp), %rax\n"
  "  xorq -24(%rsp), %rax\n"
  "  xorq -32(%rsp), %rax\n"
  "  xorq -40(%rsp), %rax\n"
  "  xorq -48(%rsp), %rax\n"
  "  xorq -56(%rsp), %rax\n"
  "  xorq -64(%rsp), %rax\n"
  "  xorq -72(%rsp), %rax\n"
  "  xorq -80(%rsp), %rax\n"
  "  xorq -88(%rsp), %rax\n"
  "  xorq -96(%rsp), %rax\n"
  "  xorq -104(%rsp), %rax\n"
  "  xorq -112(%rsp), %rax\n"
  "  xorq -120(%rsp), %rax\n"
  "  xorq -128(%rsp), %rax\n"
  "  movabsq $0x5a5a5a5a5a5a5a5a, %rcx\n"
  "  cmpq %rcx, %rax\n"
  "  sete %al\n"
  "  movzbl %al, %eax\n"
  "  addq $8, %rsp\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  popq %rbx\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %rbx\n"
  "  popq %rbp\n"
  "  .cfi_adjust_cfa_offset -8\n"
  "  .cfi_restore %rbp\n"
  "  ret\n"
  "  .cfi_endproc\n"
  ".size redzone_call, .-redzone_call\n");

/* A body with a frame (RSP is 16-byte aligned inside it) which jumps to a bb
   thunk the way the generated code does, and the fragment the thunk jumps to.
   The fragment repairs the stack of the emulated body and returns.  */
extern "C" long long internal_body (void *thunk, long long a);
/* the frame register value of internal_body (CFA = body_rbp + 32) */
extern "C" {
void *body_rbp;
}

__asm__ (
  ".text\n"
  ".globl internal_body\n"
  ".type internal_body, @function\n"
  "internal_body:\n"
  "  .cfi_startproc\n"
  "  pushq %rbp\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %rbp, -16\n"
  "  pushq %rbx\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  .cfi_offset %rbx, -24\n"
  "  subq $8, %rsp\n"
  "  .cfi_adjust_cfa_offset 8\n"
  "  movq %rsp, %rbp\n"
  "  .cfi_def_cfa_register %rbp\n"
  "  movq %rbp, body_rbp(%rip)\n"
  "  movq %rdi, %rax\n"
  "  movq %rsi, %rdi\n"
  "  jmp *%rax\n"
  "  .cfi_endproc\n"
  ".size internal_body, .-internal_body\n"
  ".globl internal_target\n"
  ".type internal_target, @function\n"
  "internal_target:\n"
  "  movabsq $0x2222, %rax\n"
  /* the epilogue of the emulated body: undo the 8-byte slot and the two pushes
     (the real fragment would return the same way through its own epilogue) */
  "  addq $8, %rsp\n"
  "  popq %rbx\n"
  "  popq %rbp\n"
  "  ret\n"
  ".size internal_target, .-internal_target\n");

extern "C" long long internal_target (void);
static long long internal_catch (void *thunk) {
  raii_guard guard (&dtors);

  try {
    return ((long long (*) (void *, long long)) &internal_body) (thunk, 1);
  } catch (int code) {
    caught = code;
    return -1;
  }
}

/* A tiny leaf which returns a value from a far away mapping. */
static void *make_far_target (long long value) {
  static const uintptr_t candidates[] = {0x200000000000ull, 0x300000000000ull, 0x100000000000ull};
  unsigned char *m = NULL;
  size_t i;

  for (i = 0; i < sizeof (candidates) / sizeof (candidates[0]); i++) {
    m = (unsigned char *) mmap ((void *) candidates[i], 4096, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (m != MAP_FAILED && m != NULL) break;
    m = NULL;
  }
  if (m == NULL) return NULL;
  /* movabs $value,%rax; ret */
  m[0] = 0x48;
  m[1] = 0xb8;
  memcpy (m + 2, &value, 8);
  m[10] = 0xc3;
  if (mprotect (m, 4096, PROT_READ | PROT_EXEC) != 0) return NULL;
  return m;
}

static void run_thunk_tests (void) {
  static const unsigned char adjusted[] = {0x0c, 0x07, 0x90, 0x01}; /* def_cfa rsp, 144 */
  uintptr_t near_target, far_target;

  if (!setup ("full", 2, NULL)) return;
  bb_wrapper_addr = _MIR_get_bb_wrapper (ctx, (void *) 0x1234, (void *) bb_hook);
  check_true ("thunk: wrapper published", bb_wrapper_addr != NULL);
  /* the entry thunk: entered by a call, so RSP is 8 modulo 16 there (136) */
  bb_thunk_addr = _MIR_get_bb_thunk_dwarf (ctx, (void *) 0x5678, bb_wrapper_addr, 136, 1, NULL, 0,
                                           adjusted, sizeof (adjusted));
  check_true ("thunk: thunk published", bb_thunk_addr != NULL);
  hook_calls = 0;
  hook_action = 0;
  bb_patch_p = 0;
  hook_ret = (void *) bb_target;
  /* the continuation of the thunk after the hook return jumps to hook_ret */
  check ("thunk: first call", ((long long (*) (long long)) bb_thunk_addr) (5), 105);
  check ("thunk: hook called", hook_calls, 1);
  /* the red zone of the caller must survive the wrapper (fresh thunk) */
  check ("thunk: red zone", redzone_call (bb_thunk_addr, 6), 1);
  /* a backtrace inside the bb hook crosses the wrapper frame */
  hook_action = 1;
  reset_probe ();
  check ("thunk: walk result", ((long long (*) (long long)) bb_thunk_addr) (1), 101);
  check_true ("thunk: the walk has at least three frames", nframes >= 3);

  /* the 5-byte patch: a target in the same code holder */
  near_target = (uintptr_t) _MIR_publish_code (ctx, (const uint8_t *) "\x48\xb8\x63\x00\x00\x00"
                                                                    "\x00\x00\x00\x00\xc3",
                                               11);
  check_true ("thunk: near target published", near_target != 0);
  bb_patch_target = (void *) near_target;
  bb_patch_p = 1;
  hook_calls = 0;
  hook_action = 0;
  /* the first call still runs the thunk continuation after the hook return */
  check ("thunk: 5-byte patch first call", ((long long (*) (long long)) bb_thunk_addr) (5), 99);
  check ("thunk: 5-byte patch hook", hook_calls, 1);
  check ("thunk: 5-byte patch opcode", ((unsigned char *) bb_thunk_addr)[0], 0xe9);
  check ("thunk: 5-byte patch direct call", ((long long (*) (long long)) bb_thunk_addr) (5), 99);
  check ("thunk: 5-byte patch hook not called again", hook_calls, 1);
  /* (the patched thunk is a bare jump, so a red zone check here would not test
     anything: it is done on the fresh thunks above) */

  /* the 13-byte patch: the target is more than 2GB away */
  hook_ret = (void *) bb_target;
  bb_thunk_addr = _MIR_get_bb_thunk_dwarf (ctx, (void *) 0x5678, bb_wrapper_addr, 136, 1, NULL, 0,
                                           adjusted, sizeof (adjusted));
  check_true ("thunk: second thunk published", bb_thunk_addr != NULL);
  hook_action = 0;
  hook_calls = 0;
  check ("thunk: far first call", ((long long (*) (long long)) bb_thunk_addr) (5), 105);
  far_target = (uintptr_t) make_far_target (77);
  check_true ("thunk: far target mapped", far_target != 0);
  if (far_target != 0) {
    int64_t dist = (int64_t) (far_target - (uintptr_t) bb_thunk_addr);

    check_true ("thunk: the target is out of the rel32 range",
                dist < INT32_MIN || dist > INT32_MAX);
    bb_patch_target = (void *) far_target;
    bb_patch_p = 1;
    hook_calls = 0;
    check ("thunk: 13-byte patch first call", ((long long (*) (long long)) bb_thunk_addr) (5), 77);
    check ("thunk: 13-byte patch hook", hook_calls, 1);
    /* movabs %r11,<far target>; jmp *%r11 (13 bytes, the continuation at 0x17
       is still intact behind them) */
    check ("thunk: 13-byte patch opcode", ((unsigned char *) bb_thunk_addr)[0], 0x49);
    check ("thunk: 13-byte patch opcode 2", ((unsigned char *) bb_thunk_addr)[1], 0xbb);
    check ("thunk: the continuation is intact",
           ((unsigned char *) bb_thunk_addr)[0x17], 0x48);
    check ("thunk: 13-byte patch direct call", ((long long (*) (long long)) bb_thunk_addr) (5), 77);
    check ("thunk: 13-byte patch hook not called again", hook_calls, 1);
  }
  /* An internal thunk (a 128-byte reservation) is entered by a jump from a body
     with a frame: its frame rules are the body rules, so a backtrace and a
     throw from the wrapper call have to cross it.  */
  {
    /* The body rules of the emulated frame: CFA = rbp+32 with the caller RBP at
       CFA-16 and the caller RBX at CFA-24.  The thunk has to carry the *whole*
       body state and not only the CFA, otherwise the unwinder can not restore
       the callee saved registers of the frame which jumped to it.  */
    static const unsigned char body_rule[] = {0x0c, 0x06, 0x20, /* def_cfa rbp, 32 */
                                              0x86, 0x02,       /* offset rbp, 2 (cfa-16) */
                                              0x83, 0x03};      /* offset rbx, 3 (cfa-24) */
    void *thunk = _MIR_get_bb_thunk_dwarf (ctx, (void *) 0x9999, bb_wrapper_addr, 128, 1, body_rule,
                                           sizeof (body_rule), body_rule, sizeof (body_rule));

    check_true ("internal thunk: published", thunk != NULL);
    hook_action = 0;
    hook_calls = 0;
    bb_patch_p = 0;
    hook_ret = (void *) &internal_target;
    check ("internal thunk: run", ((long long (*) (void *, long long)) &internal_body) (thunk, 1),
           0x2222);
    check ("internal thunk: hook called", hook_calls, 1);
    hook_action = 1;
    reset_probe ();
    check ("internal thunk: walk run",
           ((long long (*) (void *, long long)) &internal_body) (thunk, 1), 0x2222);
    /* A thunk entered by a jump reports its own frame (its PC is the return
       address into it) and the enclosing body is merged with it: the frame after
       the thunk is the caller of the body.  The checks below are the ones which
       fail when the thunk carries only the CFA and not the whole body state. */
    {
      int i = find_frame_in (thunk, (char *) thunk + 0x21);
      uintptr_t cfa = (uintptr_t) body_rbp + 32; /* the body CFA of internal_body */
      check_true ("internal thunk: the thunk frame is in the walk", i >= 0);
      if (i >= 0 && i + 1 < nframes) {
        /* libgcc reports the CFA computed for the previous frame in
           frames[k].cfa, so the CFA of the thunk frame (which has to be the CFA
           of the body it was jumped from) is in frames[i + 1].  */
        check ("internal thunk: the thunk CFA is the body CFA", (long long) frames[i + 1].cfa,
               (long long) cfa);
        /* the caller RBP is recovered through the thunk's offset rules; without
           them it would be reported as the live register of the body */
        check ("internal thunk: the caller RBP is recovered", (long long) frames[i + 1].rbp,
               (long long) walk_saved_rbp);
        check_true ("internal thunk: the recovered RBP is not the live one",
                    (long long) frames[i + 1].rbp != (long long) (uintptr_t) body_rbp);
      } else {
        check_true ("internal thunk: the caller frame is in the walk", 0);
      }
    }
    hook_action = 2;
    dtors = caught = 0;
    check ("internal thunk: throw", internal_catch (thunk), -1);
    check ("internal thunk: throw value", caught, 7);
    check ("internal thunk: throw dtor", dtors, 1);
  }
  /* a throw from inside the bb hook crosses the wrapper frame */
  bb_thunk_addr = _MIR_get_bb_thunk_dwarf (ctx, (void *) 0x5678, bb_wrapper_addr, 136, 1, NULL, 0,
                                           adjusted, sizeof (adjusted));
  hook_action = 2;
  bb_patch_p = 0;
  dtors = caught = 0;
  check ("thunk: hook throw", call_and_catch (bb_thunk_addr, 1), -1);
  check ("thunk: hook throw value", caught, 7);
  check ("thunk: hook throw dtor", dtors, 1);
  finish ();
}

int main (int argc, char **argv) {
  int i, all = argc == 1;
  int do_modes = all, do_hook = all, do_thunk = all, do_interp = all, do_leaf = all, do_growth = all,
      do_alloc = all, do_jret = all;
  const char *modes[3] = {"full", "lazy", "bb"};
  int mi, opt;

  if (!all)
    do_modes = do_hook = do_thunk = do_interp = do_leaf = do_growth = do_alloc = do_jret = 0;
  for (i = 1; i < argc; i++) {
    if (strcmp (argv[i], "full") == 0 || strcmp (argv[i], "lazy") == 0
        || strcmp (argv[i], "bb") == 0) {
      do_modes = 1;
    } else if (strcmp (argv[i], "hook") == 0) {
      do_hook = 1;
    } else if (strcmp (argv[i], "thunk") == 0) {
      do_thunk = 1;
    } else if (strcmp (argv[i], "jret") == 0) {
      do_jret = 1;
    } else if (strcmp (argv[i], "interp") == 0) {
      do_interp = 1;
    } else if (strcmp (argv[i], "leaf") == 0) {
      do_leaf = 1;
    } else if (strcmp (argv[i], "growth") == 0) {
      do_growth = 1;
    } else if (strcmp (argv[i], "allocator") == 0) {
      do_alloc = 1;
    } else {
      printf ("unknown scenario %s\n", argv[i]);
      return 1;
    }
  }
  if (do_modes) {
    /* the "full|lazy|bb" arguments select the modes explicitly */
    int only = -1;

    for (i = 1; i < argc; i++)
      for (mi = 0; mi < 3; mi++)
        if (strcmp (argv[i], modes[mi]) == 0) only = mi;
    for (mi = 0; mi < 3; mi++) {
      if (only >= 0 && only != mi) continue;
      for (opt = 0; opt <= 2; opt += 2) {
        if (!setup (modes[mi], opt, NULL)) continue;
        run_matrix (modes[mi], opt);
        finish ();
      }
    }
  }
  if (do_leaf) run_leaf_tests ();
  if (do_growth) run_growth_tests ();
  if (do_alloc) run_allocator_test ();
  if (do_interp) run_interp_tests ();
  if (do_hook) run_hook_tests ();
  if (do_thunk) run_thunk_tests ();
  if (do_jret) run_jret_tests ();
  if (fails == 0) printf ("all unwinding checks passed\n");
  else printf ("%d unwinding check(s) failed\n", fails);
  return fails == 0 ? 0 : 1;
}
