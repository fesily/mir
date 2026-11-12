/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   Windows x64 JIT stack unwinding tests.  Every scenario generates MIR code,
   calls it through a hand written machine-code caller (which sets the
   non-volatile register sentinels and checks them after the call), and walks
   the real Windows stack from a host probe with RtlLookupFunctionEntry and
   RtlVirtualUnwind.  The checks are about observable behaviour only: unwound
   return addresses, stack pointers, restored non-volatile registers, exception
   delivery, and function table lookup after the context is destroyed.  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../mir.h"
#include "../mir-gen.h"
#include "../mir-win64-unwind.h"

#if defined(__x86_64__) || defined(_M_AMD64)

#if defined(_MSC_VER)
#define RET_ADDR() ((void *) _ReturnAddress ())
#else
#define RET_ADDR() ((void *) __builtin_return_address (0))
#endif

static int fails = 0;

static void check (const char *what, long long got, long long want) {
  if (got != want) {
    printf ("FAIL %-40s got=%lld want=%lld\n", what, got, want);
    fails++;
  }
}

static void check_true (const char *what, int cond) {
  if (!cond) {
    printf ("FAIL %s\n", what);
    fails++;
  }
}

/* ---------- non-volatile register sentinels ---------- */

#define SENT_RBX 0x1111111122222222ull
#define SENT_RSI 0x3333333344444444ull
#define SENT_RDI 0x5555555566666666ull
#define SENT_R12 0x7777777788888888ull
#define SENT_R13 0x99999999aaaaaaaaull
#define SENT_R14 0xbbbbbbbbccccccccull
#define SENT_R15 0xddddddddeeeeeeeeull
#define SENT_XOR                                                                                   \
  (SENT_RBX ^ SENT_RSI ^ SENT_RDI ^ SENT_R12 ^ SENT_R13 ^ SENT_R14 ^ SENT_R15)

/* ---------- stack walk ---------- */

#define MAX_FRAMES 64
struct frame_rec {
  void *pc;
  unsigned long long rsp, rbx, rsi, rdi, r12, r13, r14, r15;
};

static struct frame_rec frames[MAX_FRAMES];
static int nframes;
static void *probe_ret; /* the probe return address (inside the JIT frame) */
static void *mc_ret;    /* the machine-code caller return address (inside main) */
static int probe_calls;
static int walk_enabled;
static int raise_code; /* when nonzero the probe raises instead of walking */

static void walk_stack (void) {
  CONTEXT ctx;
  int i;

  RtlCaptureContext (&ctx);
  for (i = 0; i < MAX_FRAMES; i++) {
    DWORD64 base = 0, establisher = 0;
    PRUNTIME_FUNCTION rf;
    void *handler_data = NULL;

    frames[i].pc = (void *) (uintptr_t) ctx.Rip;
    frames[i].rsp = (unsigned long long) ctx.Rsp;
    frames[i].rbx = (unsigned long long) ctx.Rbx;
    frames[i].rsi = (unsigned long long) ctx.Rsi;
    frames[i].rdi = (unsigned long long) ctx.Rdi;
    frames[i].r12 = (unsigned long long) ctx.R12;
    frames[i].r13 = (unsigned long long) ctx.R13;
    frames[i].r14 = (unsigned long long) ctx.R14;
    frames[i].r15 = (unsigned long long) ctx.R15;
    if (ctx.Rip == 0) break;
    if ((rf = RtlLookupFunctionEntry (ctx.Rip, &base, NULL)) == NULL) {
      /* a leaf frame: the return address is on the top of the stack */
      ctx.Rip = *(DWORD64 *) (uintptr_t) ctx.Rsp;
      ctx.Rsp += 8;
    } else {
      RtlVirtualUnwind (UNW_FLAG_NHANDLER, base, ctx.Rip, rf, &ctx, &handler_data, &establisher,
                        NULL);
    }
  }
  nframes = i;
}

/* RET is the return address of the function the generated code called: it has to
   be taken in that function itself (an intrinsic inside an inlined helper
   returns the address within the enclosing function).  */
static void start_probe (void *ret) {
  probe_calls++;
  probe_ret = ret;
  if (raise_code != 0) RaiseException ((DWORD) raise_code, 0, 0, NULL);
  if (walk_enabled) walk_stack ();
}

static long long probe0 (void) {
  start_probe (RET_ADDR ());
  return 0;
}

static long long probe8 (long long a0, long long a1, long long a2, long long a3, long long a4,
                         long long a5, long long a6, long long a7) {
  start_probe (RET_ADDR ());
  return a0 + 2 * a1 + 3 * a2 + 4 * a3 + 5 * a4 + 6 * a5 + 7 * a6 + 8 * a7;
}

static int find_pc (const void *pc) {
  int i;

  for (i = 0; i < nframes; i++)
    if (frames[i].pc == pc) return i;
  return -1;
}

/* The walk assertions shared by all scenarios: it has to pass the JIT frame
   which called the probe and then reach the C caller of the outer function,
   and the non-volatile sentinels must have been restored on the way.  */
static void check_walk (const char *what) {
  char buf[96];
  int i, seen_sentinels = 0;



  snprintf (buf, sizeof (buf), "%s: probe called", what);
  check_true (buf, probe_calls > 0);
  snprintf (buf, sizeof (buf), "%s: probe frame in the walk", what);
  check_true (buf, find_pc (probe_ret) >= 0);
  snprintf (buf, sizeof (buf), "%s: host caller frame in the walk", what);
  check_true (buf, find_pc (mc_ret) >= 0);
  for (i = 0; i < nframes; i++)
    if (frames[i].rbx == SENT_RBX && frames[i].rsi == SENT_RSI && frames[i].rdi == SENT_RDI
        && frames[i].r12 == SENT_R12 && frames[i].r13 == SENT_R13 && frames[i].r14 == SENT_R14
        && frames[i].r15 == SENT_R15)
      seen_sentinels = 1;
  snprintf (buf, sizeof (buf), "%s: non-volatile sentinels restored", what);
  check_true (buf, seen_sentinels);
}

/* ---------- machine-code sentinel caller ----------

   uint64_t caller (void *fn, long long a1, a2, a3): saves the non-volatile registers,
   sets the sentinels, calls fn, returns the xor of the observed non-volatile
   registers (0 when fn preserved them all).  The fn result and the caller
   return address are stored into the globals below.  The code is published with
   its own unwind information so that exceptions can also pass it.  */

static long long mc_result;
static long long mc_xmm; /* the low half of the returned xmm0 */
static unsigned char mc_code[512];
static size_t mc_len;

static void e1b (unsigned v) { mc_code[mc_len++] = (unsigned char) v; }
static void e2b (unsigned a, unsigned b) {
  e1b (a);
  e1b (b);
}
static void e4b (uint32_t v) {
  memcpy (mc_code + mc_len, &v, sizeof (v));
  mc_len += 4;
}
static void e8b (uint64_t v) {
  memcpy (mc_code + mc_len, &v, sizeof (v));
  mc_len += 8;
}
static void movabs_reg (unsigned rex, unsigned opcode, uint64_t v) {
  e2b (rex, opcode);
  e8b (v);
}

static void *build_sentinel_caller (MIR_context_t ctx) {
  struct mir_win64_unwind_builder b;
  struct _MIR_code_unwind uw;
  uint8_t info[MIR_WIN64_UNWIND_MAX_BYTES];
  size_t info_len;
  uint8_t *res;

  mir_win64_unwind_init (&b);
  mc_len = 0;
  /* push rbx; push rbp; push rsi; push rdi; push r12..r15 */
  e1b (0x53);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_RBX);
  e1b (0x55);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_RBP);
  e1b (0x56);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_RSI);
  e1b (0x57);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_RDI);
  e2b (0x41, 0x54);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_R12);
  e2b (0x41, 0x55);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_R13);
  e2b (0x41, 0x56);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_R14);
  e2b (0x41, 0x57);
  mir_win64_unwind_push_nonvol (&b, (uint8_t) mc_len, MIR_UNWREG_R15);
  /* sub rsp,56 (keeps the call 16-byte aligned and gives a home area) */
  e2b (0x48, 0x83);
  e1b (0xec);
  e1b (56);
  mir_win64_unwind_alloc (&b, (uint8_t) mc_len, 56);
  /* keep fn and the three arguments in the frame: [0]=fn [8..24]=args [32]=result */
  e2b (0x48, 0x89);
  e2b (0x4c, 0x24);
  e1b (0x00);
  e2b (0x48, 0x89);
  e2b (0x54, 0x24);
  e1b (0x08);
  e2b (0x4c, 0x89);
  e2b (0x44, 0x24);
  e1b (0x10);
  e2b (0x4c, 0x89);
  e2b (0x4c, 0x24);
  e1b (0x18);
  /* mc_ret = [rsp+0x78]  (the caller return address) */
  movabs_reg (0x48, 0xb9, (uint64_t) (uintptr_t) &mc_ret);
  e2b (0x48, 0x8b);
  e2b (0x84, 0x24);
  e4b (0x78);
  e2b (0x48, 0x89);
  e1b (0x01);
  /* the sentinels */
  movabs_reg (0x48, 0xbb, SENT_RBX);
  movabs_reg (0x48, 0xbe, SENT_RSI);
  movabs_reg (0x48, 0xbf, SENT_RDI);
  movabs_reg (0x49, 0xbc, SENT_R12);
  movabs_reg (0x49, 0xbd, SENT_R13);
  movabs_reg (0x49, 0xbe, SENT_R14);
  movabs_reg (0x49, 0xbf, SENT_R15);
  /* the floating point argument registers get known values too */
  movabs_reg (0x48, 0xb8, 0x3ff8000000000000ull); /* 1.5 */
  e2b (0x66, 0x48);
  e2b (0x0f, 0x6e);
  e1b (0xc0); /* movq %rax,%xmm0 */
  movabs_reg (0x48, 0xb8, 0x4004000000000000ull); /* 2.5 */
  e2b (0x66, 0x48);
  e2b (0x0f, 0x6e);
  e1b (0xc8); /* movq %rax,%xmm1 */
  /* the call: rcx/rdx/r8 = args, rax = fn; call *%rax */
  e2b (0x48, 0x8b);
  e2b (0x4c, 0x24);
  e1b (0x08);
  e2b (0x48, 0x8b);
  e2b (0x54, 0x24);
  e1b (0x10);
  e2b (0x4c, 0x8b);
  e2b (0x44, 0x24);
  e1b (0x18);
  e2b (0x48, 0x8b);
  e2b (0x44, 0x24);
  e1b (0x00);
  e2b (0xff, 0xd0);
  e2b (0x48, 0x89);
  e2b (0x44, 0x24);
  e1b (0x20); /* mov %rax,0x20(%rsp) */
  /* mc_xmm = xmm0 (a floating point result) */
  e2b (0x66, 0x48);
  e2b (0x0f, 0x7e);
  e1b (0xc0); /* movq %xmm0,%rax */
  movabs_reg (0x48, 0xb9, (uint64_t) (uintptr_t) &mc_xmm);
  e2b (0x48, 0x89);
  e1b (0x01); /* mov %rax,(%rcx) */
  /* xor accumulate the observed non-volatile registers */
  e2b (0x4d, 0x31);
  e1b (0xc0); /* xor %r8,%r8 */
  e2b (0x49, 0x31);
  e1b (0xd8); /* xor %r8,%rbx */
  e2b (0x49, 0x31);
  e1b (0xf0); /* xor %r8,%rsi */
  e2b (0x49, 0x31);
  e1b (0xf8); /* xor %r8,%rdi */
  e2b (0x4d, 0x31);
  e1b (0xe0); /* xor %r8,%r12 */
  e2b (0x4d, 0x31);
  e1b (0xe8); /* xor %r8,%r13 */
  e2b (0x4d, 0x31);
  e1b (0xf0); /* xor %r8,%r14 */
  e2b (0x4d, 0x31);
  e1b (0xf8); /* xor %r8,%r15 */
  /* mc_result = [rsp+0x20] */
  movabs_reg (0x48, 0xb9, (uint64_t) (uintptr_t) &mc_result);
  e2b (0x48, 0x8b);
  e2b (0x44, 0x24);
  e1b (0x20);
  e2b (0x48, 0x89);
  e1b (0x01);
  /* return the xor */
  e2b (0x4c, 0x89);
  e1b (0xc0);
  /* add rsp,56; pop r15..r12, rdi, rsi, rbp, rbx; ret */
  e2b (0x48, 0x83);
  e1b (0xc4);
  e1b (56);
  e2b (0x41, 0x5f);
  e2b (0x41, 0x5e);
  e2b (0x41, 0x5d);
  e2b (0x41, 0x5c);
  e1b (0x5f);
  e1b (0x5e);
  e1b (0x5d);
  e1b (0x5b);
  e1b (0xc3);
  if ((info_len = mir_win64_unwind_encode (&b, 0, info, sizeof (info))) == 0) {
    printf ("cannot encode the machine-code caller unwind info\n");
    fails++;
    return NULL;
  }
  uw.begin = 0;
  uw.end = mc_len;
  uw.info = info;
  uw.info_len = info_len;
  res = _MIR_publish_code_with_unwind (ctx, mc_code, mc_len, 1, &uw);
  return res;
}

typedef unsigned long long (*mc_caller_t) (void *fn, long long a1, long long a2, long long a3);
static mc_caller_t mc_caller;

/* ---------- the MIR program ---------- */

static char prog_buf[400000];
static size_t prog_len;

static void pstr (const char *s) {
  size_t n = strlen (s);

  memcpy (prog_buf + prog_len, s, n);
  prog_len += n;
}

static void pf (const char *fmt, ...) {
  va_list ap;
  int n;

  va_start (ap, fmt);
  n = vsnprintf (prog_buf + prog_len, sizeof (prog_buf) - prog_len, fmt, ap);
  va_end (ap);
  if (n > 0) prog_len += (size_t) n;
}

#define GROWTH_FUNCS 600
#define BIG_LOCALS 40

static void build_program (void) {
  int i;

  prog_len = 0;
  pstr ("m: module\n"
        "import h_probe0, h_probe8\n"
        "p_probe0: proto i64\n"
        "p_probe8: proto i64, i64:a, i64:b, i64:c, i64:d, i64:e, i64:f, i64:g, i64:h\n"
        "p_work: proto i64, i64:k\n"
        "p_big: proto i64, i64:k\n"
        "p_var: proto i64, i64:n, ...\n"
        "p_all: proto i64, i64:k\n"
        "p_bst: proto i64, i64:k\n"
        "p_seh: proto i64, i64:k\n"
        "p_add: proto i64, i64:a, i64:b\n"
        "p_ffn: proto d, d:x, d:y\n"
        "p_nofp: proto i64, i64:k\n"
        "p_g: proto i64, i64:k\n");
  /* eight values live across the probe call */
  pstr ("work: func i64, i64:k\n"
        " local i64:a0, i64:a1, i64:a2, i64:a3, i64:a4, i64:a5, i64:a6, i64:a7, i64:r\n"
        " mov a0, 1\n mov a1, 2\n mov a2, 3\n mov a3, 4\n"
        " mov a4, 5\n mov a5, 6\n mov a6, 7\n mov a7, 8\n"
        " call p_probe8, h_probe8, r, a0, a1, a2, a3, a4, a5, a6, a7\n"
        " add r, r, k\n add r, r, a0\n add r, r, a1\n add r, r, a2\n add r, r, a3\n"
        " add r, r, a4\n add r, r, a5\n add r, r, a6\n add r, r, a7\n"
        " ret r\n endfunc\n");
  /* a frame which needs more than the maximal frame register offset */
  pstr ("big: func i64, i64:k\n local i64:r");
  for (i = 0; i < BIG_LOCALS; i++) pf (", i64:b%d", i);
  pstr ("\n");
  for (i = 0; i < BIG_LOCALS; i++) pf (" mov b%d, %d\n", i, i + 1);
  pstr (" call p_probe8, h_probe8, r, b0, b1, b2, b3, b4, b5, b6, b7\n");
  for (i = 0; i < BIG_LOCALS; i++) pf (" add r, r, b%d\n", i);
  pstr (" ret r\n endfunc\n");
  /* varargs: the argument registers must survive in the caller home area */
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
  /* a dynamic frame */
  pstr ("allfn: func i64, i64:k\n"
        " local i64:a, i64:r\n"
        " alloca a, 128\n"
        " mov i64:0(a), 42\n"
        " call p_probe8, h_probe8, r, 1, 2, 3, 4, 5, 6, 7, 8\n"
        " add r, r, i64:0(a)\n"
        " ret r\n endfunc\n");
  /* an inlined callee uses bstart/bend, then a call follows */
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
  /* a function without a frame pointer and without calls: it still has to get
     ALLOC/SAVE based unwind information (the frame is bigger than the call used
     registers allow, so some values end up in non-volatile registers) */
  pstr ("nofp: func i64, i64:k\n local i64:r, i64:t");
  for (i = 0; i < 20; i++) pf (", i64:c%d", i);
  for (i = 0; i < 10; i++) pf (", i64:u%d", i);
  pstr ("\n");
  for (i = 0; i < 20; i++) pf (" mov c%d, %d\n", i, i + 1);
  /* the argument keeps the values from being constant folded, so they stay live
     and need more registers than the call used ones provide */
  for (i = 0; i < 10; i++) pf (" add u%d, k, c%d\n", i, i);
  pstr (" mov r, 0\n");
  for (i = 0; i < 10; i++) pf (" add r, r, u%d\n", i);
  for (i = 10; i < 20; i++) pf (" add r, r, c%d\n", i);
  pstr (" ret r\n endfunc\n");
  /* floating point arguments: they pass through the wrapper XMM saves */
  pstr ("ffn: func d, d:x, d:y\n"
        " local i64:r\n"
        " call p_probe0, h_probe0, r\n"
        " dadd x, x, y\n"
        " ret x\n endfunc\n");
  /* two JIT frames in a row, used by the exception tests */
  pstr ("sehfn: func i64, i64:k\n"
        " local i64:r\n"
        " call p_work, work, r, k\n"
        " ret r\n endfunc\n");
  for (i = 0; i < GROWTH_FUNCS; i++)
    pf ("g%d: func i64, i64:k\n local i64:r\n"
        " call p_probe0, h_probe0, r\n add r, r, k\n ret r\n endfunc\n",
        i);
  pstr ("endmodule\n");
}

/* ---------- the test harness ---------- */

static MIR_context_t ctx;
static MIR_module_t module;
static MIR_item_t f_work, f_big, f_var, f_all, f_bst, f_seh, f_ffn, f_nofp;
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
  probe_ret = mc_ret = NULL;
  raise_code = 0;
  walk_enabled = 1;
  mc_result = mc_xmm = 0;
}

static int setup (const char *mode, int opt_level) {
  int i;
  char name[32];

  build_program ();
  ctx = MIR_init ();
  MIR_scan_string (ctx, prog_buf);
  module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  f_work = find_func ("work");
  f_big = find_func ("big");
  f_var = find_func ("varfn");
  f_all = find_func ("allfn");
  f_bst = find_func ("bstfn");
  f_seh = find_func ("sehfn");
  f_ffn = find_func ("ffn");
  f_nofp = find_func ("nofp");
  for (i = 0; i < GROWTH_FUNCS; i++) {
    snprintf (name, sizeof (name), "g%d", i);
    g_funcs[i] = find_func (name);
  }
  if (f_work == NULL || f_big == NULL || f_var == NULL || f_all == NULL || f_bst == NULL
      || f_seh == NULL || f_ffn == NULL || f_nofp == NULL
      || g_funcs[GROWTH_FUNCS - 1] == NULL) {
    printf ("unwind test: item lookup failed\n");
    fails++;
    MIR_finish (ctx);
    return 0;
  }
  MIR_load_module (ctx, module);
  MIR_load_external (ctx, "h_probe0", (void *) probe0);
  MIR_load_external (ctx, "h_probe8", (void *) probe8);
  MIR_gen_init (ctx);
  MIR_gen_set_optimize_level (ctx, (unsigned) opt_level);
  if (strcmp (mode, "full") == 0) {
    MIR_link (ctx, MIR_set_gen_interface, NULL);
  } else if (strcmp (mode, "lazy") == 0) {
    MIR_link (ctx, MIR_set_lazy_gen_interface, NULL);
  } else if (strcmp (mode, "bb") == 0) {
    MIR_link (ctx, MIR_set_lazy_bb_gen_interface, NULL);
  } else {
    printf ("unknown mode %s\n", mode);
    fails++;
    MIR_gen_finish (ctx);
    MIR_finish (ctx);
    return 0;
  }
  mc_caller = (mc_caller_t) build_sentinel_caller (ctx);
  return mc_caller != NULL;
}

/* Call ITEM through the machine-code sentinel caller and check the result, the
   preserved non-volatile registers and the walked stack.  */
static void run_one (const char *mode, int opt, const char *name, MIR_item_t item, long long a1,
                     long long a2, long long a3, long long want) {
  char what[128];
  unsigned long long x;

  reset_probe ();
  x = mc_caller (item->addr, a1, a2, a3);
  snprintf (what, sizeof (what), "%s/%d/%s", mode, opt, name);
  check_true (what, x == SENT_XOR); /* all sentinels were restored by the callee */
  snprintf (what, sizeof (what), "%s/%d/%s result", mode, opt, name);
  check (what, mc_result, want);
  snprintf (what, sizeof (what), "%s/%d/%s", mode, opt, name);
  check_walk (what);
}

static void run_scenarios (const char *mode, int opt) {
  if (!setup (mode, opt)) return;
  /* work: probe8 (1..8 weighted) + k + sum (1..8) */
  run_one (mode, opt, "work", f_work, 3, 0, 0, 204 + 3 + 36);
  /* big: probe8 (b0..b7 = 1..8) + sum (1..40) */
  run_one (mode, opt, "big", f_big, 0, 0, 0, 204 + (BIG_LOCALS * (BIG_LOCALS + 1)) / 2);
  /* varargs: (2, 10, 20) -> 30 + probe8 (1..8) */
  run_one (mode, opt, "varfn", f_var, 2, 10, 20, 30 + 204);
  /* alloca: probe8 + 42 */
  run_one (mode, opt, "allfn", f_all, 0, 0, 0, 204 + 42);
  /* the frameless function: sum (1..20) + 5, and it needs its own table entry */
  {
    DWORD64 base = 0;
    char what[128];

    reset_probe ();
    (void) mc_caller (f_nofp->addr, 5, 0, 0);
    snprintf (what, sizeof (what), "%s/%d/nofp", mode, opt);
    check (what, mc_result, 10 * 5 + (1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10) + (11 + 20) * 10 / 2);
    if (f_nofp->u.func->machine_code != NULL) { /* no code for lazy bb mode */
      snprintf (what, sizeof (what), "%s/%d/nofp table entry", mode, opt);
      check_true (what, RtlLookupFunctionEntry ((DWORD64) (uintptr_t) f_nofp->u.func->machine_code,
                                                &base, NULL)
                           != NULL);
    }
  }
  /* inline with bstart/bend: (5 + 6) + probe8 */
  run_one (mode, opt, "bstfn", f_bst, 0, 0, 0, 11 + 204);
  /* 1.5 + 2.5 = 4.0 from the floating point argument registers */
  {
    char what[128];
    unsigned long long x;

    reset_probe ();
    x = mc_caller (f_ffn->addr, 0, 0, 0);
    snprintf (what, sizeof (what), "%s/%d/ffn", mode, opt);
    check_true (what, x == SENT_XOR);
    snprintf (what, sizeof (what), "%s/%d/ffn result", mode, opt);
    check (what, mc_xmm, (long long) 0x4010000000000000ull);
    check_walk (what);
  }
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
}

/* ---------- exception delivery ---------- */

#define SEH_CODE 0xE0424D49u

#if defined(_MSC_VER)
static int seh_finally_ran;

static int run_seh_handled (MIR_item_t item, long long k) {
  reset_probe ();
  raise_code = (int) SEH_CODE;
  __try {
    (void) mc_caller (item->addr, k, 0, 0);
    return 0;
  } __except (GetExceptionCode () == SEH_CODE ? EXCEPTION_EXECUTE_HANDLER
                                              : EXCEPTION_CONTINUE_SEARCH) {
    return 1;
  }
}

static int run_seh_finally (MIR_item_t item, long long k) {
  int handled = 0;

  reset_probe ();
  raise_code = (int) SEH_CODE;
  __try {
    __try {
      (void) mc_caller (item->addr, k, 0, 0);
    } __finally {
      seh_finally_ran++;
    }
  } __except (GetExceptionCode () == SEH_CODE ? EXCEPTION_EXECUTE_HANDLER
                                              : EXCEPTION_CONTINUE_SEARCH) {
    handled = 1;
  }
  return handled;
}

static void *raising_hook (MIR_context_t c MIR_UNUSED, MIR_item_t item MIR_UNUSED) {
  RaiseException (SEH_CODE, 0, 0, NULL);
  return NULL;
}

static void run_seh (const char *mode, int opt) {
  char what[96];
  MIR_item_t item;
  void *wrapper;

  if (strcmp (mode, "bb") != 0) { /* the bb thunk does not exist for the full mode */
    if (setup (mode, opt)) {
      snprintf (what, sizeof (what), "%s/%d/seh except", mode, opt);
      check_true (what, run_seh_handled (f_seh, 1));
      seh_finally_ran = 0;
      snprintf (what, sizeof (what), "%s/%d/seh finally", mode, opt);
      check_true (what, run_seh_finally (f_seh, 1));
      snprintf (what, sizeof (what), "%s/%d/seh finally ran", mode, opt);
      check_true (what, seh_finally_ran == 1);
      /* the same through a dynamic frame */
      snprintf (what, sizeof (what), "%s/%d/seh alloca", mode, opt);
      check_true (what, run_seh_handled (f_all, 0));
      /* an exception raised inside the generation hook of a wrapper: it has to
         pass the wrapper frame and the thunk of the called function */
      item = f_work;
      wrapper = _MIR_get_wrapper (ctx, item, raising_hook);
      _MIR_redirect_thunk (ctx, item->addr, wrapper);
      reset_probe ();
      {
        int handled = 0;

        __try {
          (void) mc_caller (item->addr, 1, 0, 0);
        } __except (GetExceptionCode () == SEH_CODE ? EXCEPTION_EXECUTE_HANDLER
                                                    : EXCEPTION_CONTINUE_SEARCH) {
          handled = 1;
        }
        snprintf (what, sizeof (what), "%s/%d/seh hook except", mode, opt);
        check_true (what, handled);
      }
      MIR_gen_finish (ctx);
      MIR_finish (ctx);
    }
  }
}
#endif

/* ---------- wrapper home area isolation ----------

   A machine-code hook which destroys the 32 bytes of its own home (shadow) area
   and then returns a given target.  The wrapper must keep its saved registers
   outside the home area, so the three floating point arguments (xmm0..xmm2)
   and the integer arguments must come through unchanged.  */
static void *build_clobbering_hook (MIR_context_t c, void *target) {
  unsigned char code[64];
  size_t n = 0;

#define H1(v) (code[n++] = (unsigned char) (v))
#define H2(a, b) (H1 (a), H1 (b))
#define H8(v) (memcpy (code + n, &(v), 8), n += 8)
  H2 (0x49, 0xbb);
  {
    uint64_t junk = 0xccccccccccccccccull;

    H8 (junk);
  }
  for (int i = 0; i < 4; i++) { /* mov %r11,0x8+8*i(%rsp) */
    H2 (0x4c, 0x89);
    H2 (0x5c, 0x24);
    H1 (0x08 + 8 * i);
  }
  H2 (0x48, 0xb8); /* movabs target,%rax */
  H8 (target);
  H1 (0xc3); /* ret */
#undef H1
#undef H2
#undef H8
  return _MIR_publish_code (c, code, n);
}

static void run_clobbering_hook (void) {
  void *hook, *wrapper, *target;
  unsigned long long x;

  if (!setup ("full", 2)) return;
  target = f_ffn->u.func->machine_code;
  hook = build_clobbering_hook (ctx, target);
  wrapper = _MIR_get_wrapper (ctx, f_ffn, hook);
  _MIR_redirect_thunk (ctx, f_ffn->addr, wrapper);
  reset_probe ();
  x = mc_caller (f_ffn->addr, 0, 0, 0);
  check_true ("clobbering hook: sentinels", x == SENT_XOR);
  check ("clobbering hook: result", mc_xmm, (long long) 0x4010000000000000ull);
  check_walk ("clobbering hook");
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
}

/* ---------- growth and lifetime ---------- */

static void run_growth (const char *mode, int opt) {
  char what[96];
  int i;
  void *jit_pc = NULL;

  if (!setup (mode, opt)) return;
  for (i = 0; i < GROWTH_FUNCS; i++) {
    reset_probe ();
    (void) mc_caller (g_funcs[i]->addr, (long long) i, 0, 0);
    if (mc_result != (long long) i) {
      snprintf (what, sizeof (what), "%s/%d/growth%d", mode, opt, i);
      check (what, mc_result, i);
    }
    if (probe_calls != 1 || find_pc (probe_ret) < 0 || find_pc (mc_ret) < 0) {
      snprintf (what, sizeof (what), "%s/%d/growth%d walk", mode, opt, i);
      check_true (what, 0);
    }
    jit_pc = probe_ret;
  }
  /* generated code stays callable and unwindable after the generator is gone */
  MIR_gen_finish (ctx);
  reset_probe ();
  (void) mc_caller (g_funcs[GROWTH_FUNCS - 1]->addr, 7, 0, 0);
  snprintf (what, sizeof (what), "%s/%d/growth after gen_finish", mode, opt);
  check (what, mc_result, 7);
  check_walk (what);
  /* after the context is destroyed the function tables are gone */
  MIR_finish (ctx);
  {
    DWORD64 base = 0;

    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry ((DWORD64) (uintptr_t) jit_pc, &base, NULL);

    snprintf (what, sizeof (what), "%s/%d/lookup after finish", mode, opt);
    check_true (what, rf == NULL);
  }
  /* repeated creation/destruction of a context */
  for (i = 0; i < 3; i++) {
    if (!setup (mode, opt)) return;
    reset_probe ();
    (void) mc_caller (f_work->addr, 1, 0, 0);
    if (mc_result != 204 + 1 + 36) {
      snprintf (what, sizeof (what), "%s/%d/recreate%d", mode, opt, i);
      check (what, mc_result, 204 + 1 + 36);
    }
    MIR_gen_finish (ctx);
    MIR_finish (ctx);
  }
}

/* ---------- custom code allocator: the function tables go first ----------

   The allocator checks in its unmap callback that the recorded JIT code address
   is already gone from the function tables when the code is released.  */

static void *unmap_check_pc;
static int unmap_checks, unmap_violations;

static void *test_mem_map (size_t len, void *user_data) {
  (void) user_data;
  return VirtualAlloc (NULL, len, MEM_COMMIT, PAGE_EXECUTE);
}

static int test_mem_unmap (void *addr, size_t len, void *user_data) {
  (void) user_data;
  if (unmap_check_pc != NULL && (uintptr_t) unmap_check_pc >= (uintptr_t) addr
      && (uintptr_t) unmap_check_pc < (uintptr_t) addr + len) {
    DWORD64 base = 0;

    unmap_checks++;
    if (RtlLookupFunctionEntry ((DWORD64) (uintptr_t) unmap_check_pc, &base, NULL) != NULL)
      unmap_violations++;
  }
  (void) len;
  return VirtualFree (addr, 0, MEM_RELEASE) ? 0 : -1; /* MEM_RELEASE needs size 0 */
}

static int test_mem_protect (void *addr, size_t len, MIR_mem_protect_t prot, void *user_data) {
  DWORD old_prot = 0;
  int native_prot = prot == PROT_WRITE_EXEC ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;

  (void) user_data;
  return VirtualProtect (addr, len, native_prot, &old_prot) ? 0 : -1;
}

static void run_custom_allocator (void) {
  static struct MIR_code_alloc alloc = {test_mem_map, test_mem_unmap, test_mem_protect, NULL};

  unmap_checks = unmap_violations = 0;
  unmap_check_pc = NULL;
  build_program ();
  ctx = MIR_init2 (NULL, &alloc);
  MIR_scan_string (ctx, prog_buf);
  module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  f_work = find_func ("work");
  if (f_work == NULL) {
    printf ("FAIL custom allocator: item lookup\n");
    fails++;
    MIR_finish (ctx);
    return;
  }
  MIR_load_module (ctx, module);
  MIR_load_external (ctx, "h_probe0", (void *) probe0);
  MIR_load_external (ctx, "h_probe8", (void *) probe8);
  MIR_gen_init (ctx);
  MIR_link (ctx, MIR_set_gen_interface, NULL);
  mc_caller = (mc_caller_t) build_sentinel_caller (ctx);
  reset_probe ();
  (void) mc_caller (f_work->addr, 1, 0, 0);
  check ("custom allocator: result", mc_result, 204 + 1 + 36);
  check_walk ("custom allocator");
  unmap_check_pc = (void *) f_work->u.func->machine_code;
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
  check_true ("custom allocator: unmap checked", unmap_checks > 0);
  check_true ("custom allocator: tables deleted before release", unmap_violations == 0);
  unmap_check_pc = NULL;
}

/* ---------- prologue/epilogue instruction boundary unwinding ----------

   A small template is emitted with the same encoder and publisher as the
   generated code.  For every instruction boundary of its prologue (and the
   first epilogue instruction) the machine state is reproduced on a private
   stack, and the system unwinder has to return the original caller state.  */

static long long boundary_failures;

static const uint64_t rb_sentinel = 0xa1a2a3a4a5a6a7a8ull;

static void boundary_case (const char *what, CONTEXT *c, const void *want_rip,
                           unsigned long long want_rsp, unsigned long long want_rbp,
                           unsigned long long want_rbx) {
  DWORD64 base = 0, establisher = 0;
  PRUNTIME_FUNCTION rf;
  void *handler_data = NULL;

  if ((rf = RtlLookupFunctionEntry ((DWORD64) (uintptr_t) c->Rip, &base, NULL)) == NULL) {
    printf ("FAIL %s: no function table entry\n", what);
    boundary_failures++;
    return;
  }
  RtlVirtualUnwind (UNW_FLAG_NHANDLER, base, c->Rip, rf, c, &handler_data, &establisher, NULL);
  if ((const void *) (uintptr_t) c->Rip != want_rip || c->Rsp != want_rsp || c->Rbp != want_rbp
      || c->Rbx != want_rbx) {
    printf ("FAIL %s: rip=%p rsp=%llx rbp=%llx rbx=%llx (want %p %llx %llx %llx)\n", what,
            (void *) (uintptr_t) c->Rip, (unsigned long long) c->Rsp, (unsigned long long) c->Rbp,
            (unsigned long long) c->Rbx, want_rip, want_rsp, want_rbp, want_rbx);
    boundary_failures++;
  }
}

/* Emit a template with the encoder and publisher of the generated code and
   unwind it from every prologue instruction boundary (and from the epilogue).
   The context of every boundary is reproduced on a private stack; the system
   unwinder has to return the caller state, restoring the saved registers which
   the prologue has already stored.  */
static void run_boundaries (void) {
  /* push rbp; sub rsp,0x50; lea rbp,[rsp+0x40]; mov [rbp-0x40],rbx;
     movdqa [rbp-0x30],xmm6; nop; lea rsp,[rbp+0x10]; pop rbp; ret */
  static const uint8_t template_code[] = {
    0x55,                               /* push %rbp */
    0x48, 0x81, 0xec, 0x50, 0, 0, 0,    /* sub $0x50,%rsp */
    0x48, 0x8d, 0x6c, 0x24, 0x40,       /* lea 0x40(%rsp),%rbp */
    0x48, 0x89, 0x5d, 0xc0,             /* mov %rbx,-0x40(%rbp) */
    0x66, 0x0f, 0x7f, 0x75, 0xd0,       /* movdqa %xmm6,-0x30(%rbp) */
    0x90,                               /* nop: the prologue ends here */
    0x48, 0x8d, 0x65, 0x10,             /* lea 0x10(%rbp),%rsp */
    0x5d,                               /* pop %rbp */
    0xc3,                               /* ret */
  };
#if defined(_MSC_VER)
  __declspec (align (16)) static uint8_t stack[65536];
#else
  static uint8_t stack[65536] __attribute__ ((aligned (16)));
#endif
  struct mir_win64_unwind_builder b;
  struct _MIR_code_unwind uw;
  uint8_t info[MIR_WIN64_UNWIND_MAX_BYTES];
  size_t info_len;
  uint8_t *code;
  uintptr_t E;
  unsigned long long old_rbp = 0x5152535455565758ull;
  void *caller_rip = (void *) 0x1122334455667788ull;
  const uintptr_t after_push_rsp = 8, after_sub_rsp = 8 + 0x50;

  /* A fresh context: the template is published into an empty function table.  */
  ctx = MIR_init ();
  MIR_gen_init (ctx);
  mir_win64_unwind_init (&b);
  mir_win64_unwind_push_nonvol (&b, 1, MIR_UNWREG_RBP);
  mir_win64_unwind_alloc (&b, 8, 0x50);
  mir_win64_unwind_set_frame_reg (&b, MIR_UNWREG_RBP, 0x40);
  mir_win64_unwind_set_fpreg (&b, 0xd);
  mir_win64_unwind_save_nonvol (&b, 0x11, MIR_UNWREG_RBX, 0);
  mir_win64_unwind_save_xmm128 (&b, 0x16, 6, 0x10);
  mir_win64_unwind_set_prolog_size (&b, 0x17);
  if ((info_len = mir_win64_unwind_encode (&b, 0, info, sizeof (info))) == 0) {
    printf ("FAIL boundaries: cannot encode\n");
    fails++;
    return;
  }
  uw.begin = 0;
  uw.end = sizeof (template_code);
  uw.info = info;
  uw.info_len = info_len;
  code = _MIR_publish_code_with_unwind (ctx, template_code, sizeof (template_code), 1, &uw);
  if (code == NULL) {
    printf ("FAIL boundaries: cannot publish\n");
    fails++;
    return;
  }
  E = ((uintptr_t) stack + 32768) & ~(uintptr_t) 15;
  E += 8;                                   /* the stack at the function entry */
  *(void **) E = caller_rip;                /* the caller return address */
  *(unsigned long long *) (E - 8) = old_rbp; /* the saved frame pointer */
  *(unsigned long long *) (E - 8 - 0x50) = rb_sentinel; /* [frame base] = saved rbx */

#define BOUNDARY(name, off, rsp, rbp, init_rbx, want_rbx)                                        \
  do {                                                                                           \
    CONTEXT c;                                                                                   \
    memset (&c, 0, sizeof (c));                                                                  \
    c.Rip = (DWORD64) (uintptr_t) (code + (off));                                                \
    c.Rsp = (DWORD64) (rsp);                                                                     \
    c.Rbp = (DWORD64) (rbp);                                                                     \
    c.Rbx = (DWORD64) (init_rbx);                                                                \
    boundary_case (name, &c, caller_rip, E + 8, old_rbp, (want_rbx));                            \
  } while (0)

  BOUNDARY ("entry", 0, E, old_rbp, 0, 0);
  BOUNDARY ("after push rbp", 1, E - after_push_rsp, old_rbp, 0, 0);
  BOUNDARY ("after sub rsp", 8, E - after_sub_rsp, old_rbp, 0, 0);
  BOUNDARY ("after lea rbp", 0xd, E - after_sub_rsp, E - after_sub_rsp + 0x40, 0, 0);
  BOUNDARY ("after save rbx", 0x11, E - after_sub_rsp, E - after_sub_rsp + 0x40, 0, rb_sentinel);
  BOUNDARY ("after save xmm", 0x16, E - after_sub_rsp, E - after_sub_rsp + 0x40, 0, rb_sentinel);
  /* the epilogue restores the registers itself, so the unwinder leaves them */
  BOUNDARY ("epilogue lea rsp", 0x1b, E - after_push_rsp, E - after_sub_rsp + 0x40, rb_sentinel,
            rb_sentinel);
#undef BOUNDARY
  /* The frame without a frame register: sub rsp,0x28; mov [rsp+0x20],rbx; nop;
     add rsp,0x28; ret (the shape the generator uses for a function which does
     not need a frame pointer).  */
  {
    static const uint8_t code2[] = {
      0x48, 0x83, 0xec, 0x28,       /* sub $0x28,%rsp */
      0x48, 0x89, 0x5c, 0x24, 0x20, /* mov %rbx,0x20(%rsp) */
      0x90,                         /* nop: the prologue ends here */
      0x48, 0x83, 0xc4, 0x28,       /* add $0x28,%rsp */
      0xc3,                         /* ret */
    };
    uint8_t *code2_pub;
    const uintptr_t sub_rsp = 0x28;

    mir_win64_unwind_init (&b);
    mir_win64_unwind_alloc (&b, 4, sub_rsp);
    mir_win64_unwind_save_nonvol (&b, 9, MIR_UNWREG_RBX, 0x20);
    mir_win64_unwind_set_prolog_size (&b, 10);
    if ((info_len = mir_win64_unwind_encode (&b, 0, info, sizeof (info))) == 0) {
      printf ("FAIL boundaries: cannot encode the frameless template\n");
      fails++;
      return;
    }
    uw.begin = 0;
    uw.end = sizeof (code2);
    uw.info = info;
    uw.info_len = info_len;
    code2_pub = _MIR_publish_code_with_unwind (ctx, code2, sizeof (code2), 1, &uw);
    *(unsigned long long *) (E - 8) = rb_sentinel; /* [rsp+0x20] after the sub */
#define BOUNDARY2(name, off, rsp, init_rbx, want_rbx)                                           \
  do {                                                                                          \
    CONTEXT c;                                                                                  \
    memset (&c, 0, sizeof (c));                                                                 \
    c.Rip = (DWORD64) (uintptr_t) (code2_pub + (off));                                          \
    c.Rsp = (DWORD64) (rsp);                                                                    \
    c.Rbp = (DWORD64) old_rbp;                                                                  \
    c.Rbx = (DWORD64) (init_rbx);                                                               \
    boundary_case (name, &c, caller_rip, E + 8, old_rbp, (want_rbx));                           \
  } while (0)

    BOUNDARY2 ("frameless entry", 0, E, 0, 0);
    BOUNDARY2 ("frameless after sub", 4, E - sub_rsp, 0, 0);
    BOUNDARY2 ("frameless after save", 9, E - sub_rsp, 0, rb_sentinel);
    /* the epilogue releases the stack itself */
    BOUNDARY2 ("frameless epilogue", 0xe, E, rb_sentinel, rb_sentinel);
#undef BOUNDARY2
  }
  /* The bb thunk shape: the body rules with no code offsets plus the thunk's own
     reservation, i.e. what win64_create_frame_desc() builds for a lazy fragment
     of a function without a frame register.  The unwinder takes an explicit save
     offset relative to the RSP of the save, and the thunk has already lowered RSP
     by its reservation, so a frameless body moves its save offsets by the
     reservation (32 here); with a frame register the base is the register and
     nothing moves.  The context is the state of the thunk entry with the wrapper
     call already unwound.  */
  {
    static const uint8_t code3[] = {0x90, 0x90, 0x90, 0x90, 0xc3};
    uint8_t *code3_pub;
    const uintptr_t body_sub = 0x28, thunk_res = 0x20;
    uintptr_t base = E - body_sub; /* the frame base of the body */
    CONTEXT c;

    mir_win64_unwind_init (&b);
    mir_win64_unwind_alloc (&b, 0, body_sub);
    mir_win64_unwind_save_nonvol (&b, 0, MIR_UNWREG_RBX, 0x20 + thunk_res);
    mir_win64_unwind_set_prolog_size (&b, 0);
    mir_win64_unwind_alloc (&b, 0, thunk_res);
    if ((info_len = mir_win64_unwind_encode (&b, 1, info, sizeof (info))) == 0) {
      printf ("FAIL boundaries: cannot encode the bb thunk template\n");
      fails++;
      return;
    }
    uw.begin = 0;
    uw.end = sizeof (code3);
    uw.info = info;
    uw.info_len = info_len;
    code3_pub = _MIR_publish_code_with_unwind (ctx, code3, sizeof (code3), 1, &uw);
    memset (&c, 0, sizeof (c));
    c.Rip = (DWORD64) (uintptr_t) (code3_pub + 1);
    c.Rsp = (DWORD64) (base - thunk_res);
    c.Rbp = (DWORD64) old_rbp;
    c.Rbx = 0; /* the thunk itself does not touch it */
    boundary_case ("bb thunk after the wrapper call", &c, caller_rip, E + 8, old_rbp, rb_sentinel);
  }
  if (boundary_failures != 0) {
    printf ("FAIL boundaries: %lld case(s)\n", boundary_failures);
    fails++;
  }
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
}

/* ---------- interpreter and ff_call ---------- */

static void run_interp (void) {
  if (!setup ("full", 2)) return;
  MIR_set_interp_interface (ctx, f_work);
  reset_probe ();
  (void) mc_caller (f_work->addr, 4, 0, 0);
  check ("interp result", mc_result, 204 + 4 + 36);
  check_walk ("interp");
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
}



int main (int argc, char **argv) {
#if defined(_WIN32) && (defined(__x86_64__) || defined(_M_AMD64))
  static const char *modes[] = {"full", "lazy", "bb"};
  size_t i, n = sizeof (modes) / sizeof (modes[0]);

  setvbuf (stdout, NULL, _IONBF, 0);

  if (argc > 1) {
    for (i = 0; i < n; i++)
      if (strcmp (argv[1], modes[i]) == 0) break;
    if (i == n) {
      printf ("usage: %s [full|lazy|bb]\n", argv[0]);
      return 2;
    }
    run_scenarios (modes[i], 2);
    run_scenarios (modes[i], 0);
    run_growth (modes[i], 2);
#if defined(_MSC_VER)
    run_seh (modes[i], 2);
#endif
  } else {
    for (i = 0; i < n; i++) {
      run_scenarios (modes[i], 2);
      run_scenarios (modes[i], 0);
    }
    for (i = 0; i < n; i++) run_growth (modes[i], 2);
#if defined(_MSC_VER)
    run_seh ("full", 2);
    run_seh ("lazy", 2);
#endif
    run_boundaries ();
    run_interp ();
    run_clobbering_hook ();
    run_custom_allocator ();
  }
  if (fails != 0) {
    printf ("Win64 unwind test: %d failure(s)\n", fails);
    return 1;
  }
  printf ("Win64 unwind test: OK\n");
#endif
  return 0;
}

#endif /* x86-64 */

#endif /* _WIN32 */
