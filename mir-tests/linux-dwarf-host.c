/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   A pure C host of the Linux x86-64 JIT frame information: it generates one
   MIR function, calls it and walks the system stack from a native callback.
   It is a *smoke* test for the two ways to use libmir (the shared library and
   the static one with the documented dependencies); the link contract itself
   (that libmir.so records the libgcc_s dependency) is asserted by the
   dwarf-unwind-shared-needed CTest, because gcc appends -lgcc_s to every
   executable link and would hide a missing dependency here.  */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../mir.h"
#include "../mir-gen.h"

struct dwarf_eh_bases {
  void *tbase, *dbase, *func;
};
extern void *_Unwind_Find_FDE (void *pc, struct dwarf_eh_bases *bases);

/* <unwind.h> is a C++/C header of libgcc; the declarations below are the C
   subset this test uses.  */
struct _Unwind_Context;
typedef int _Unwind_Reason_Code;
typedef _Unwind_Reason_Code (*_Unwind_Trace_Fn) (struct _Unwind_Context *, void *);
extern _Unwind_Reason_Code _Unwind_Backtrace (_Unwind_Trace_Fn, void *);
extern uintptr_t _Unwind_GetIP (struct _Unwind_Context *);
extern uintptr_t _Unwind_GetCFA (struct _Unwind_Context *);

static void *jit_lo, *jit_hi;
/* the frame of main, i.e. the host frame which called the JIT code: the walk has
   to report it after the JIT frame, otherwise it stopped early */
static void *host_lo, *host_hi;
static int saw_jit, saw_host, nframes;

static _Unwind_Reason_Code trace (struct _Unwind_Context *ctx, void *arg) {
  uintptr_t pc = _Unwind_GetIP (ctx);

  (void) arg;
  nframes++;
  if ((void *) pc >= jit_lo && (void *) pc < jit_hi) saw_jit = 1;
  if ((void *) pc >= host_lo && (void *) pc < host_hi) saw_host = 1;
  return nframes > 64 ? -1 /* _URC_END_OF_STACK */ : 0 /* _URC_NO_REASON */;
}

static long long probe (long long a0, long long a1) {
  nframes = 0;
  (void) _Unwind_Backtrace (trace, NULL);
  return a0 + a1;
}

static const char *program = "m: module\n"
                             "import c_probe\n"
                             "p_probe: proto i64, i64:a, i64:b\n"
                             "p_work: proto i64, i64:k\n"
                             "work: func i64, i64:k\n"
                             " local i64:a, i64:b, i64:r\n"
                             " mov a, 1\n mov b, 2\n"
                             " call p_probe, c_probe, r, a, b\n"
                             " add r, r, k\n"
                             " ret r\n endfunc\n"
                             "endmodule\n";

int main (void) {
  MIR_context_t ctx = MIR_init ();
  MIR_module_t module;
  MIR_item_t func;
  long long res;

  MIR_scan_string (ctx, program);
  module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  func = NULL;
  for (MIR_item_t item = DLIST_HEAD (MIR_item_t, module->items); item != NULL;
       item = DLIST_NEXT (MIR_item_t, item))
    if (item->item_type == MIR_func_item && strcmp (item->u.func->name, "work") == 0) func = item;
  if (func == NULL) {
    printf ("dwarf host: no work function\n");
    return 1;
  }
  MIR_load_module (ctx, module);
  MIR_load_external (ctx, "c_probe", (void *) probe);
  MIR_gen_init (ctx);
  MIR_link (ctx, MIR_set_gen_interface, NULL);
  jit_lo = (void *) func->u.func->machine_code;
  jit_hi = (void *) ((char *) jit_lo + 65536);
  host_lo = (void *) &main;
  host_hi = (void *) ((char *) host_lo + 8192);
  res = ((long long (*) (long long)) func->addr) (5);
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
  if (res != 8) {
    printf ("dwarf host: wrong result %lld\n", res);
    return 1;
  }
  if (!saw_jit || !saw_host || nframes < 3) {
    printf ("dwarf host: the walk did not cross the JIT frame (%d %d %d)\n", saw_jit, saw_host,
            nframes);
    return 1;
  }
  printf ("dwarf host: the walk crossed the JIT frame\n");
  return 0;
}
