/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   The plain (no unwind support) target paths, compiled and run on a host which
   does support them by building this file with -DMIR_UNWIND_DISABLE:

     * mir.c, mir-gen.c and mir-x86_64.c are compiled with that macro, so the
       branches which only macOS, *BSD, x32 and Android use are the ones which
       build here - an undeclared identifier or an unused variable in them is a
       compile error, not a broken release on another platform (two blockers of
       the first review were exactly that: see the review notes);
     * the runtime part checks that the same code still works: a JIT function is
       generated, called, and no frame information is registered for it.

   Registered by CMake next to the Linux DWARF test; it needs _Unwind_Find_FDE
   from libgcc_s, so it is a Linux x86-64 test as well.  */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../mir.h"
#include "../mir-gen.h"

struct dwarf_eh_bases {
  void *tbase, *dbase, *func;
};
extern void *_Unwind_Find_FDE (void *pc, struct dwarf_eh_bases *bases);

/* the header must have kept the guards undefined */
#if defined(MIR_DWARF_UNWIND) || defined(MIR_WIN64_UNWIND)
#error "MIR_UNWIND_DISABLE did not disable the unwind support"
#endif

static const char *program = "m: module\n"
                             "import c_probe\n"
                             "p_probe: proto i64, i64:a\n"
                             "p_work: proto i64, i64:k\n"
                             "work: func i64, i64:k\n"
                             " local i64:r\n"
                             " call p_probe, c_probe, r, k\n"
                             " add r, r, 7\n"
                             " ret r\n endfunc\n"
                             "endmodule\n";

static long long probe (long long a) { return a * 2; }

int main (void) {
  MIR_context_t ctx = MIR_init ();
  MIR_module_t module;
  MIR_item_t func = NULL;
  long long res;
  int fails = 0;

  MIR_scan_string (ctx, program);
  module = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  for (MIR_item_t item = DLIST_HEAD (MIR_item_t, module->items); item != NULL;
       item = DLIST_NEXT (MIR_item_t, item))
    if (item->item_type == MIR_func_item && strcmp (item->u.func->name, "work") == 0) func = item;
  if (func == NULL) {
    printf ("FAIL plain-unwind: no work function\n");
    return 1;
  }
  MIR_load_module (ctx, module);
  MIR_load_external (ctx, "c_probe", (void *) probe);
  MIR_gen_init (ctx);
  /* the lazy bb mode is the one which uses the legacy thunk and wrapper */
  MIR_link (ctx, MIR_set_lazy_bb_gen_interface, NULL);
  res = ((long long (*) (long long)) func->addr) (5);
  if (res != 17) {
    printf ("FAIL plain-unwind: result %lld != 17\n", res);
    fails++;
  }
  /* the plain path registers nothing: libgcc must not know the entry point */
  {
    struct dwarf_eh_bases bases;

    if (_Unwind_Find_FDE (func->addr, &bases) != NULL) {
      printf ("FAIL plain-unwind: frame information was registered\n");
      fails++;
    }
  }
  MIR_gen_finish (ctx);
  MIR_finish (ctx);
  if (fails == 0) printf ("plain-unwind: the plain target paths work\n");
  return fails == 0 ? 0 : 1;
}
