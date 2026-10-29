/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.
   Win64 C ABI interoperability tests: C-compiled functions called from MIR
   generated code and MIR generated functions called from C, covering the
   register/stack argument classes and the aggregate size classes.  */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "../mir.h"
#include "../mir-gen.h"

#if defined(_WIN32)

static int fails = 0;

static void check (const char *what, long long got, long long want) {
  if (got != want) {
    printf ("FAIL %-12s got=%lld want=%lld\n", what, got, want);
    fails++;
  }
}

/* ---------- C (host) side ---------- */

long long h_i8 (long long a, long long b, long long c, long long d, long long e, long long f,
                long long g, long long h) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

double h_d8 (double a, double b, double c, double d, double e, double f, double g, double h) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

double h_mix (long long a, double b, long long c, double d, long long e, double f, long long g,
              double h) {
  return a + 10 * b + 100 * c + 1000 * d + 10000 * e + 100000 * f + 1000000 * g + 10000000 * h;
}

double h_var (int n, ...) {
  va_list ap;
  double s = 0;
  int i;

  va_start (ap, n);
  for (i = 0; i < n; i++) s += va_arg (ap, double);
  va_end (ap);
  return s;
}

struct S3 { char a, b, c; };
struct S5 { char a[5]; };
struct S7 { char a[7]; };
struct S8 { long long x; };
struct S16 { long long x, y; };

long long h_s3 (struct S3 s) { return s.a + 10 * s.b + 100 * s.c; }
long long h_s5 (struct S5 s) { return s.a[0] + 10 * s.a[1] + 100 * s.a[4]; }
long long h_s7 (struct S7 s) { return s.a[0] + 10 * s.a[3] + 100 * s.a[6]; }
long long h_s8 (struct S8 s) { return s.x; }
long long h_s16 (struct S16 s) { return s.x + s.y; }
struct S3 h_make3 (long long x) {
  struct S3 s = {(char) x, (char) (x + 1), (char) (x + 2)};
  return s;
}
struct S16 h_make16 (long long x) {
  struct S16 s = {x, x + 1};
  return s;
}

/* ---------- MIR side ---------- */

static const char *prog =
  "m: module\n"
  "import h_i8, h_d8, h_mix, h_var, h_s3, h_s5, h_s7, h_s8, h_s16, h_make3, h_make16\n"
  "p_i8:   proto i64, i64:a, i64:b, i64:c, i64:d, i64:e, i64:f, i64:g, i64:h\n"
  "p_d8:   proto d, d:a, d:b, d:c, d:d, d:e, d:f, d:g, d:h\n"
  "p_mix:  proto d, i64:a, d:b, i64:c, d:d, i64:e, d:f, i64:g, d:h\n"
  "p_var:  proto d, i64:n, ...\n"
  "p_s3:   proto i64, blk:3(s)\n"
  "p_s5:   proto i64, blk:5(s)\n"
  "p_s7:   proto i64, blk:7(s)\n"
  "p_s8:   proto i64, blk:8(s)\n"
  "p_s16:  proto i64, blk:16(s)\n"
  "p_m3:   proto rblk:3(dest), i64:x\n"
  "p_m16:  proto rblk:16(dest), i64:x\n"
  /* MIR -> C */
  "c_i8:   func i64\n local i64:r\n"
  " call p_i8, h_i8, r, 1, 2, 3, 4, 5, 6, 7, 8\n ret r\n endfunc\n"
  "c_d8:   func d\n local d:r\n"
  " call p_d8, h_d8, r, 1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5\n ret r\n endfunc\n"
  "c_mix:  func d\n local d:r\n"
  " call p_mix, h_mix, r, 1, 2.5, 3, 4.5, 5, 6.5, 7, 8.5\n ret r\n endfunc\n"
  "c_var:  func d\n local d:r\n"
  " call p_var, h_var, r, 4, 1.5, 2.5, 3.5, 4.5\n ret r\n endfunc\n"
  "c_s3:   func i64\n local i64:a, i64:r\n alloca a, 8\n"
  " mov i8:0(a), 1; mov i8:1(a), 2; mov i8:2(a), 3\n"
  " call p_s3, h_s3, r, blk:3(a)\n ret r\n endfunc\n"
  "c_s5:   func i64\n local i64:a, i64:r\n alloca a, 8\n"
  " mov i8:0(a), 4; mov i8:1(a), 5; mov i8:4(a), 6\n"
  " call p_s5, h_s5, r, blk:5(a)\n ret r\n endfunc\n"
  "c_s7:   func i64\n local i64:a, i64:r\n alloca a, 8\n"
  " mov i8:0(a), 7; mov i8:3(a), 8; mov i8:6(a), 9\n"
  " call p_s7, h_s7, r, blk:7(a)\n ret r\n endfunc\n"
  "c_s8:   func i64\n local i64:a, i64:r\n alloca a, 8\n"
  " mov i64:0(a), 12345\n call p_s8, h_s8, r, blk:8(a)\n ret r\n endfunc\n"
  "c_s16:  func i64\n local i64:a, i64:r\n alloca a, 16\n"
  " mov i64:0(a), 100; mov i64:8(a), 23\n call p_s16, h_s16, r, blk:16(a)\n ret r\n endfunc\n"
  "c_m3:   func i64\n local i64:a, i64:r, i64:t\n alloca a, 8\n"
  " call p_m3, h_make3, rblk:3(a), 5\n"
  " mov r, i8:0(a)\n"
  " mov t, i8:1(a); mul t, t, 10; add r, r, t\n"
  " mov t, i8:2(a); mul t, t, 100; add r, r, t\n"
  " ret r\n endfunc\n"
  "c_m16:  func i64\n local i64:a, i64:r\n alloca a, 16\n"
  " call p_m16, h_make16, rblk:16(a), 100\n"
  " mov r, i64:0(a); add r, r, i64:8(a)\n ret r\n endfunc\n"
  /* C -> MIR: same computations in generated code */
  "j_i8:   func i64, i64:a, i64:b, i64:c, i64:d, i64:e, i64:f, i64:g, i64:h\n"
  " add a, a, b; add a, a, b\n"
  " add b, c, c; add b, b, c; add a, a, b\n"
  " lsh b, d, 2; add a, a, b\n"
  " add b, e, e; lsh b, b, 1; add b, b, e; add a, a, b\n"
  " lsh b, f, 2; lsh c, f, 1; add b, b, c; add a, a, b\n"
  " lsh b, g, 3; sub b, b, g; add a, a, b\n"
  " lsh b, h, 3; add a, a, b\n ret a\n endfunc\n"
  "j_mix:  func d, i64:a, d:b, i64:c, d:d, i64:e, d:f, i64:g, d:h\n"
  " local d:acc, d:t\n"
  " i2d acc, a\n"
  " dmul t, b, 10.0; dadd acc, acc, t\n"
  " i2d t, c; dmul t, t, 100.0; dadd acc, acc, t\n"
  " dmul t, d, 1000.0; dadd acc, acc, t\n"
  " i2d t, e; dmul t, t, 10000.0; dadd acc, acc, t\n"
  " dmul t, f, 100000.0; dadd acc, acc, t\n"
  " i2d t, g; dmul t, t, 1000000.0; dadd acc, acc, t\n"
  " dmul t, h, 10000000.0; dadd acc, acc, t\n"
  " ret acc\n endfunc\n"
  "j_s3:   func i64, blk:3(s)\n local i64:r, i64:t\n"
  " mov r, i8:0(s)\n"
  " mov t, i8:1(s); mul t, t, 10; add r, r, t\n"
  " mov t, i8:2(s); mul t, t, 100; add r, r, t\n ret r\n endfunc\n"
  "j_s5:   func i64, blk:5(s)\n local i64:r, i64:t\n"
  " mov r, i8:0(s)\n"
  " mov t, i8:1(s); mul t, t, 10; add r, r, t\n"
  " mov t, i8:4(s); mul t, t, 100; add r, r, t\n ret r\n endfunc\n"
  "j_s7:   func i64, blk:7(s)\n local i64:r, i64:t\n"
  " mov r, i8:0(s)\n"
  " mov t, i8:3(s); mul t, t, 10; add r, r, t\n"
  " mov t, i8:6(s); mul t, t, 100; add r, r, t\n ret r\n endfunc\n"
  "j_s8:   func i64, blk:8(s)\n local i64:r\n mov r, i64:0(s)\n ret r\n endfunc\n"
  "j_s16:  func i64, blk:16(s)\n local i64:r\n"
  " mov r, i64:0(s); add r, r, i64:8(s)\n ret r\n endfunc\n"
  "j_m3:   func rblk:3(dest), i64:x\n"
  " mov i8:0(dest), x\n add x, x, 1; mov i8:1(dest), x\n"
  " add x, x, 1; mov i8:2(dest), x\n ret\n endfunc\n"
  "j_m16:  func rblk:16(dest), i64:x\n"
  " mov i64:0(dest), x\n add x, x, 1; mov i64:8(dest), x\n ret\n endfunc\n"
  /* variadic MIR callee called from C */
  "j_var:  func i64, i64:n, ...\n"
  " local i64:va, i64:s, i64:i, i64:v, i64:x\n"
  " alloca va, 16\n va_start va\n mov s, 0; mov i, 0\n"
  "loop: bge fin, i, n\n va_arg v, va, i32:0\n mov x, i32:0(v)\n add s, s, x\n"
  " add i, i, 1\n jmp loop\n"
  "fin: va_end va\n ret s\n endfunc\n"
  "endmodule\n";

typedef long long (*f_ii_t) (void);
typedef double (*f_d_t) (void);
typedef long long (*f_i8_t) (long long, long long, long long, long long, long long, long long,
                             long long, long long);
typedef double (*f_mix_t) (long long, double, long long, double, long long, double, long long,
                           double);
typedef long long (*f_s3_t) (struct S3);
typedef long long (*f_s5_t) (struct S5);
typedef long long (*f_s7_t) (struct S7);
typedef long long (*f_s8_t) (struct S8);
typedef long long (*f_s16_t) (struct S16);
typedef struct S3 (*f_m3_t) (long long);
typedef struct S16 (*f_m16_t) (long long);
typedef long long (*f_var_t) (long long, ...);

static MIR_item_t find_func (MIR_context_t ctx, const char *name) {
  MIR_module_t m = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  MIR_item_t item;
  for (item = DLIST_HEAD (MIR_item_t, m->items); item != NULL; item = DLIST_NEXT (MIR_item_t, item))
    if (item->item_type == MIR_func_item && strcmp (item->u.func->name, name) == 0) return item;
  return NULL;
}

#endif /* _WIN32 */

int main (void) {
#if defined(_WIN32)
  MIR_context_t ctx = MIR_init ();
  MIR_module_t m;
  MIR_item_t c_i8, c_d8, c_mix, c_var, c_s3, c_s5, c_s7, c_s8, c_s16, c_m3, c_m16;
  MIR_item_t j_i8, j_mix, j_s3, j_s5, j_s7, j_s8, j_s16, j_m3, j_m16, j_var;
  struct S3 s3 = {1, 2, 3};
  struct S5 s5 = {{4, 5, 0, 0, 6}};
  struct S7 s7 = {{7, 0, 0, 8, 0, 0, 9}};
  struct S8 s8 = {12345};
  struct S16 s16 = {100, 23};
  struct S3 r3;
  struct S16 r16;

  MIR_scan_string (ctx, prog);
  m = DLIST_HEAD (MIR_module_t, *MIR_get_module_list (ctx));
  c_i8 = find_func (ctx, "c_i8");
  c_d8 = find_func (ctx, "c_d8");
  c_mix = find_func (ctx, "c_mix");
  c_var = find_func (ctx, "c_var");
  c_s3 = find_func (ctx, "c_s3");
  c_s5 = find_func (ctx, "c_s5");
  c_s7 = find_func (ctx, "c_s7");
  c_s8 = find_func (ctx, "c_s8");
  c_s16 = find_func (ctx, "c_s16");
  c_m3 = find_func (ctx, "c_m3");
  c_m16 = find_func (ctx, "c_m16");
  j_i8 = find_func (ctx, "j_i8");
  j_mix = find_func (ctx, "j_mix");
  j_s3 = find_func (ctx, "j_s3");
  j_s5 = find_func (ctx, "j_s5");
  j_s7 = find_func (ctx, "j_s7");
  j_s8 = find_func (ctx, "j_s8");
  j_s16 = find_func (ctx, "j_s16");
  j_m3 = find_func (ctx, "j_m3");
  j_m16 = find_func (ctx, "j_m16");
  j_var = find_func (ctx, "j_var");
  if (c_i8 == NULL || c_d8 == NULL || c_mix == NULL || c_var == NULL || c_s3 == NULL
      || c_s5 == NULL || c_s7 == NULL || c_s8 == NULL || c_s16 == NULL || c_m3 == NULL
      || c_m16 == NULL || j_i8 == NULL || j_mix == NULL || j_s3 == NULL || j_s5 == NULL
      || j_s7 == NULL || j_s8 == NULL || j_s16 == NULL || j_m3 == NULL || j_m16 == NULL
      || j_var == NULL) {
    printf ("ABI test: item lookup failed\n");
    MIR_finish (ctx);
    return 1;
  }
  MIR_load_module (ctx, m);
  MIR_load_external (ctx, "h_i8", (void *) h_i8);
  MIR_load_external (ctx, "h_d8", (void *) h_d8);
  MIR_load_external (ctx, "h_mix", (void *) h_mix);
  MIR_load_external (ctx, "h_var", (void *) h_var);
  MIR_load_external (ctx, "h_s3", (void *) h_s3);
  MIR_load_external (ctx, "h_s5", (void *) h_s5);
  MIR_load_external (ctx, "h_s7", (void *) h_s7);
  MIR_load_external (ctx, "h_s8", (void *) h_s8);
  MIR_load_external (ctx, "h_s16", (void *) h_s16);
  MIR_load_external (ctx, "h_make3", (void *) h_make3);
  MIR_load_external (ctx, "h_make16", (void *) h_make16);
  MIR_gen_init (ctx);
  MIR_link (ctx, MIR_set_gen_interface, NULL);
  {
    MIR_item_t items[] = {c_i8, c_d8, c_mix, c_var, c_s3, c_s5, c_s7, c_s8, c_s16, c_m3, c_m16,
                          j_i8, j_mix, j_s3, j_s5, j_s7, j_s8, j_s16, j_m3, j_m16, j_var};
    size_t i;
    for (i = 0; i < sizeof (items) / sizeof (items[0]); i++) MIR_gen (ctx, items[i]);
  }

  check ("mir->i8", ((f_ii_t) c_i8->addr) (), h_i8 (1, 2, 3, 4, 5, 6, 7, 8));
  check ("mir->d8", (long long) (((f_d_t) c_d8->addr) () * 1e6),
         (long long) (h_d8 (1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5) * 1e6));
  check ("mir->mix", (long long) (((f_d_t) c_mix->addr) () * 1e3),
         (long long) (h_mix (1, 2.5, 3, 4.5, 5, 6.5, 7, 8.5) * 1e3));
  check ("mir->var", (long long) (((f_d_t) c_var->addr) () * 1e3),
         (long long) (h_var (4, 1.5, 2.5, 3.5, 4.5) * 1e3));
  check ("mir->s3", ((f_ii_t) c_s3->addr) (), h_s3 (s3));
  check ("mir->s5", ((f_ii_t) c_s5->addr) (), h_s5 (s5));
  check ("mir->s7", ((f_ii_t) c_s7->addr) (), h_s7 (s7));
  check ("mir->s8", ((f_ii_t) c_s8->addr) (), h_s8 (s8));
  check ("mir->s16", ((f_ii_t) c_s16->addr) (), h_s16 (s16));
  check ("mir->m3", ((f_ii_t) c_m3->addr) (),
         (long long) h_make3 (5).a + 10 * h_make3 (5).b + 100 * h_make3 (5).c);
  check ("mir->m16", ((f_ii_t) c_m16->addr) (), h_make16 (100).x + h_make16 (100).y);

  check ("c->i8", ((f_i8_t) j_i8->addr) (1, 2, 3, 4, 5, 6, 7, 8),
         h_i8 (1, 2, 3, 4, 5, 6, 7, 8));
  check ("c->mix", (long long) (((f_mix_t) j_mix->addr) (1, 2.5, 3, 4.5, 5, 6.5, 7, 8.5) * 1e3),
         (long long) (h_mix (1, 2.5, 3, 4.5, 5, 6.5, 7, 8.5) * 1e3));
  check ("c->s3", ((f_s3_t) j_s3->addr) (s3), h_s3 (s3));
  check ("c->s5", ((f_s5_t) j_s5->addr) (s5), h_s5 (s5));
  check ("c->s7", ((f_s7_t) j_s7->addr) (s7), h_s7 (s7));
  check ("c->s8", ((f_s8_t) j_s8->addr) (s8), h_s8 (s8));
  check ("c->s16", ((f_s16_t) j_s16->addr) (s16), h_s16 (s16));
  r3 = ((f_m3_t) j_m3->addr) (5);
  check ("c->m3", r3.a + 10 * r3.b + 100 * r3.c,
         h_make3 (5).a + 10 * h_make3 (5).b + 100 * h_make3 (5).c);
  r16 = ((f_m16_t) j_m16->addr) (100);
  check ("c->m16", r16.x + r16.y, h_make16 (100).x + h_make16 (100).y);
  check ("c->var", ((f_var_t) j_var->addr) (4, 10, 20, 30, 40), 100);

  MIR_gen_finish (ctx);
  MIR_finish (ctx);
  if (fails != 0) {
    printf ("Win64 ABI test: %d failure(s)\n", fails);
    return 1;
  }
  printf ("Win64 ABI test: OK\n");
#endif
  return 0;
}
