/* This file is a part of MIR project.
   Copyright (C) 2018-2024 Vladimir Makarov <vmakarov.gcc@gmail.com>.

   The one definition of the target guards of the JIT stack unwinding support.
   Every translation unit which needs them includes this file, so the guards can
   not drift apart: mir.c needs them before it includes the target file at its
   end, mir-gen.c uses them in the seams after the target file has been included,
   and the target files themselves (mir-x86_64.c, mir-gen-x86_64.c) use them from
   the first line.  */

#ifndef MIR_UNWIND_TARGET_H
#define MIR_UNWIND_TARGET_H

/* Testing hook: with -DMIR_UNWIND_DISABLE both guards stay undefined, i.e. the
   plain paths (used on macOS, *BSD, x32 and Android) are compiled and can be run
   on any host - see mir-tests/plain-unwind.c.  It is not a supported Windows
   configuration: there the metadata is what makes generated code usable at all
   (the runtime stubs and the bb wrapper are written for it), so the combination
   is rejected instead of producing a build which silently breaks SEH.  */
#if defined(MIR_UNWIND_DISABLE) && defined(_WIN32) && (defined(__x86_64__) || defined(_M_AMD64))
#error "MIR_UNWIND_DISABLE is not supported on Windows x64: generated code and the runtime stubs require version 1 UNWIND_INFO"
#endif

#ifndef MIR_UNWIND_DISABLE

/* Windows x64: version 1 UNWIND_INFO records and runtime function tables.  */
#if defined(_WIN32) && (defined(__x86_64__) || defined(_M_AMD64))
#define MIR_WIN64_UNWIND 1
#endif

/* Linux x86-64 LP64 (x32 is excluded: it is ILP32 on x86-64 and its register
   and unwind ABI is not what this implementation describes; Android is excluded
   because bionic has no libgcc_s/__register_frame): DWARF call frame information
   registered with __register_frame.  */
#if !defined(_WIN32) && !defined(__ANDROID__) && defined(__linux__) \
  && defined(__x86_64__) && defined(__LP64__)
#define MIR_DWARF_UNWIND 1
#endif

#endif /* #ifndef MIR_UNWIND_DISABLE */

#endif /* #ifndef MIR_UNWIND_TARGET_H */
