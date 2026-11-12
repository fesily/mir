
cmake_minimum_required (VERSION 3.8)

#set(CMAKE_C_COMPILER "clang-cl")

project ("MIR")

if(NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

#set(CMAKE_VERBOSE_MAKEFILE ON)

if(NOT WIN32)
  add_compile_options(
    $<$<CONFIG:RELEASE>:-O3>
    $<$<CONFIG:RelWithDebInfo>:-O3>
  )
  # gnu11 is a C dialect: it must not leak into the C++ tests
  add_compile_options($<$<COMPILE_LANGUAGE:C>:-std=gnu11> -Wno-abi -fsigned-char -fPIC)
endif()

include(CheckCCompilerFlag)
if(CMAKE_COMPILER_IS_GNUCC)
  check_c_compiler_flag(-fno-tree-sra NO_TREE_SRA)
  if (NO_TREE_SRA)
    add_compile_options(-fno-tree-sra)
  endif()
  check_c_compiler_flag(-fno-ipa-cp-clone NO_IPA_CP_CLONE)
  if (NO_IPA_CP_CLONE)
    add_compile_options(-fno-ipa-cp-clone)
  endif()
endif()

include(FindThreads)
if(Threads_FOUND)
  link_libraries(${CMAKE_THREAD_LIBS_INIT})
endif()

message("C compiler flags: ${CMAKE_C_FLAGS}")

option(BUILD_TESTING "" ON)
include(CTest)

# The target guard of the Linux x86-64 JIT frame information (MIR_DWARF_UNWIND
# in mir-unwind-target.h): LP64 x86-64 Linux, not x32, not Android, not Apple and
# not the other Unixes.  One predicate for the dependency and for the tests.
set(MIR_DWARF_UNWIND_P FALSE)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux"
   AND NOT ANDROID
   AND CMAKE_SIZEOF_VOID_P EQUAL 8
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
  set(MIR_DWARF_UNWIND_P TRUE)
endif()

add_library(mir OBJECT mir.c mir-gen.c c2mir/c2mir.c mir.h mir-gen.h c2mir/c2mir.h)
target_include_directories(mir PRIVATE ${PROJECT_SOURCE_DIR})
if(Threads_FOUND)
  target_compile_definitions(mir PUBLIC "MIR_PARALLEL_GEN")
endif()
if(UNIX)
	target_link_libraries(mir PUBLIC m)
	# __register_frame/__deregister_frame are resolved at run time (see mir.c): a
	# link time dependency would leave the JIT-ed mir.c of the c2mir bootstrap with
	# an import its resolver cannot satisfy, and consumers would have to carry it.
endif()

# ------------------ LIBMIR -----------------------
add_library(mir_static STATIC)
target_link_libraries(mir_static PRIVATE mir)

# ------------------ LIBMIR SO --------------------
add_library(mir_shared SHARED)
if(WIN32)
  set_target_properties(mir_shared PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS TRUE)
endif()
target_link_libraries(mir_shared PRIVATE mir)

# ------------------ C2M --------------------------
add_executable (c2m "c2mir/c2mir-driver.c")
target_include_directories(c2m PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(c2m mir ${CMAKE_DL_LIBS} )

# ------------------ MIR RUN ----------------------

#add_executable (mir-run "mir-run.c")
#target_include_directories (mir-run PRIVATE ${PROJECT_SOURCE_DIR})
#target_link_libraries(mir-run mir ${CMAKE_DL_LIBS} )

# ------------------ MIR utils --------------------
add_executable (m2b "mir-utils/m2b.c")
target_include_directories(m2b PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(m2b mir)

add_executable (b2m "mir-utils/b2m.c")
target_include_directories(b2m PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(b2m mir)

add_executable (b2ctab "mir-utils/b2ctab.c")
target_include_directories(b2ctab PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(b2ctab mir)

# ------------------ L2M --------------------------
find_package(LLVM)
if(LLVM_FOUND)
  add_executable (l2m "llvm2mir/llvm2mir.c" "llvm2mir/llvm2mir-driver.c" "llvm2mir/llvm2mir.h")
  target_include_directories(l2m PRIVATE ${PROJECT_SOURCE_DIR} ${LLVM_INCLUDE_DIRS})
  target_link_libraries(l2m mir m ${CMAKE_DL_LIBS} LLVM)
endif()

# ------------------ ADT tests --------------------------
add_executable (varr_test "adt-tests/mir-varr-test.c")
target_include_directories(varr_test PRIVATE ${PROJECT_SOURCE_DIR})

add_executable (dlist_test "adt-tests/mir-dlist-test.c")
target_include_directories(dlist_test PRIVATE ${PROJECT_SOURCE_DIR})

add_executable (bitmap_test "adt-tests/mir-bitmap-test.c")
target_include_directories(bitmap_test PRIVATE ${PROJECT_SOURCE_DIR})

add_executable (htab_test "adt-tests/mir-htab-test.c")
target_include_directories(htab_test PRIVATE ${PROJECT_SOURCE_DIR})

add_executable (reduce_test "adt-tests/mir-reduce-test.c")
target_include_directories(reduce_test PRIVATE ${PROJECT_SOURCE_DIR})

add_test(varr-test varr_test)
add_test(dlist-test dlist_test)
add_test(bitmap-test bitmap_test)
add_test(htab-test htab_test)
add_test(reduce-test reduce_test ${PROJECT_SOURCE_DIR}/c2mir/c2mir.c)

# ------------------ MIR utility tests ------------------------
add_executable (simplify_test "mir-tests/simplify.c")
target_link_libraries(simplify_test mir)

add_executable (scan_test "mir-tests/scan-test.c")
target_link_libraries(scan_test mir)

add_executable (io_test "mir-tests/io.c")
target_link_libraries(io_test mir)

add_test(simplify-test simplify_test)
add_test(scan-test scan_test)
add_test(io-test io_test)

# ------------------ Common for MIR tests ----------------------
add_executable (run_test "mir-tests/run-test.c")
target_include_directories(run_test PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(run_test mir)

# ------------------ MIR interp tests --------------------------
add_executable (interp_loop "mir-tests/loop-interp.c")
target_include_directories(interp_loop PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(interp_loop PRIVATE MIR_INTERP_DEBUG=1)
target_link_libraries(interp_loop mir)

add_executable (interp_loop_c "mir-tests/loop-interp.c")
target_include_directories(interp_loop_c PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(interp_loop_c PRIVATE MIR_INTERP_DEBUG=1 MIR_C_INTERFACE=1)
target_link_libraries(interp_loop_c mir)

add_executable (interp_sieve "mir-tests/sieve-interp.c")
target_include_directories(interp_sieve PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(interp_sieve PRIVATE MIR_INTERP_DEBUG=1)
target_link_libraries(interp_sieve mir)

add_executable (interp_sieve_c "mir-tests/sieve-interp.c")
target_include_directories(interp_sieve_c PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(interp_sieve_c PRIVATE MIR_INTERP_DEBUG=1 MIR_C_INTERFACE=1)
target_link_libraries(interp_sieve_c mir)

add_executable (interp_hi "mir-tests/hi-interp.c")
target_include_directories(interp_hi PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(interp_hi PRIVATE MIR_INTERP_DEBUG=1)
target_link_libraries(interp_hi mir)

add_executable (interp_args "mir-tests/args-interp.c")
target_include_directories(interp_args PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(interp_args mir)

add_executable (interp_args_c "mir-tests/args-interp.c")
target_include_directories(interp_args_c PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(interp_args_c PRIVATE MIR_C_INTERFACE=1)
target_link_libraries(interp_args_c mir)

add_executable (run_test_d "mir-tests/run-test.c")
target_include_directories(run_test_d PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(run_test_d PRIVATE TEST_GEN_DEBUG=1)
target_link_libraries(run_test_d mir)

add_test(interp-test1 interp_loop)
add_test(interp-test2 interp_loop_c)
add_test(interp-test3 interp_sieve)
add_test(interp-test4 interp_sieve_c)
add_test(interp-test5 interp_hi)
add_test(interp-test6 interp_args)
add_test(interp-test7 interp_args_c)

foreach (num 8 9 10)
  add_test(interp-test${num} run_test -i ${PROJECT_SOURCE_DIR}/mir-tests/test${num}.mir)
endforeach()

if(NOT WIN32)
  add_test(interp-test11 run_test -i ${PROJECT_SOURCE_DIR}/mir-tests/test11.mir) # for long double >= 10 bytes
  add_test(interp-test12 run_test -i ${PROJECT_SOURCE_DIR}/mir-tests/test12.mir) # multiple return values
endif()

foreach (num 13 14 15 16)
  add_test(interp-test${num} run_test -i ${PROJECT_SOURCE_DIR}/mir-tests/test${num}.mir)
endforeach()

# ------------------ MIR gen tests --------------------------

foreach (num 1 2 3 4 5 6 7)
  add_test(gen-test${num} run_test -d ${PROJECT_SOURCE_DIR}/mir-tests/test${num}.mir)
endforeach()

foreach (num 8 9 10)
  add_test(gen-test${num} run_test -g ${PROJECT_SOURCE_DIR}/mir-tests/test${num}.mir)
endforeach()

if(NOT WIN32)
  add_test(gen-test11 run_test -g ${PROJECT_SOURCE_DIR}/mir-tests/test11.mir) # for long double >= 10 bytes
  add_test(gen-test12 run_test -g ${PROJECT_SOURCE_DIR}/mir-tests/test12.mir) # multiple return values
endif()

foreach (num 13 14 15 16)
  add_test(gen-test${num} run_test -g ${PROJECT_SOURCE_DIR}/mir-tests/test${num}.mir)
endforeach()

add_executable (gen_loop "mir-tests/loop-sieve-gen.c")
target_include_directories(gen_loop PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(gen_loop PRIVATE TEST_GEN_DEBUG=1 TEST_GEN_LOOP)
target_link_libraries(gen_loop mir)

add_executable (gen_sieve "mir-tests/loop-sieve-gen.c")
target_include_directories(gen_sieve PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(gen_sieve PRIVATE TEST_GEN_DEBUG=1 TEST_GEN_SIEVE)
target_link_libraries(gen_sieve mir)

add_test(gen-test-loop gen_loop)
add_test(gen-test-sieve gen_sieve)

# ------------------ Win64 C ABI interop test ----------------

if(WIN32)
  add_executable (win64_abi "mir-tests/win64-abi.c")
  target_include_directories(win64_abi PRIVATE ${PROJECT_SOURCE_DIR})
  target_link_libraries(win64_abi mir)

  add_test(win64-abi-test win64_abi)

  # JIT stack unwinding (Windows x64 unwind information and function tables)
  add_executable (win64_unwind "mir-tests/win64-unwind.c")
  target_include_directories(win64_unwind PRIVATE ${PROJECT_SOURCE_DIR})
  target_link_libraries(win64_unwind mir)

  add_test(win64-unwind-full win64_unwind full)
  add_test(win64-unwind-lazy win64_unwind lazy)
  add_test(win64-unwind-bb win64_unwind bb)
  add_test(win64-unwind-misc win64_unwind)
endif()

# ------------------ Linux x86-64 JIT unwinding test ----------------

if(MIR_DWARF_UNWIND_P)
  add_executable (linux_dwarf_unwind "mir-tests/linux-dwarf-unwind.cpp")
  target_include_directories(linux_dwarf_unwind PRIVATE ${PROJECT_SOURCE_DIR})
  target_link_libraries(linux_dwarf_unwind mir)
  set_property(TARGET linux_dwarf_unwind PROPERTY CXX_STANDARD 17)
  set_property(TARGET linux_dwarf_unwind PROPERTY CXX_STANDARD_REQUIRED ON)

  add_test(dwarf-unwind-full linux_dwarf_unwind full)
  add_test(dwarf-unwind-lazy linux_dwarf_unwind lazy)
  add_test(dwarf-unwind-bb linux_dwarf_unwind bb)
  add_test(dwarf-unwind-hook linux_dwarf_unwind hook)
  add_test(dwarf-unwind-thunk linux_dwarf_unwind thunk)
  add_test(dwarf-unwind-interp linux_dwarf_unwind interp)
  add_test(dwarf-unwind-leaf linux_dwarf_unwind leaf)
  add_test(dwarf-unwind-growth linux_dwarf_unwind growth)
  add_test(dwarf-unwind-allocator linux_dwarf_unwind allocator)
  add_test(dwarf-unwind-jret linux_dwarf_unwind jret)

  # A pure C host which only uses MIR (the shared and the static library): the
  # unwinder is not a dependency of libmir any more, mir.c resolves it at run
  # time, so these are the checks that a host which never links an unwinder still
  # gets its generated frames described and registered.
  add_executable (linux_dwarf_host_shared "mir-tests/linux-dwarf-host.c")
  target_include_directories(linux_dwarf_host_shared PRIVATE ${PROJECT_SOURCE_DIR})
  # the source itself calls _Unwind_*, and gcc only masks a missing -lgcc_s with
  # its implicit one (clang with --rtlib=compiler-rt does not)
  target_link_libraries(linux_dwarf_host_shared mir_shared gcc_s)
  add_test(dwarf-unwind-host-shared linux_dwarf_host_shared)

  add_executable (linux_dwarf_host_static "mir-tests/linux-dwarf-host.c")
  target_include_directories(linux_dwarf_host_static PRIVATE ${PROJECT_SOURCE_DIR})
  target_link_libraries(linux_dwarf_host_static mir_static gcc_s)
  add_test(dwarf-unwind-host-static linux_dwarf_host_static)


  # The plain target paths (macOS, *BSD, x32, Android) are compiled and run here
  # by disabling the unwind support: this is the only automated check that those
  # branches build and work, and it is what the "other targets keep the previous
  # behaviour" requirement rests on.
  add_executable (plain_unwind "mir-tests/plain-unwind.c")
  target_include_directories(plain_unwind PRIVATE ${PROJECT_SOURCE_DIR})
  target_compile_definitions(plain_unwind PRIVATE MIR_UNWIND_DISABLE)
  # the library has to be built with the same setting, so it is compiled again
  add_library(mir_plain OBJECT mir.c mir-gen.c)
  target_include_directories(mir_plain PRIVATE ${PROJECT_SOURCE_DIR})
  target_compile_definitions(mir_plain PRIVATE MIR_UNWIND_DISABLE)
  target_link_libraries(plain_unwind mir_plain ${CMAKE_DL_LIBS})
  # the test asserts the absence of any FDE with _Unwind_Find_FDE
  target_link_libraries(plain_unwind gcc_s)
  if(Threads_FOUND)
    target_link_libraries(plain_unwind ${CMAKE_THREAD_LIBS_INIT})
  endif()
  add_test(plain-unwind-test plain_unwind)
endif()

# ------------------ readme example test ----------------

add_executable (readme_example "mir-tests/readme-example.c")
target_include_directories(readme_example PRIVATE ${PROJECT_SOURCE_DIR})
target_link_libraries(readme_example mir)

add_test(readme-example-test readme_example)

# ------------------ mir2c test -------------------------

add_executable (mir2c_test "mir2c/mir2c.c")
target_include_directories(mir2c_test PRIVATE ${PROJECT_SOURCE_DIR})
target_compile_definitions(mir2c_test PRIVATE TEST_MIR2C)
target_link_libraries(mir2c_test mir)

add_test(mir2c-test mir2c_test)

# ------------------ c2m tests --------------------------

add_test(c2mir-simple-test c2m -v ${PROJECT_SOURCE_DIR}/sieve.c -ei)

