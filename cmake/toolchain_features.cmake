#
# Copyright 2017, Intel Corporation
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckCSourceCompiles)
include(CheckIncludeFiles)
include(CheckFunctionExists)

if (NOT CMAKE_VERSION VERSION_LESS 3.1.0)
	set(CMAKE_C_STANDARD 99)
	set(CMAKE_C_STANDARD_REQUIRED ON)
	set(CMAKE_CXX_STANDARD 11)
else()
	check_c_compiler_flag(-std=c99 HAS_STDC99)
	if(HAS_STDC99)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
	else()
		check_c_compiler_flag(-std=gnu99 HAS_STDGNU99)
		if(HAS_STDGNU99)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99")
		endif()
	endif()
	check_cxx_compiler_flag(-std=c++11 HAS_STDCPP11)
	if(HAS_STDCPP11)
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
	endif()
endif()

check_c_compiler_flag(-Werror HAS_WERROR)
check_c_compiler_flag(-Wall HAS_WALL)
check_c_compiler_flag(-Wextra HAS_WEXTRA)
check_c_compiler_flag(-pedantic HAS_PEDANTIC)
check_c_compiler_flag(-Wno-missing-field-initializers HAS_NOMFI)
check_c_compiler_flag(-Wno-c90-c99-compat HAS_NO9099)
check_c_compiler_flag(-Wno-c99-c11-compat HAS_NO9911)
check_c_compiler_flag(-Wno-c11-extensions HAS_NOC11WARN)
check_c_compiler_flag(-Wl,-nostdlib LINKER_HAS_NOSTDLIB)
check_c_compiler_flag(-Wl,--fatal-warnings HAS_WLFATAL)
check_c_compiler_flag(-Wno-unused-command-line-argument HAS_NOUNUSEDARG)
check_c_compiler_flag(-Wno-deprecated-declarations
			SYSCALL_INTERCEPT_WNO_WARN_DEPCRECATED)
check_c_compiler_flag(-pie HAS_ARG_PIE)
check_c_compiler_flag(-nopie HAS_ARG_NOPIE)
check_c_compiler_flag(-no-pie HAS_ARG_NO_PIE)

if(HAS_WERROR AND TREAT_WARNINGS_AS_ERRORS)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
endif()
if(HAS_WLFATAL AND TREAT_WARNINGS_AS_ERRORS)
	set(CMAKE_LD_FLAGS ${CMAKE_LD_FLAGS} -Wl,--fatal-warnings)
endif()
if(HAS_WALL)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()
if(HAS_WEXTRA)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wextra")
endif()
if(HAS_PEDANTIC)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pedantic")
endif()
if(HAS_NO9099)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-c90-c99-compat")
endif()
if(HAS_NO9911)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-c99-c11-compat")
endif()
if(HAS_NOC11WARN)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-c11-extensions")
endif()

if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang" AND HAS_NOMFI)
	# See: https://llvm.org/bugs/show_bug.cgi?id=21689
	set(CMAKE_C_FLAGS
		"${CMAKE_C_FLAGS} -Wno-missing-field-initializers")
endif()

#####################################################
#
# Check for the existance of gnu_get_libc_release, to
# infer whether the runtime library used is GNU libc.
# If it is so, use the _GNU_SOURCE macro to enable
# more extension in libc header files.
#
check_c_source_compiles("
#include <gnu/libc-version.h>
#include <stdio.h>
int main()
{ return puts(gnu_get_libc_release()); }
 " SYSCALL_INTERCEPT_WITH_GLIBC)

if(SYSCALL_INTERCEPT_WITH_GLIBC)
	set(CMAKE_REQUIRED_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS} -D_GNU_SOURCE")
	add_definitions(-D_GNU_SOURCE)
endif()

#####################################################
#
# constructor, destructor attributes
#
# language extensions
#
check_c_source_compiles("
static __attribute__((constructor)) void
entry_point(void) {}

static __attribute__((destructor)) void
exit_point(void) {}

int main(void) { return 0; }
"
 HAS_GCC_ATTR_CONSTR)

#####################################################
#
# system header pragma
#
# language extension
#
set(orig_req_incs ${CMAKE_REQUIRED_INCLUDES})
set(CMAKE_REQUIRED_INCLUDES
	"${CMAKE_REQUIRED_INCLUDES} ${PROJECT_SOURCE_DIR}/cmake")

check_c_source_compiles("
#include \"test_header.h\"

int main(void) { return 0; }
"
 SYSCALL_INTERCEPT_GCC_PRAGMA_SYSH)

set(CMAKE_REQUIRED_INCLUDES ${orig_req_incs})

#####################################################
# stdnoreturn.h header
# C11 standard library feature, considered a language extension when using C99
#
check_include_files(stdnoreturn.h SYSCALL_INTERCEPT_STDNORETURN_H)

set(orig_req_libs ${CMAKE_REQUIRED_LIBRARIES})
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_DL_LIBS})

#####################################################
# dladdr is a common libc extentsion
#
check_include_files(dlfcn.h SYSCALL_INTERCEPT_DLFCN_H)
if(SYSCALL_INTERCEPT_DLFCN_H)
	check_function_exists(dladdr SYSCALL_INTERCEPT_DLADDR)
endif()

#####################################################
# headers, symbols needed for finding/decoding objects on GNU/Linux
#
check_include_files(elf.h SYSCALL_INTERCEPT_ELF_H)
check_include_files(link.h SYSCALL_INTERCEPT_LINK_H)

if(SYSCALL_INTERCEPT_LINK_H)
	check_function_exists(dl_iterate_phdr SYSCALL_INTERCEPT_DL_ITERATE_PHDR)
endif()

#####################################################
# headers, symbols needed for finding/decoding objects on Mac OSX
#
check_include_files(mach-o/dyld.h SYSCALL_INTERCEPT_MACHO_DYLD_H)

if(SYSCALL_INTERCEPT_MACHO_DYLD_H)
	check_function_exists(_dyld_get_image_header SYSCALL_INTERCEPT_DYLD_GET_I_HEADER)
endif()

#####################################################
# getauxval(3) needed for finding Linux [vdso] using glibc
#
check_include_files(sys/auxv.h SYSCALL_INTERCEPT_SYS_AUXV_H)
if(SYSCALL_INTERCEPT_SYS_AUXV_H)
	check_function_exists(getauxval SYSCALL_INTERCEPT_GETAUXVAL)
endif()

check_include_files(sys/syscall.h SYSCALL_INTERCEPT_SYS_SYSCALL_H)

set(CMAKE_REQUIRED_LIBRARIES ${orig_req_libs})

#####################################################
# mach headers, needed for finding suitable address for trampoline table on MAC OSX
#
check_include_files(mach/mach.h SYSCALL_INTERCEPT_MACH_H)

#####################################################
# _Noreturn keyword
# C11 language feature, considered a language extension when using C99
#
check_c_source_compiles("
volatile unsigned i;
_Noreturn void x(void);
void x(void)
{
	while (1) {
		++i;
	}
}
int main(void) {
	return 0;
}
"
 SYSCALL_INTERCEPT_NORETURN_KEYWORD)

#####################################################
# noreturn macro
# C11 standard library feature, considered as an extension when using C99
#
if(SYSCALL_INTERCEPT_STDNORETURN_H)

check_c_source_compiles("
#include <stdnoreturn.h>
volatile unsigned i;
noreturn void x(void);
void x(void)
{
	while (1) {
		++i;
	}
}
int main(void) {
	return 0;
}
"
 SYSCALL_INTERCEPT_NORETURN_MACRO)

endif()

#####################################################
# noreturn attribute
# language extension
#
check_c_source_compiles("
__attribute__((noreturn)) void x(void);
volatile unsigned i;
void x(void)
{
	while (1) {
		++i;
	}
}
int main(void) {
	return 0;
}
"
 SYSCALL_INTERCEPT_NORETURN_ATTRIBUTE)

#####################################################
# format attribute
# language extension
#
check_c_source_compiles("
void x(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
int main(void) {
	return 0;
}
"
 SYSCALL_INTERCEPT_FORMAT_ATTRIBUTE)

#####################################################
# __builtin_unreachable
# language extension
#
check_c_source_compiles("
void x(int y)
{
	(void) y;
	__builtin_unreachable();
}
int main(void) {
	return 0;
}
"
 SYSCALL_INTERCEPT_BUILTIN_UNREACHABLE)

#####################################################
#
# clang diagnostic push/pop pragmas
#
# language extension
#
check_c_source_compiles("
int main(void) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored \"-Wunused-variable\"
	int x;
#pragma clang diagnostic pop
	return 0;
}
"
 SYSCALL_INTERCEPT_CLANG_DIAGNOSTIC_PRAGMA)

#####################################################
#
# GCC diagnostic push/pop pragmas
#
# language extension
#
check_c_source_compiles("
int main(void) {
#pragma gcc diagnostic push
#pragma gcc diagnostic ignored \"-Wunused-variable\"
	int x;
#pragma gcc diagnostic pop
	return 0;
}
"
 SYSCALL_INTERCEPT_GCC_DIAGNOSTIC_PRAGMA)
