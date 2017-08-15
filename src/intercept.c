/*
 * Copyright 2016-2017, Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * intercept.c - The entry point of libsyscall_intercept, and some of
 * the main logic.
 *
 * intercept() - the library entry point
 * intercept_routine() - the entry point for each hooked syscall
 */

#include <assert.h>
#include <stdbool.h>
#include <fcntl.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "intercept.h"
#include "intercept_util.h"
#include "intercept_log.h"
#include "libsyscall_intercept_hook_point.h"
#include "disasm_wrapper.h"
#include "detect_objects.h"
#include "analyze_object.h"
#include "crawl_text.h"
#include "magic_syscalls.h"
#include "map_region_iterator.h"
#include "patcher.h"
#include "obj_desc.h"

int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);

void (*intercept_hook_point_clone_child)(void);

static void log_header(void);

static void
intercept_routine(long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			uint32_t syscall_offset,
			const char *libpath,
			long return_to_asm_wrapper_syscall,
			long return_to_asm_wrapper,
			long (*clone_wrapper)(long, long, long, long, long),
			long rsp_in_asm_wrapper);

static void clone_child_intercept_routine(void);

/*
 * intercept - This is where the highest level logic of hotpatching
 * is described. Upon startup, this routine looks for libc, and libpthread.
 * If these libraries are found in the process's address space, they are
 * patched.
 */
void
intercept(void)
{
	debug_dumps_on = getenv("INTERCEPT_DEBUG_DUMP") != NULL;

	/* Should all objects be patched, or only libc and libpthread? */
	bool patch_all_objs = (getenv("INTERCEPT_ALL_OBJS") != NULL);
	intercept_setup_log(getenv("INTERCEPT_LOG"),
			getenv("INTERCEPT_LOG_TRUNC"));
	log_header();
	init_patcher();
	map_iterator_init();

	struct object_list list =
		detect_objects(patch_all_objs ? 0 : detect_libc_only);

	if (!list.libc_found)
		xabort("libc not found");

	for (struct obj_desc *obj = list.head; obj != NULL; obj = obj->next) {
		obj->c_destination = (void *)((uintptr_t)&intercept_routine);
		obj->c_destination_clone_child =
		    (void *)((uintptr_t)&clone_child_intercept_routine);
		analyze_object(obj);
		if (obj->text_start != NULL) {
			crawl_text(obj);
			allocate_trampoline_table(obj);
			create_patch_wrappers(obj);
		}
	}

	mprotect_asm_wrappers();

	for (struct obj_desc *obj = list.head; obj != NULL; obj = obj->next)
		activate_patches(obj);
}

/*
 * log_header - part of logging
 * This routine outputs some potentially useful information into the log
 * file, which can be very useful during development.
 */
static void
log_header(void)
{
	static const char self_decoder[] =
		"tempfile=$(mktemp) ; tempfile2=$(mktemp) ; "
		"grep \"^/\" $0 | cut -d \" \" -f 1,2 | "
		"sed \"s/^/addr2line -p -f -e /\" > $tempfile ; "
		"{ echo ; . $tempfile ; echo ; } > $tempfile2 ; "
		"paste $tempfile2 $0 ; exit 0\n";

	intercept_log(self_decoder, sizeof(self_decoder) - 1);
}

/*
 * is_hooking_supported -- filters out some syscalls known
 * to do things with the stack, or the stack pointer, that makes
 * calling them from a C function impossible. These might need some
 * hand written assembly code to handle the situation arising
 * after return from syscalls.
 *
 * The clone syscall on Linux is a case, for which some code is
 * already prepared, and this function returns true for that syscall.
 */
static bool
is_hooking_supported(long syscall_number)
{
	(void) syscall_number;

#ifdef SYS_vfork
	if (syscall_number == SYS_vfork)
		return false;
#endif

#ifdef SYS_rt_sigreturn
	if (syscall_number == SYS_rt_sigreturn)
		return false;
#endif

#ifdef SYS_bsdthread_create
	if (syscall_number == SYS_bsdthread_create)
		return false;
#endif

#if defined(SYS_clone) && !defined(__linux)
	/*
	 * If some other system has a syscall called clone, it probably
	 * needs more analysis before syscall_intercept claims support
	 * for hooking it.
	 */
	if (syscall_number == SYS_clone)
		return false;
#endif

	return true;
}

/*
 * is_linux_clone_thread -- is the syscall a clone syscall altering
 * the stack pointer?
 * On Linux, arg1 is a pointer to be used as the stack pointer of
 * a newly created thread.
 */
static bool
is_linux_clone_thread(long syscall_number, long arg1)
{
#if defined(SYS_clone) && defined(__linux)
	if (syscall_number == SYS_clone && arg1 != 0)
		return true;
#else
	(void) syscall_number;
	(void) arg1;
#endif

	return false;
}

/*
 * intercept_routine(...)
 * This is the function called from the asm wrappers,
 * forwarding the syscall parameters to a hook function
 * if one is present.
 *
 * Arguments:
 * nr, arg0 - arg 5 -- syscall number
 *
 * For logging ( debugging, validating ):
 *
 * syscall_offset -- the offset of the original syscall
 *  instruction in the shared object
 * libpath -- the path of the .so being intercepted,
 *  e.g.: "/usr/lib/libc.so.6"
 *
 * For returning to libc:
 * return_to_asm_wrapper_syscall, return_to_asm_wrapper -- the
 *  address to jump to, when this function is done. The function
 *  is called with a faked return address on the stack ( to aid
 *  stack unwinding ). So, instead of just returning from this
 *  function, one must jump to one of these addresses. The first
 *  one triggers the execution of the syscall after restoring all
 *  registers, and before actually jumping back to the subject library.
 *
 * clone_wrapper -- the address to call in the special case of thread
 *  creation using clone.
 *
 * rsp_in_asm_wrapper -- the stack pointer to restore after returning
 *  from this function.
 */
static void
intercept_routine(long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			uint32_t syscall_offset,
			const char *libpath,
			long return_to_asm_wrapper_syscall,
			long return_to_asm_wrapper,
			long (*clone_wrapper)(long, long, long, long, long),
			long rsp_in_asm_wrapper)
{
	long result;
	int forward_to_kernel = true;

	if (handle_magic_syscalls(nr, arg0, arg1, arg2, arg3, arg4, arg5) == 0)
		xlongjmp(return_to_asm_wrapper_syscall, rsp_in_asm_wrapper, 0);

	intercept_log_syscall(libpath, nr, arg0, arg1, arg2, arg3, arg4, arg5,
	    syscall_offset, UNKNOWN, 0);

	if (intercept_hook_point != NULL &&
	    get_syscall_class(nr) == SYSCALL_CLASS_UNIX)
		forward_to_kernel = intercept_hook_point(get_syscall_number(nr),
		    arg0, arg1, arg2, arg3, arg4, arg5, &result);

	if (!is_hooking_supported(nr))
		xlongjmp(return_to_asm_wrapper_syscall, rsp_in_asm_wrapper, nr);

	if (forward_to_kernel) {
		/*
		 * The clone syscall's arg1 is a pointer to a memory region
		 * that serves as the stack space of a new child thread.
		 * If this is zero, the child thread uses the same address
		 * as stack pointer as the parent does (e.g.: a copy of
		 * of the memory area after fork).
		 *
		 * The code at clone_wrapper only returns to this routine
		 * in the parent thread. In the child thread, it calls
		 * the clone_child_intercept_routine instead, executing
		 * it on the new child threads stack, then returns to libc.
		 */
		if (is_linux_clone_thread(nr, arg1))
			result = clone_wrapper(arg0, arg1, arg2, arg3, arg4);
		else
			result = raw_syscall_no_intercept(nr,
			    arg0, arg1, arg2, arg3, arg4, arg5);
	}

	intercept_log_syscall(libpath, nr, arg0, arg1, arg2, arg3, arg4, arg5,
	    syscall_offset, KNOWN, result);

	xlongjmp(return_to_asm_wrapper, rsp_in_asm_wrapper, result);
}

/*
 * clone_child_intercept_routine
 * The routine called by an assembly wrapper when a clone syscall returns zero,
 * and a new stack pointer is used in the child thread.
 */
static void
clone_child_intercept_routine(void)
{
	if (intercept_hook_point_clone_child != NULL)
		intercept_hook_point_clone_child();
}
