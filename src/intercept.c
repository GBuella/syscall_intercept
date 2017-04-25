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
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <sys/mman.h>
#include <sys/auxv.h>

#include "intercept.h"
#include "intercept_util.h"
#include "libsyscall_intercept_hook_point.h"
#include "disasm_wrapper.h"
#include "magic_syscalls.h"

int (*intercept_hook_point)(long syscall_number,
			long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			long *result);

static void log_header(void);

void __attribute__((noreturn)) xlongjmp(long rip, long rsp, long rax);

static void
intercept_routine(long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			uint32_t syscall_offset,
			const char *libpath,
			long return_to_asm_wrapper_syscall,
			long return_to_asm_wrapper,
			long rsp_in_asm_wrapper);

/* Should all objects be patched, or only libc and libpthread? */
static bool patch_all_objs;

/*
 * Information collected during dissassembly phase, and anything else
 * needed for hotpatching are stored in this dynamically allocated
 * array of structs.
 * The number currently allocated is in the objs_count variable.
 */
static struct intercept_desc *objs;
static unsigned objs_count;

/* was libc found while looking for loaded objects? */
static bool libc_found;

/* address of [vdso] */
static void *vdso_addr;

/*
 * allocate_next_obj_desc
 * Handles the dynamic allocation of the struct intercept_desc array.
 * Returns a pointer to a newly allocated item.
 */
static struct intercept_desc *
allocate_next_obj_desc(void)
{
	if (objs_count == 0)
		objs = xmmap_anon(sizeof(objs[0]));
	else
		objs = xmremap(objs, objs_count * sizeof(objs[0]),
			(objs_count + 1) * sizeof(objs[0]));

	++objs_count;
	return objs + objs_count - 1;
}

/*
 * get_lib_short_name - find filename in path containing directories.
 */
static const char *
get_lib_short_name(const char *name)
{
	const char *slash = strrchr(name, '/');
	if (slash != NULL)
		name = slash + 1;

	return name;
}

/*
 * str_match - matching library names.
 * The first string (name) is not null terminated, while
 * the second string (expected) is null terminated.
 * This allows matching e.g.: "libc-2.25.so\0" with "libc\0".
 * If name_len is 4, the comparision is between: "libc" and "libc".
 */
static bool
str_match(const char *name, size_t name_len,
		const char *expected)
{
	return name_len == strlen(expected) &&
		strncmp(name, expected, name_len) == 0;
}

static const char *
get_name_from_proc_maps(uintptr_t addr)
{
	static char paths[0x10000];
	static char *next_path;
	const char *path = NULL;

	char line[0x2000];
	FILE *maps;

	if (next_path == NULL)
		next_path = paths;

	if ((paths + sizeof(paths)) - next_path < 0x1000)
		return NULL;

	if ((maps = fopen("/proc/self/maps", "r")) == NULL)
		return NULL;

	while ((fgets(line, sizeof(line), maps)) != NULL) {
		unsigned char *start;
		unsigned char *end;
		char perms[5];
		unsigned long dummy[4];

		if (sscanf(line, "%p-%p %s %lx %lx:%lx %lu %s",
		    (void **)&start, (void **)&end, perms,
		    dummy, dummy + 1, dummy + 2, dummy + 3,
		    next_path) != 8)
			break;

		if ((uintptr_t)start == addr) {
			path = next_path;
			next_path += strlen(next_path) + 1;
			break;
		}
	}

	fclose(maps);

	return path;
}

static const char *
get_object_path(const struct dl_phdr_info *info, uintptr_t addr)
{
	if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0')
		return info->dlpi_name;
	else
		return get_name_from_proc_maps(addr);
}

/*
 * should_patch_object
 * Decides whether a particular loaded object should should be targeted for
 * hotpatching.
 * Always skipped: [vdso], and the syscall_intercept library itself.
 * Besides these two, if patch_all_objs is true, everything object is
 * a target. When patch_all_objs is false, only libraries that are parts of
 * the glibc implementation are targeted, i.e.: libc and libpthread.
 */
static bool
should_patch_object(uintptr_t addr, const char *path)
{
	static const char self[] = "libsyscall_intercept";
	static const char libc[] = "libc";
	static const char pthr[] = "libpthread";
	static const char caps[] = "libcapstone";

	if (addr == (uintptr_t)vdso_addr)
		return false;

	const char *name = get_lib_short_name(path);
	size_t len = strcspn(name, "-.");

	if (len == 0)
		return false;

	if (str_match(name, len, self) || str_match(name, len, caps))
		return false;

	if (str_match(name, len, libc)) {
		libc_found = true;
		return true;
	}

	if (patch_all_objs)
		return true;

	if (str_match(name, len, pthr))
		return true;

	return false;
}

static uintptr_t
object_base_addr(struct dl_phdr_info *info)
{
	const Elf64_Phdr *pheaders = info->dlpi_phdr;

	for (Elf64_Word i = 0; i < info->dlpi_phnum; ++i) {
		if (pheaders[i].p_offset == 0)
			return info->dlpi_addr + pheaders[i].p_vaddr;
	}
	return 0; /* not found */
}

/*
 * analyze_object
 * Look at a library loaded into the current process, and determine as much as
 * possible about it. The disassembling, allocations are initiated here.
 *
 * This is a callback function, passed to dl_iterate_phdr(3).
 * data and size are just unused callback arguments.
 */
static int
analyze_object(struct dl_phdr_info *info, size_t size, void *data)
{
	(void) data;
	(void) size;
	const char *path;
	uintptr_t base_addr;

	if ((base_addr = object_base_addr(info)) == 0)
		return 0;

	char buf[128];
	sprintf(buf, "----%p----\n", (void *)base_addr);

	if ((path = get_object_path(info, base_addr)) == NULL)
		return 0;

	if (!should_patch_object(base_addr, path))
		return 0;

	struct intercept_desc *patches = allocate_next_obj_desc();

	patches->base_addr = (unsigned char *)base_addr;
	patches->load_offset = (unsigned char *)info->dlpi_addr;
	patches->path = path;
	patches->c_destination = (void *)((uintptr_t)&intercept_routine);
	find_syscalls(patches);
	allocate_trampoline_table(patches);
	create_patch_wrappers(patches);

	return 0;
}

/*
 * intercept - This is where the highest level logic of hotpatching
 * is described. Upon startup, this routine looks for libc, and libpthread.
 * If these libraries are found in the process's address space, they are
 * patched.
 */
void
intercept(void)
{
	vdso_addr = (void *)(uintptr_t)getauxval(AT_SYSINFO_EHDR);
	patch_all_objs = (getenv("INTERCEPT_ALL_OBJS") != NULL);
	intercept_setup_log(getenv("INTERCEPT_LOG"),
			getenv("INTERCEPT_LOG_TRUNC"));
	log_header();
	init_patcher();

	dl_iterate_phdr(analyze_object, NULL);
	if (!libc_found) {
		intercept_logs("libc not found");
		intercept_log_close();
		return;
	}
	mprotect_asm_wrappers();
	for (unsigned i = 0; i < objs_count; ++i)
		activate_patches(objs + i);
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
 * xabort - speaks for itself
 * Calling abort() in libc might result other syscalls being called
 * by libc.
 */
void
xabort(void)
{
	static const char msg[] = "libsyscall_intercept error\n";

	syscall_no_intercept(SYS_write, 2, msg, sizeof(msg));
	syscall_no_intercept(SYS_exit_group, 1);

	__builtin_trap();
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
			long rsp_in_asm_wrapper)
{
	long result;
	int forward_to_kernel = true;

	if (handle_magic_syscalls(nr, arg0, arg1, arg2, arg3, arg4, arg5) == 0)
		xlongjmp(return_to_asm_wrapper_syscall, rsp_in_asm_wrapper, 0);

	intercept_log_syscall(libpath, nr, arg0, arg1, arg2, arg3, arg4, arg5,
	    syscall_offset, UNKNOWN, 0);

	if (intercept_hook_point != NULL)
		forward_to_kernel = intercept_hook_point(nr,
		    arg0, arg1, arg2, arg3, arg4, arg5, &result);

	if (nr == SYS_clone ||
	    nr == SYS_vfork ||
	    nr == SYS_rt_sigreturn) {
		/* can't handle these syscall the normal way */
		xlongjmp(return_to_asm_wrapper_syscall, rsp_in_asm_wrapper, nr);
	}

	if (forward_to_kernel)
		result = syscall_no_intercept(nr,
		    arg0, arg1, arg2, arg3, arg4, arg5);

	intercept_log_syscall(libpath, nr, arg0, arg1, arg2, arg3, arg4, arg5,
	    syscall_offset, KNOWN, result);

	xlongjmp(return_to_asm_wrapper, rsp_in_asm_wrapper, result);
}
