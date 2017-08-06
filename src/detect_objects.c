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

#include "config.h"
#include "detect_objects.h"
#include "intercept.h"
#include "intercept_util.h"
#include "obj_desc.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>

#ifdef SYSCALL_INTERCEPT_GETAUXVAL

#include <sys/auxv.h>

static uintptr_t
get_vdso_addr(void)
{
	return (uintptr_t)getauxval(AT_SYSINFO_EHDR);
}

#else

static uintptr_t
get_vdso_addr(void)
{
	return 0;
}

#endif

struct search {
	struct object_list result;
	uintptr_t vdso_addr;
	bool libc_only;
};

static bool
is_vdso(struct search *search, uintptr_t addr, const char *path)
{
	return (search->vdso_addr != 0 && addr == search->vdso_addr) ||
		strstr(path, "vdso") != NULL;
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
 * If name_len is 4, the comparison is between: "libc" and "libc".
 */
static bool
str_match(const char *name, size_t name_len,
		const char *expected)
{
	return name_len == strlen(expected) &&
		strncmp(name, expected, name_len) == 0;
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
should_patch_object(struct search *search, uintptr_t addr, const char *path)
{
	static const char self[] = "libsyscall_intercept";
	static const char libc[] = "libc";
	static const char pthr[] = "libpthread";
	static const char caps[] = "libcapstone";

	if (is_vdso(search, addr, path)) {
		debug_dump(" - skipping: is_vdso\n");
		return false;
	}

	const char *name = get_lib_short_name(path);
	size_t len = strcspn(name, "-.");

	if (len == 0)
		return false;

	if (str_match(name, len, self)) {
		debug_dump(" - skipping: matches self\n");
		return false;
	}

	if (str_match(name, len, caps)) {
		debug_dump(" - skipping: matches capstone\n");
		return false;
	}

	if (str_match(name, len, libc)) {
		debug_dump(" - libc found\n");
		search->result.libc_found = true;
		return true;
	}

	if (!search->libc_only)
		return true;

	if (str_match(name, len, pthr)) {
		debug_dump(" - libpthread found\n");
		return true;
	}

	debug_dump(" - skipping, patch_all_objs == false\n");
	return false;
}

/*
 * get_any_used_vaddr - find a virtual address that is expected to
 * be a used for the object file mapped into memory.
 *
 * An Elf64_Phdr struct contains information about a segment in an on object
 * file. This routine looks for a segment with type LOAD, that has a non-zero
 * size in memory. The p_vaddr field contains the virtual address where this
 * segment should be loaded to. This of course is relative to the base address.
 *
 * typedef struct
 * {
 *   Elf64_Word p_type;			Segment type
 *   Elf64_Word p_flags;		Segment flags
 *   Elf64_Off p_offset;		Segment file offset
 *   Elf64_Addr p_vaddr;		Segment virtual address
 *   Elf64_Addr p_paddr;		Segment physical address
 *   Elf64_Xword p_filesz;		Segment size in file
 *   Elf64_Xword p_memsz;		Segment size in memory
 *   Elf64_Xword p_align;		Segment alignment
 * } Elf64_Phdr;
 *
 *
 */
static uintptr_t
get_any_used_vaddr(const struct dl_phdr_info *info)
{
	const Elf64_Phdr *pheaders = info->dlpi_phdr;

	for (Elf64_Word i = 0; i < info->dlpi_phnum; ++i) {
		if (pheaders[i].p_type == PT_LOAD && pheaders[i].p_memsz != 0)
			return info->dlpi_addr + pheaders[i].p_vaddr;
	}

	return 0; /* not found */
}

/*
 * get_name_from_proc_maps
 * Tries to find the path of an object file loaded at a specific
 * address.
 *
 * The paths found are stored in BSS, in the paths variable. The
 * returned pointer points into this variable. The next_path
 * pointer keeps track of the already "allocated" space inside
 * the paths array.
 */
static const char *
get_name_from_proc_maps(uintptr_t addr)
{
	static char paths[0x10000];
	static char *next_path = paths;
	const char *path = NULL;

	char line[0x2000];
	FILE *maps;

	if ((next_path >= paths + sizeof(paths) - sizeof(line)))
		return NULL; /* No more space left */

	if ((maps = fopen("/proc/self/maps", "r")) == NULL)
		return NULL;

	while ((fgets(line, sizeof(line), maps)) != NULL) {
		unsigned char *start;
		unsigned char *end;

		/* Read the path into next_path */
		if (sscanf(line, "%p-%p %*s %*x %*x:%*x %*u %s",
		    (void **)&start, (void **)&end, next_path) != 3)
			continue;

		if (addr < (uintptr_t)start)
			break;

		if ((uintptr_t)start <= addr && addr < (uintptr_t)end) {
			/*
			 * Object found, setting the return value.
			 * Adjusting the next_path pointer to point past the
			 * string found just now, to the unused space behind it.
			 * The next string found (if this routine is called
			 * again) will be stored there.
			 */
			path = next_path;
			next_path += strlen(next_path) + 1;
			break;
		}
	}

	fclose(maps);

	return path;
}

/*
 * get_object_path - attempt to find the path of the object in the
 * filesystem.
 *
 * This is usually supplied by dl_iterate_phdr in the dl_phdr_info struct,
 * but sometimes that does not contain it.
 */
static const char *
get_object_path(const struct dl_phdr_info *info)
{
	if (info->dlpi_name != NULL && info->dlpi_name[0] != '\0') {
		return info->dlpi_name;
	} else {
		uintptr_t addr = get_any_used_vaddr(info);
		if (addr == 0)
			return NULL;
		return get_name_from_proc_maps(addr);
	}
}

void
allocate_next_obj_desc(struct object_list *list)
{
	struct obj_desc *obj = obj_desc_allocate();
	obj->next = list->head;
	list->head = obj;
}

/*
 * dl_iterate_callback
 * Look at a library loaded into the current process, and determine as much as
 * possible about it. The disassembling, allocations are initiated here.
 *
 * This is a callback function, passed to dl_iterate_phdr(3).
 * data and size are just unused callback arguments.
 *
 *
 * From dl_iterate_phdr(3) man page:
 *
 * struct dl_phdr_info
 * {
 *     ElfW(Addr) dlpi_addr;             Base address of object
 *     const char *dlpi_name;            (Null-terminated) name of object
 *     const ElfW(Phdr) *dlpi_phdr;      Pointer to array of ELF program headers
 *     ElfW(Half) dlpi_phnum;            # of items in dlpi_phdr
 *     ...
 * }
 *
 */
static int
dl_iterate_callback(struct dl_phdr_info *info, size_t size, void *arg)
{
	(void) size;

	struct search *search = arg;
	const char *path;

	debug_dump("dl_iterate_callback called on "
	    "\"%s\" at 0x%016" PRIxPTR "\n",
	    info->dlpi_name, info->dlpi_addr);

	if ((path = get_object_path(info)) == NULL)
		return 0;

	if (!should_patch_object(search, info->dlpi_addr, path))
		return 0;

	allocate_next_obj_desc(&search->result);

	search->result.head->base_addr = (unsigned char *)info->dlpi_addr;
	search->result.head->path = path;

	return 0;
}

struct object_list
detect_objects(int flags)
{
	struct search search = {
	    .result = { .head = NULL, .libc_found = false },
	    .vdso_addr = get_vdso_addr(),
	    .libc_only = ((flags & detect_libc_only) != 0) };

	dl_iterate_phdr(dl_iterate_callback, &search);

	return search.result;
}
