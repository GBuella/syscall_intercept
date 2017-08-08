/*
 * Copyright 2017, Intel Corporation
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
#include "obj_desc.h"
#include "intercept_util.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/* XXX */
#include <stdio.h>

#include <mach-o/dyld.h>

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

static bool
str_match(const char *name, size_t name_len,
		const char *expected)
{
	return name_len == strlen(expected) &&
		strncmp(name, expected, name_len) == 0;
}

static bool
should_patch_object(const char *name)
{
	static const char sysdir[] = "/usr/lib/system";
	static const char self[] = "libsyscall_intercept";
	static const char caps[] = "libcapstone";

	if (name == NULL)
		return false;

	if (strncmp(name, sysdir, strlen(sysdir)) == 0)
		return true;

	name = get_lib_short_name(name);
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

	return false;
}

void
allocate_next_obj_desc(struct object_list *list)
{
	struct obj_desc *obj = obj_desc_allocate();
	obj->next = list->head;
	list->head = obj;
}

static void
detect_object(struct object_list *list,
		const struct mach_header *header, const char *name, size_t slide)
{
	if (header == NULL)
		return;

	debug_dump("detect_object called on "
	    "\"%s\" at 0x%016" PRIxPTR "\n",
	    name, (uintptr_t)(void *) header);

	if (!should_patch_object(name))
		return;

	if (strstr(name, "libsystem_c.dylib") != NULL)
		list->libc_found = true;

	if (header->magic != MH_MAGIC_64)
		xabort("magical error");

	allocate_next_obj_desc(list);
	list->head->path = name;
	list->head->base_addr = (void *) header;
	list->head->vm_slide = slide;
}

struct object_list
detect_objects(int flags)
{
	(void) flags;
	struct object_list list = {.head = NULL, .libc_found = false };

	uint32_t count = _dyld_image_count();

	for (uint32_t i = 0; i < count; ++i)
		detect_object(&list, _dyld_get_image_header(i),
				_dyld_get_image_name(i),
				_dyld_get_image_vmaddr_slide(i));

	return list;
}
