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

#include "intercept_util.h"
#include "analyze_object.h"
#include "sections.h"

#include <sys/syscall.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

/*
 * open_orig_file
 *
 * Instead of looking for the needed metadata in already mmap library,
 * all this information is read from the file, thus its original place,
 * the file where the library is in an FS. The loaded library is mmaped
 * already of course, but not necessarily the whole file is mapped as one
 * readable mem mapping -- only some segments are present in memory, but
 * information about the file's sections, and the sections themselves might
 * only be present in the original file.
 * Note on naming: memory has segments, the object file has sections.
 */
static long
open_orig_file(const struct obj_desc *obj)
{
	long fd;

	fd = syscall_no_intercept(SYS_open, obj->path, O_RDONLY);

	if (fd < 0) {
		syscall_no_intercept(SYS_write, 2,
		    obj->path, strlen(obj->path));
		xabort(" open_orig_file");
	}

	return fd;
}

void
analyze_object(struct obj_desc *obj)
{
	debug_dump("analyze %s\n", obj->path);

	long fd = open_orig_file(obj);
	struct sections sections;
	find_sections(obj, &sections, fd);

	debug_dump(
	    "%s .text mapped at 0x%016" PRIxPTR " - 0x%016" PRIxPTR " \n",
	    obj->path,
	    (uintptr_t)obj->text_start,
	    (uintptr_t)obj->text_end);

	allocate_jump_table(obj);
	allocate_nop_table(obj);

	for (Elf64_Half i = 0; i < sections.symbol_tables.count; ++i)
		find_jumps_in_section_syms(obj, &sections,
		    sections.symbol_tables.headers + i, fd);

	for (Elf64_Half i = 0; i < sections.rela_tables.count; ++i)
		find_jumps_in_section_rela(obj,
		    sections.rela_tables.headers + i, fd);

	syscall_no_intercept(SYS_close, fd);

	dispose_section_info(&sections);
}
