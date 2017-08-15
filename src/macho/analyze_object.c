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

#include "intercept_util.h"
#include "analyze_object.h"
#include "obj_desc.h"

#include <inttypes.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <stdio.h>
#include <string.h>

struct analysis {
	struct obj_desc *obj;
	const struct symtab_command *symtab;
	const struct segment_command_64 *linkedit_segment;
	const struct linkedit_data_command *function_starts;
	uint32_t text_section_file_offset;
};

static const struct load_command *
next_commant(const struct load_command *command)
{
	return
	    (const struct load_command *)(((char *)command) + command->cmdsize);
}

uint64_t
read_LEB128(const unsigned char **c)
{
	const unsigned char *byte = *c;
	int shift = 0;
	uint64_t result = 0;
	do {
		result += ((*byte) & 0x7f) << shift;
		shift += 7;
	} while (((*(byte++)) & 0x80) != 0);
	*c = byte;

	return result;
}

static void
parse_function_starts(struct analysis *analysis)
{
	if (analysis->linkedit_segment == NULL)
		return;
	if (analysis->function_starts == NULL)
		return;

	debug_dump("analysis->linkedit_segment->vmaddr == %016" PRIxPTR "\n",
			(uintptr_t)analysis->linkedit_segment->vmaddr);
	debug_dump("analysis->function_starts->cmdsize == %016" PRIxPTR "\n",
			(uintptr_t)analysis->function_starts->cmdsize);
	debug_dump("analysis->function_starts->dataoff == %08" PRIx32 "\n",
			analysis->function_starts->dataoff);
	debug_dump("analysis->function_starts->datasize == %" PRIuPTR "\n",
			(uintptr_t)analysis->function_starts->datasize);

	const unsigned char *c =
		(const unsigned char *)analysis->linkedit_segment->vmaddr +
		analysis->obj->vm_slide -
		analysis->linkedit_segment->fileoff +
		analysis->function_starts->dataoff;
	const unsigned char *end = c + analysis->function_starts->datasize;
	uint64_t offset = 0;

	debug_dump("c == %016" PRIxPTR " end = %016" PRIxPTR "\n",
			(uintptr_t)c, (uintptr_t)end);

	while (c < end) {
		offset += read_LEB128(&c);
		debug_dump("c = %016" PRIxPTR " function at: %016" PRIx64 "\n",
				(uintptr_t)c, offset);
		if (offset > analysis->text_section_file_offset) {
			const unsigned char *addr = analysis->obj->text_start;
			addr += offset - analysis->text_section_file_offset;
			mark_jump(analysis->obj, addr);
		}
	}
}

static void
find_text_section(const struct segment_command_64 *command,
		struct analysis *analysis)
{
	uintptr_t addr = (uintptr_t)command + sizeof(*command);
	const struct section_64 *section = (const struct section_64 *)addr;

	uint32_t n = command->nsects;
	while ((n > 0) && (strcmp(section->sectname, SECT_TEXT) != 0)) {
		--n;
		++section;
	}

	if (n == 0)
		return; /* not found */

	/* text section found */
	addr = (uintptr_t)section->addr + analysis->obj->vm_slide;
	analysis->obj->text_start = (unsigned char *)addr;
	analysis->obj->text_end = analysis->obj->text_start + section->size;
	analysis->text_section_file_offset = section->offset;
}

static void
parse_command(const struct load_command *command, struct analysis *analysis)
{
	if (command->cmd == LC_SEGMENT_64) {
		const struct segment_command_64 *segment =
			(const struct segment_command_64 *)command;

		debug_dump("segment %s .vmaddr %016" PRIx64
			   " .fileoff %016" PRIx64 "\n",
			   segment->segname, segment->vmaddr, segment->fileoff);

		if (strcmp(segment->segname, SEG_TEXT) == 0)
			find_text_section(segment, analysis);
		else if (strcmp(segment->segname, SEG_LINKEDIT) == 0)
			analysis->linkedit_segment = segment;
	} else if (command->cmd == LC_SYMTAB) {
		analysis->symtab = (const struct symtab_command *)command;
	} else if (command->cmd == LC_FUNCTION_STARTS) {
		analysis->function_starts =
			(const struct linkedit_data_command *)command;
	}
}

void
analyze_object(struct obj_desc *obj)
{
	debug_dump("analyze %s %p at %p",
		obj->path, (void *) obj->base_addr,
		(void *) (obj->base_addr + obj->vm_slide));

	const struct mach_header_64 *header =
		(const struct mach_header_64 *) obj->base_addr;

	if (header->magic != MH_MAGIC_64)
		xabort("invalid mach-o magic marker");

	debug_dump(" filtype: %" PRIx32 " ncmds: %" PRId32 "\n",
			header->filetype, header->ncmds);

	/*
	 * uint64_t tsize;
	 * char *taddr;
	 * taddr = getsectdatafromheader_64(header, SEG_TEXT, SECT_TEXT, &tsize);
	 * obj->text_start = (unsigned char *)taddr + obj->vm_slide;
	 * obj->text_end = obj->text_start + tsize;
	 */

	struct analysis analysis = {.obj = obj, };

	debug_dump("%s text before: "
		"%016" PRIxPTR "-%016" PRIxPTR "\n",
		obj->path,
		(uintptr_t)obj->text_start,
		(uintptr_t)obj->text_end);

	const struct load_command *command =
		(const struct load_command *)(obj->base_addr + sizeof(*header));

	for (uint32_t i = 0; i < header->ncmds; ++i) {
		uintptr_t off = ((uintptr_t)command) - ((uintptr_t)obj->base_addr);
		debug_dump("at %08"PRIxPTR " cmd %" PRIx32 ": "
			".cmd=%" PRIx32 ", .cmdsize = %" PRId32 "\n",
			off, i, command->cmd, command->cmdsize);
		parse_command(command, &analysis);
		command = next_commant(command);
	}
	debug_dump("%s text at after: "
		"%016" PRIxPTR "-%016" PRIxPTR "\n",
		obj->path,
		(uintptr_t)obj->text_start,
		(uintptr_t)obj->text_end);

	if (obj->text_start != NULL) {
		allocate_jump_table(obj);
		allocate_nop_table(obj);
	}

	parse_function_starts(&analysis);

	(void) header;
}
