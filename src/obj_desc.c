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

#include "obj_desc.h"
#include "patcher.h"
#include "intercept_util.h"

#include <assert.h>

/*
 * is_bit_set - check a bit in a bitmap
 */
static bool
is_bit_set(const unsigned char *table, uint64_t offset)
{
	return table[offset / 8] & (1 << (offset % 8));
}

/*
 * set_bit - set a bit in a bitmap
 */
static void
set_bit(unsigned char *table, uint64_t offset)
{
	unsigned char tmp = (unsigned char)(1 << (offset % 8));
	table[offset / 8] |= tmp;
}

/*
 * has_jump - check if addr is known to be a destination of any
 * jump ( or subroutine call ) in the code. The address must be
 * the one seen by the current process, not the offset in the original
 * ELF file.
 */
bool
has_jump(const struct obj_desc *desc, unsigned char *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end)
		return is_bit_set(desc->jump_table,
		    (uint64_t)(addr - desc->text_start));
	else
		return false;
}

/*
 * mark_jump - Mark an address as a jump destination, see has_jump above.
 */
void
mark_jump(const struct obj_desc *desc, const unsigned char *addr)
{
	if (addr >= desc->text_start && addr <= desc->text_end)
		set_bit(desc->jump_table, (uint64_t)(addr - desc->text_start));
}

/*
 * calculate_table_count - estimate the number of entries
 * that might be used for nop table.
 */
static size_t
calculate_table_count(const struct obj_desc *desc)
{
	assert(desc->text_start < desc->text_end);

	/* how large is the text segment? */
	size_t bytes = (size_t)(desc->text_end - desc->text_start + 1);

	/*
	 * Guess: one entry per 64 bytes of machine code.
	 * This would result in zero entries for 63 bytes of text segment,
	 * so it is safer to have an absolute minimum. The 0x10000 value
	 * is just an arbitrary value.
	 * If more nops than this estimate are found (not likely), than the
	 * code just continues without remembering those nops - this does
	 * not break the patching process.
	 */
	if (bytes > 0x10000)
		return bytes / 64;
	else
		return 1024;
}

/*
 * allocate_nop_table - allocates desc->nop_table
 */
void
allocate_nop_table(struct obj_desc *desc)
{
	desc->max_nop_count = calculate_table_count(desc);
	desc->nop_count = 0;
	desc->nop_table =
	    xmmap_anon(desc->max_nop_count * sizeof(desc->nop_table[0]));
}

/*
 * allocate_jump_table
 *
 * Allocates a bitmap, where each bit represents a unique address in
 * the text section.
 */
void
allocate_jump_table(struct obj_desc *desc)
{
	/* How many bytes need to be addressed? */
	assert(desc->text_start < desc->text_end);
	size_t bytes = (size_t)(desc->text_end - desc->text_start + 1);

	/* Allocate 1 bit for each addressable byte */
	/* Plus one -- integer division can result a number too low */
	desc->jump_table = xmmap_anon(bytes / 8 + 1);
}

/*
 * mark_nop - mark an address in a text section as overwritable nop instruction
 */
void
mark_nop(struct obj_desc *desc, unsigned char *address, size_t size)
{
	if (desc->nop_count == desc->max_nop_count)
		return;

	desc->nop_table[desc->nop_count].address = address;
	desc->nop_table[desc->nop_count].size = size;
	desc->nop_count++;
}

struct obj_desc *
obj_desc_allocate(void)
{
	struct obj_desc *obj = xmmap_anon(sizeof(*obj));
	obj->nop_count = 0;
	obj->max_nop_count = 0;
	obj->patch_count = 0;

	return obj;
}
