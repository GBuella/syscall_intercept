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

#ifndef SYSCALL_INTERCEPT_OBJ_DESC_H
#define SYSCALL_INTERCEPT_OBJ_DESC_H

#include <stdbool.h>
#include <stddef.h>

#include "range.h"

struct patch_desc;

struct obj_desc {

	/*
	 * uses_trampoline_table - For now this is decided runtime
	 * to make it easy to compare the operation of the library
	 * with and without it. If it is OK, we can remove this
	 * flag, and just always use the trampoline table.
	 */
	bool uses_trampoline_table;

	/*
	 * delta between vmem addresses and addresses in symbol tables,
	 * non-zero for dynamic objects
	 */
	unsigned char *base_addr;

	/* where the object is in fs */
	const char *path;

	/* Where the text starts inside the shared object */
	unsigned long text_offset;

	/*
	 * Where the text starts and ends in the virtual memory seen by the
	 * current process.
	 */
	unsigned char *text_start;
	unsigned char *text_end;


	struct patch_desc *items;
	unsigned patch_count;
	unsigned char *jump_table;

	size_t nop_count;
	size_t max_nop_count;
	struct range *nop_table;

	void *c_destination;
	void *c_destination_clone_child;

	unsigned char *trampoline_table;
	size_t trampoline_table_size;

	unsigned char *next_trampoline;

	struct obj_desc *next;
};

struct obj_desc *obj_desc_allocate(void);

bool has_jump(const struct obj_desc *desc, unsigned char *addr);
void mark_jump(const struct obj_desc *desc, const unsigned char *addr);
void mark_nop(struct obj_desc *desc, unsigned char *address, size_t size);

void allocate_jump_table(struct obj_desc *);
void allocate_nop_table(struct obj_desc *);
void allocate_trampoline_table(struct obj_desc *);

#endif
