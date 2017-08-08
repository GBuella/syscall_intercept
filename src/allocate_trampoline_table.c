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

#include "map_region_iterator.h"
#include "intercept_util.h"
#include "obj_desc.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/syscall.h>

void
allocate_trampoline_table(struct obj_desc *desc)
{
	char *e = getenv("INTERCEPT_NO_TRAMPOLINE");

	/* Use the extra trampoline table by default */
	desc->uses_trampoline_table = (e == NULL) || (e[0] == '0');

	if (!desc->uses_trampoline_table) {
		desc->trampoline_table = NULL;
		desc->trampoline_table_size = 0;
		desc->trampoline_table = NULL;
		return;
	}

	unsigned char *guess;
	size_t size;

	if ((uintptr_t)desc->text_end < INT32_MAX) {
		/* start from the bottom of memory */
		guess = (void *)0;
	} else {
		/*
		 * start from the lowest possible address, that can be reached
		 * from the text segment using a 32 bit displacement.
		 * Round up to a memory page boundary, as this address must be
		 * mappable.
		 */
		guess = desc->text_end - INT32_MAX;
		guess = (unsigned char *)(((uintptr_t)guess)
				& ~((uintptr_t)(0xfff))) + 0x1000;
	}

	if ((uintptr_t)guess < get_min_address())
		guess = (void *)get_min_address();

	size = 64 * 0x1000; /* XXX: don't just guess */

	struct map_iterator *it = map_iterator_start((void *)guess);
	struct map m;
	while (!is_map_null(m = map_iterator_advance(&it))) {
		/*
		 * Let's see if an existing mapping overlaps
		 * with the guess!
		 */
		if (m.end < guess)
			continue; /* No overlap, let's see the next mapping */

		if (m.start >= guess + size) {
			/* The rest of the mappings can't possibly overlap */
			break;
		}

		/*
		 * The next guess is the page following the mapping seen
		 * just now.
		 */
		guess = m.end;

		if (guess + size >= desc->text_start + INT32_MAX) {
			/* Too far away */
			xabort("unable to find place for trampoline table");
		}
	}
	map_iterator_end(&it);

	long result = syscall_no_intercept(SYS_mmap, guess, size,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_FIXED | MAP_PRIVATE | MAP_ANON,
					-1, 0);

	if (result < 0 && result >= -0x1000)
		xabort("unable to allocate space for trampoline table");

	desc->trampoline_table = (void *)result;
	desc->trampoline_table_size = size;

	desc->next_trampoline = desc->trampoline_table;
}
