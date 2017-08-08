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

#include <stdio.h>

/*
 * get_min_address
 * Looks for the lowest address that might be mmap-ed. This is
 * useful while looking for space for a trampoline table close
 * to some text section.
 */
uintptr_t
get_min_address(void)
{
	static uintptr_t min_address;

	if (min_address != 0)
		return min_address;

	min_address = 0x10000; /* best guess */

	FILE *f = fopen("/proc/sys/vm/mmap_min_addr,", "r");

	if (f != NULL) {
		char line[64];
		if (fgets(line, sizeof(line), f) != NULL)
			min_address = (uintptr_t)atoll(line);

		fclose(f);
	}

	return min_address;
}

static FILE *self_maps;
static uintptr_t iterator;
static char line[0x100];

map_iterator_handle
map_iterator_start(void *address)
{
	FILE *self_maps;

	if ((self_maps = fopen("/proc/self/maps", "r")) == NULL)
		xabort("fopen /proc/self/maps");

	return (struct map_iterator *)self_maps;
}

struct map
map_iterator_advance(void)
{
	if ((fgets(line, sizeof(line), maps)) == NULL) {
		fclose(self_maps);
		self_maps = NULL;
	}
}

void map_iterator_end(void);
