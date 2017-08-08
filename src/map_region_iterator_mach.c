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

#include "map_region_iterator.h"
#include "intercept_util.h"

#include <mach/mach.h>
#include <mach/mach_vm.h>

static mach_port_t self = MACH_PORT_TYPE_NONE;

uintptr_t
get_min_address(void)
{
	return 0x1000; /* Valid on Darwin */
}

void
map_iterator_init(void)
{
	struct task_basic_info_64 taskinfo;
	mach_msg_type_number_t count = TASK_BASIC_INFO_64_COUNT;
	self = mach_task_self();
	kern_return_t error = task_info(self, TASK_BASIC_INFO_64,
				(task_info_t)&taskinfo, &count);

	if (error != KERN_SUCCESS)
		xabort("task_info");
}

struct map_iterator *
map_iterator_start(void *address)
{
	return (struct map_iterator *)address;
}

struct map
map_iterator_advance(struct map_iterator **it)
{
	vm_region_top_info_data_t info;
	mach_port_t object_name;
	mach_msg_type_number_t info_cnt = VM_REGION_BASIC_INFO_COUNT;

	mach_vm_address_t address = (mach_vm_address_t)*it;
	mach_vm_size_t size;

	kern_return_t r = mach_vm_region(self, &address, &size,
				VM_REGION_TOP_INFO,
				(vm_region_info_t)&info,
				&info_cnt, &object_name);

	struct map m;
	if (r == KERN_SUCCESS) {
		m.start = (unsigned char *)address;
		m.end = m.start + size;
		*it = (void *)m.end;
	} else {
		m.start = NULL;
		m.end = NULL;
	}

	return m;
}

void
map_iterator_end(struct map_iterator **it)
{
	(void) it;
}
