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

#ifndef SYSCALL_DESC_H
#define SYSCALL_DESC_H

#include <stddef.h>
#include <stdint.h>

#include "macros.h"

/*
 * The syscall_desc struct describes a syscall initiated by a syscall
 * instruction (actually a jump instruction written in the place of
 * a syscall).
 *
 * The syscall number and syscall arguments are stored as `long`, as
 * is defined in the ABI. As of now, and in the foreseeable future
 * the syscall_intercept library only works on Linux/x86_64, so these are
 * assumed to be 64 bit values.
 * The offset field contains the offset of the syscall instruction relative to
 * the base address of an object file. The libpath pointer points to the path
 * of this object file in the file system -- currently this path can be assumed
 * to available for any syscall being intercepted.
 *
 * This struct does not indicate the actual number of meaningful syscall
 * arguments. In the case of syscalls using fewer than six arguments, the rest
 * of the contents of the args array is just filled with irrelevant values, that
 * happened to be in the registers at the time of the syscall.
 */
struct syscall_desc {
	long nr;
	long args[6];
	uint32_t offset;
	const char *libpath;
};

/*
 * The layout of struct syscall_desc must match the layout
 * expected by the code in the intercept_template.s asm file.
 */
static_assert(sizeof(struct syscall_desc) == 8 * 9,
		"syscall_desc layout error");
static_assert(offsetof(struct syscall_desc, offset) == 8 * 7,
		"syscall_desc layout error");
static_assert(offsetof(struct syscall_desc, libpath) == 8 * 8,
		"syscall_desc layout error");

#endif
