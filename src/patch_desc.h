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

#ifndef SYSCALL_INTERCEPT_PATCHER_H
#define SYSCALL_INTERCEPT_PATCHER_H

#include "range.h"
#include "disasm_wrapper.h"

/*
 * The patch_list array stores some information on
 * whereabouts of patches made to glibc.
 * The syscall_addr pointer points to where a syscall
 *  instruction originally resided in glibc.
 * The asm_wrapper pointer points to the function
 *  called from glibc.
 * The glibc_call_patch pointer points to the exact
 *  location, where the new call instruction should
 *  be written.
 */
struct patch_desc {
	/* the original syscall instruction */
	unsigned char *syscall_addr;

	/* the offset of the original syscall instruction */
	unsigned long syscall_offset;

	/* the new asm wrapper created */
	unsigned char *asm_wrapper;

	/* the first byte overwritten in the code */
	unsigned char *dst_jmp_patch;

	/* the address to jump back to */
	unsigned char *return_address;

	/*
	 * Describe up to three instructions surrounding the original
	 * syscall instructions. Sometimes just overwritting the two
	 * direct neighbors of the syscall is not enough, ( e.g. if
	 * both the directly preceding, and the directly following are
	 * single byte instruction, that only gives 4 bytes of space ).
	 */
	struct intercept_disasm_result preceding_ins_2;
	struct intercept_disasm_result preceding_ins;
	struct intercept_disasm_result following_ins;
	bool uses_prev_ins_2;
	bool uses_prev_ins;
	bool uses_next_ins;

	bool uses_nop_trampoline;

	struct range nop_trampoline;
};

#endif
