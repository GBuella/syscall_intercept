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
#include "intercept.h"

#include <sys/uio.h>


/*
 * Log syscalls after intercepting, in a human readable ( as much as possible )
 * format. The format is either:
 *
 * offset -- name(arguments...) = result
 *
 * where the name is known, or
 *
 * offset -- syscall(syscall_number, arguments...) = result
 *
 * where the name is not known.
 *
 * Each line starts with the offset of the syscall instruction in libc's ELF.
 * This should be easy to pass to addr2line, to see in what symbol in libc
 * the syscall was initiated.
 *
 * E.g.:
 * 0xdaea2 -- fstat(1, 0x7ffd115206f0) = 0
 *
 * Each syscall should be logged after being executed, so the result can be
 * logged as well.
 */
void
intercept_print_syscall(struct syscall_log_line *line,
			long nr, long arg0, long arg1,
			long arg2, long arg3,
			long arg4, long arg5,
			enum intercept_log_result result_known, long result)
{

	for (int i = 0; i < max_iov_count; ++i)
		iov[i].iov_base = buffer[i - 1];

	iov[1].iov_len = sprintf(iov[1].iov_base, " ", syscall_offset);
	iov[2].iov_base = buffer;
	iov[2].iov_len = buf - buffer;
}
