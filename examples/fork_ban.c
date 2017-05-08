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

/*
 * fork_ban.c - Block forking new processes after a maximum number of
 *  forks.
 *
 *
 */

#include "libsyscall_intercept_hook_point.h"

#include <errno.h>
#include <stdbool.h>
#include <sched.h>
#include <syscall.h>
#include <stdlib.h>

static bool
is_syscall_fork(long syscall_number, long arg0)
{
	if (syscall_number == SYS_fork || syscall_number == SYS_vfork)
		return true;

	if (syscall_number == SYS_clone && (arg0 & CLONE_THREAD) == 0)
		return true;

	return false;
}

static int fork_counter_max = 16;

static int
hook(long syscall_number,
		long arg0, long arg1,
		long arg2, long arg3,
		long arg4, long arg5,
		long *result)
{
	(void) arg1;
	(void) arg2;
	(void) arg3;
	(void) arg4;
	(void) arg5;

	if (!is_syscall_fork(syscall_number, arg0))
		return 1;

	static int fork_counter;

	if (fork_counter < fork_counter_max) {
		++fork_counter;

		*result = syscall_no_intercept(syscall_number,
		    arg0, arg1, arg2, arg3, arg4, arg5);

		if (*result > 0) {
			/* Messing with parent process: return wrong pid */
			*result += 16;
		}
	} else {
		static const char msg[] = "fork not allowed anymore!\n";
		syscall_no_intercept(SYS_write, 2, msg, sizeof(msg));
		*result = -EAGAIN;
	}

	return 0;
}

static __attribute__((constructor)) void
start(void)
{
	const char *e = getenv("ALLOW_FORK_MAX");

	if (e != NULL)
		fork_counter_max = atoi(e);

	intercept_hook_point = &hook;
}
