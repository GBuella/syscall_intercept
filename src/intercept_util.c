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
#include "libsyscall_intercept_hook_point.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>

void *
xmmap_anon(size_t size)
{
	long addr = syscall_no_intercept(SYS_mmap,
				NULL, size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANON, -1, (off_t)0);

	xabort_on_syserror(addr, __func__);

	return (void *) addr;
}

void *
xmremap(void *addr, size_t old, size_t new)
{
	long new_addr = syscall_no_intercept(SYS_mremap, addr,
				old, new, MREMAP_MAYMOVE);

	xabort_on_syserror(new_addr, __func__);

	return (void *) new_addr;
}

void
xmunmap(void *addr, size_t len)
{
	long result = syscall_no_intercept(SYS_munmap, addr, len);

	xabort_on_syserror(result, __func__);
}

long
xlseek(long fd, unsigned long off, int whence)
{
	long result = syscall_no_intercept(SYS_lseek, fd, off, whence);

	xabort_on_syserror(result, __func__);

	return result;
}

void
xread(long fd, void *buffer, size_t size)
{
	long result = syscall_no_intercept(SYS_read, fd, buffer, size);

	if (result != (long)size)
		xabort_errno(syscall_error_code(result), __func__);
}

bool debug_dumps_on;

void
debug_dump(const char *fmt, ...)
{
	int len;
	va_list ap;

	if (!debug_dumps_on)
		return;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (len <= 0)
		return;

	char buf[len + 1];

	va_start(ap, fmt);
	len = vsprintf(buf, fmt, ap);
	va_end(ap);

	syscall_no_intercept(SYS_write, 2, buf, len);
}

/*
 * xabort_errno - print a message to stderr, and exit the process.
 * Calling abort() in libc might result other syscalls being called
 * by libc.
 *
 * If error_code is not zero, it is also printed.
 */
void
xabort_errno(int error_code, const char *msg)
{
	static const char main_msg[] = " libsyscall_intercept error\n";

	if (msg != NULL) {
		/* not using libc - inline strlen */
		size_t len = 0;
		while (msg[len] != '\0')
			++len;
		syscall_no_intercept(SYS_write, 2, msg, len);
	}

	if (error_code != 0) {
		char buf[0x10];
		size_t len = 1;
		char *c = buf + sizeof(buf) - 1;

		/* not using libc - inline sprintf */
		do {
			*c-- = error_code % 10;
			++len;
			error_code /= 10;
		} while (error_code != 0);
		*c = ' ';

		syscall_no_intercept(SYS_write, 2, c, len);
	}

	syscall_no_intercept(SYS_write, 2, main_msg, sizeof(main_msg) - 1);
	syscall_no_intercept(SYS_exit_group, 1);

	__builtin_unreachable();
}

/*
 * xabort - print a message to stderr, and exit the process.
 */
void
xabort(const char *msg)
{
	xabort_errno(0, msg);
}

/*
 * xabort_on_syserror -- examines the return value of syscall_no_intercept,
 * and calls xabort_errno if the said return value indicates an error.
 */
void
xabort_on_syserror(long syscall_result, const char *msg)
{
	if (syscall_error_code(syscall_result) != 0)
		xabort_errno(syscall_error_code(syscall_result), msg);
}
