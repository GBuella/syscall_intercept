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
 * syscall_coverage.c
 * A simple test program that makes a lot of basic syscalls.
 * Basic in the sense of there being no special case for handling
 * them in syscall_intercept. The main goal is to test logging
 * of these syscalls.
 *
 */

#ifdef NDEBUG
#undef NDEBUG
#endif

#pragma GCC diagnostic ignored "-Wnonnull"
#pragma GCC diagnostic ignored "-Wunused-result"

#include <assert.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "libsyscall_intercept_hook_point.h"
#include "magic_syscalls.h"

static bool test_in_progress;

#define RESULT 77

static char buffer[2][0x200];

/*
 * input data for buffers - expected to appear in the logs when
 * some syscall has a string, or binary data buffer argument.
 */
static const char input[2][sizeof(buffer[0])] = {
	"input_data\x01\x02\x03\n\r\t",
	"other_input_data\x01\x02\x03\n\r\t"};

/*
 * output data for buffers - expected to appear in the logs when
 * a hooked syscall's result is logged.
 * Of course it only really makes sense with those syscalls, which
 * would really write to some buffer. Even though the hook function
 * here would be able to mock buffer modifications for a write(2) syscall,
 * this test does not require syscall_intercept to handle that correctly.
 */
static const char expected_output[2][sizeof(buffer[0])] = {
	"expected_output_data\x06\xff\xe0\t"
	"other_expected_output_data\x06\xff\xe0\t"};

/*
 * setup_buffers - Should be called before every test using a buffer.
 */
static void
setup_buffers(void)
{
	memcpy(buffer, input, sizeof(buffer));
}

/*
 * mock_output
 * This function overwrites buffers pointed to by syscall arguments
 * with their expected output. This helps test the output logging syscall
 * results. These values are expected in the logs, and syscall_intercept
 * should definitely not print what was their contents before the hooking,
 * when a syscall is expected to write to some buffer.
 */
static void
mock_output(long arg)
{
	if ((uintptr_t)arg == (uintptr_t)(buffer[0]))
		memcpy(buffer[0], expected_output[0], sizeof(buffer[0]));

	if ((uintptr_t)arg == (uintptr_t)(buffer[1]))
		memcpy(buffer[1], expected_output[1], sizeof(buffer[1]));
}

/*
 * hook
 * The hook function used for all logged syscalls in this test. This test would
 * be impractical, if all these syscalls would be forwarded to the kernel.
 * Mocking all the syscalls guarantees the reproducibility of syscall results.
 */
static int
hook(long syscall_number,
	long arg0, long arg1,
	long arg2, long arg3,
	long arg4, long arg5,
	long *result)
{
	(void) syscall_number;

	if (!test_in_progress)
		return 1;

	mock_output(arg0);
	mock_output(arg1);
	mock_output(arg2);
	mock_output(arg3);
	mock_output(arg4);
	mock_output(arg5);

	*result = RESULT;

	return 0;
}

#define ALL_O_FLAGS \
	O_RDWR | O_APPEND | O_APPEND | O_CLOEXEC | O_CREAT | O_DIRECTORY | \
	O_DSYNC | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_RSYNC | \
	O_SYNC | O_TRUNC

int
main(int argc, char **argv)
{
	if (argc < 2)
		return EXIT_FAILURE;

	intercept_hook_point = hook;

	/*
	 * The two input buffers contain null terminated strings, with
	 * extra null characters following the string. For testing the logging
	 * of syscall arguments pointing to binary data, one can pass
	 * e.g. len0 - 3 to test printing a buffer without a null terminator,
	 * or len0 + 3 for printing null characters.
	 */
	size_t len0 = strlen(input[0]);
	size_t len1 = strlen(input[1]);

	(void) len1;
	magic_syscall_start_log(argv[1], "1");
	test_in_progress = true;

	read(9, NULL, 44);

	setup_buffers();
	read(7, buffer[0], len0 + 3);

	write(7, input[0], len0 + 4);

	open(input[0], O_CREAT | O_RDWR | O_SYNC, 0321);
	open(input[0], 0, 0321);
	open(NULL, ALL_O_FLAGS, 0777);
	open(input[0], ALL_O_FLAGS, 0777);
	open(input[1], O_RDWR | O_NONBLOCK, 0111);
	open(input[1], 0);
	open(NULL, 0);

	close(9);

	mmap(NULL, 0, 0, 0, 0, 0);
	mmap((void *)0x123000, 0x8000, PROT_EXEC, MAP_SHARED, 99, 0x1000);

	test_in_progress = false;
	magic_syscall_stop_log();

	return EXIT_SUCCESS;
}
