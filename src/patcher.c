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

/*
 * patcher.c -- patching a library
 *
 * Jumping from the subject library:
 *
 *     /--------------------------\
 *     |               subject.so |
 *     |                          |
 *     |  jmp to_trampoline_table |  patched by activate_patches()
 *  /->|   |                      |
 *  |  \___|______________________/
 *  |      |
 *  |  /---|--------------------------\
 *  |  | movabs %r11, wrapper_address | jmp generated by activate_patches()
 *  |  | jmp *%r11                    | This allows subject.so and
 *  |  |   |                          | libsyscall_intercept.so to be farther
 *  |  \___|__________________________/ than 2 gigabytes from each other
 *  |      |
 *  |  /---|-----------------------------\
 *  |  |   |  libsyscall_intercept.so    |
 *  |  |   |                             |
 *  |  | /-|--------------------------\  |
 *  |  | | |  static unsigned char    |  |
 *  |  | | |  asm_wrapper_space[]     |  |
 *  |  | | |    in BSS                |  | wrapper routine
 *  |  | | |                          |  | generated into asm_wrapper_space
 *  |  | | |                          |  | by create_wrapper()
 *  |  | |wrapper routine             |  |
 *  |  | |calls C hook function  ----------> intercept_routine in intercept.c
 *  |  | |movabs %r11, return_address |  |
 *  |  | |jmp *%r11                   |  |
 *  |  | \_|__________________________/  |
 *  |  \___|_____________________________/
 *  |      |
 *  \______/
 *
 */

#include "intercept.h"
#include "intercept_util.h"

#include <assert.h>
#include <stdint.h>
#include <syscall.h>
#include <sys/mman.h>
#include <string.h>

#include <stdio.h>

#define PAGE_SIZE ((size_t)0x1000)

/* The size of a trampoline jump, jmp instruction + pointer */
enum { TRAMPOLINE_SIZE = 6 + 8 };

static unsigned char *
round_down_address(unsigned char *address)
{
	return (unsigned char *)(((uintptr_t)address) & ~(PAGE_SIZE - 1));
}


static unsigned char asm_wrapper_space[0x100000];

static unsigned char *next_asm_wrapper_space(void);

static void create_wrapper(struct patch_desc *patch,
			void *dest_routine, void *dest_routine_clone_child,
			bool use_absolute_return,
			const char *libpath);

/*
 * create_absolute_jump(from, to)
 * Create an indirect jump, with the pointer right next to the instruction.
 *
 * jmp *0(%rip)
 *
 * This uses up 6 bytes for the jump instruction, and another 8 bytes
 * for the pointer right after the instruction.
 */
static void
create_absolute_jump(unsigned char *from, void *to)
{
	from[0] = 0xff; /* opcode of RIP based indirect jump */
	from[1] = 0x25; /* opcode of RIP based indirect jump */
	from[2] = 0; /* 32 bit zero offset */
	from[3] = 0; /* this means zero relative to the value */
	from[4] = 0; /* of RIP, which during the execution of the jump */
	from[5] = 0; /* points to right after the jump instruction */

	unsigned char *d = (unsigned char *)&to;

	from[6] = d[0]; /* so, this is where (RIP + 0) points to, */
	from[7] = d[1]; /* jump reads the destination address */
	from[8] = d[2]; /* from here */
	from[9] = d[3];
	from[10] = d[4];
	from[11] = d[5];
	from[12] = d[6];
	from[13] = d[7];
}

/*
 * create_jump(opcode, from, to)
 * Create a 5 byte jmp/call instruction jumping to address to, by overwriting
 * code starting at address from.
 */
void
create_jump(unsigned char opcode, unsigned char *from, void *to)
{
	/*
	 * The operand is the difference between the
	 * instruction pointer pointing to the instruction
	 * just after the call, and the to address.
	 * Thus RIP seen by the call instruction is from + 5
	 */
	ptrdiff_t delta = ((unsigned char *)to) - (from + JUMP_INS_SIZE);

	if (delta > ((ptrdiff_t)INT32_MAX) || delta < ((ptrdiff_t)INT32_MIN))
		xabort("create_jump distance check");

	int32_t delta32 = (int32_t)delta;
	unsigned char *d = (unsigned char *)&delta32;

	from[0] = opcode;
	from[1] = d[0];
	from[2] = d[1];
	from[3] = d[2];
	from[4] = d[3];
}

/*
 * check_trampoline_usage -
 * Make sure the trampoline table allocated at the beginning of patching has
 * enough space for all trampolines. This just aborts the process if the
 * allocate space does not seem to be enough, but it can be fairly easy
 * to implement more allocation here if such need would arise.
 */
static void
check_trampoline_usage(const struct intercept_desc *desc)
{
	if (!desc->uses_trampoline_table)
		return;

	/*
	 * We might actually not have enough space for creating
	 * more trampolines.
	 */

	size_t used = (size_t)(desc->next_trampoline - desc->trampoline_table);

	if (used + TRAMPOLINE_SIZE >= desc->trampoline_table_size)
		xabort("trampoline space not enough");
}

/*
 * is_nop_in_range - checks if NOP is sufficiently close to address, to be
 * reachable by a jmp having a 8 bit displacement.
 */
static bool
is_nop_in_range(unsigned char *address, const struct range *nop)
{
	/*
	 * Planning to put a 5 byte jump starting at the third byte
	 * of the nop instruction. The syscall should jump to this
	 * trampoline jump.
	 */
	unsigned char *dst = nop->address + 2;
	/*
	 * Planning to put a two byte jump in the place of the syscall
	 * instruction, that is going to jump relative to the value of
	 * RIP during execution, which points to the next instruction,
	 * at address + 2.
	 */
	unsigned char *src = address + 2;

	/*
	 * How far can this short jump instruction jump, considering
	 * the one byte singed displacement?
	 */
	unsigned char *reach_min = src - 128;
	unsigned char *reach_max = src + 127;

	/*
	 * Can a two byte jump reach the proposed destination?
	 * I.e.: is dst in the [reach_min, reach_max] range?
	 */
	return reach_min <= dst && dst <= reach_max;
}

/*
 * assign_nop_trampoline
 * Looks for a NOP instruction close to a syscall instruction to be patched.
 * The struct patch_desc argument specifies where the particular syscall
 * instruction resides, and the struct intercept_desc argument of course
 * already contains information about NOPs, collected by the find_syscalls
 * routine.
 *
 * This routine essentially initializes the uses_nop_trampoline and
 * the nop_trampoline fields of a struct patch_desc.
 */
static void
assign_nop_trampoline(struct intercept_desc *desc,
		struct patch_desc *patch,
		size_t *next_nop_i)
{
	struct range *nop = desc->nop_table + *next_nop_i;

	if (*next_nop_i >= desc->nop_count) {
		patch->uses_nop_trampoline = false;
		return; /* no more nops available */
	}

	/*
	 * Consider a nop instruction, to use as trampoline, but only
	 * if a two byte jump in the place of the syscall can jump
	 * to the proposed trampoline. Check if the nop is:
	 *  1) at an address too low
	 *  2) close enough for a two byte jump
	 *  3) at an address too high
	 */

	if (is_nop_in_range(patch->syscall_addr, nop)) {
		patch->uses_nop_trampoline = true;
		patch->nop_trampoline = *nop;
		++(*next_nop_i);
		return; /* found a nop in range to use as trampoline */
	}

	if (nop->address > patch->syscall_addr) {
		patch->uses_nop_trampoline = false;
		return; /* nop is too far ahead */
	}

	/* nop is too far behind, try the next nop */
	++(*next_nop_i);
	assign_nop_trampoline(desc, patch, next_nop_i);
}

/*
 * is_relocateable_before_syscall
 * checks if an instruction found before a syscall instruction
 * can be relocated (and thus overwritten).
 */
static bool
is_relocateable_before_syscall(struct intercept_disasm_result ins)
{
	if (!ins.is_set)
		return false;

	return !(ins.has_ip_relative_opr ||
	    ins.is_call ||
	    ins.is_rel_jump ||
	    ins.is_jump ||
	    ins.is_ret ||
	    ins.is_syscall);
}

/*
 * is_relocateable_after_syscall
 * checks if an instruction found before a syscall instruction
 * can be relocated (and thus overwritten).
 *
 * Notice: we allow relocation of ret instructions.
 */
static bool
is_relocateable_after_syscall(struct intercept_disasm_result ins)
{
	if (!ins.is_set)
		return false;

	return !(ins.has_ip_relative_opr ||
	    ins.is_call ||
	    ins.is_rel_jump ||
	    ins.is_jump ||
	    ins.is_syscall);
}


/*
 * check_surrounding_instructions
 * Sets up the following members in a patch_desc, based on
 * instruction being relocateable or not:
 * uses_prev_ins ; uses_prev_ins_2 ; uses_next_ins
 */
static void
check_surrounding_instructions(struct intercept_desc *desc,
				struct patch_desc *patch)
{
	patch->uses_prev_ins =
	    is_relocateable_before_syscall(patch->preceding_ins) &&
	    !is_overwritable_nop(&patch->preceding_ins) &&
	    !has_jump(desc, patch->syscall_addr);

	if (patch->uses_prev_ins) {
		patch->uses_prev_ins_2 =
		    patch->uses_prev_ins &&
		    is_relocateable_before_syscall(patch->preceding_ins_2) &&
		    !is_overwritable_nop(&patch->preceding_ins_2) &&
		    !has_jump(desc, patch->syscall_addr
			- patch->preceding_ins.length);
	} else {
		patch->uses_prev_ins_2 = false;
	}

	patch->uses_next_ins =
	    is_relocateable_after_syscall(patch->following_ins) &&
	    !is_overwritable_nop(&patch->following_ins) &&
	    !has_jump(desc,
		patch->syscall_addr + SYSCALL_INS_SIZE);
}

/*
 * create_patch_wrappers - create the custom assembly wrappers
 * around each syscall to be intercepted. Well, actually, the
 * function create_wrapper does that, so perhaps this function
 * deserves a better name.
 * What this function actually does, is figure out how to create
 * a jump instruction in libc ( which bytes to overwrite ).
 * If it successfully finds suitable bytes for hotpatching,
 * then it determines the exact bytes to overwrite, and the exact
 * address for jumping back to libc.
 *
 * This is all based on the information collected by the routine
 * find_syscalls, which does the disassembling, finding jump destinations,
 * finding padding bytes, etc..
 */
void
create_patch_wrappers(struct intercept_desc *desc)
{
	size_t next_nop_i = 0;

	for (unsigned patch_i = 0; patch_i < desc->count; ++patch_i) {
		struct patch_desc *patch = desc->items + patch_i;

		assign_nop_trampoline(desc, patch, &next_nop_i);

		if (patch->uses_nop_trampoline) {
			/*
			 * The preferred option it to use a 5 byte relative
			 * jump in a padding space between symbols in libc.
			 * If such padding space is found, a 2 byte short
			 * jump is enough for jumping to it, thus no
			 * instructions other than the syscall
			 * itself need to be overwritten.
			 */
			patch->uses_prev_ins = false;
			patch->uses_prev_ins_2 = false;
			patch->uses_next_ins = false;
			patch->dst_jmp_patch =
			    patch->nop_trampoline.address + 2;
			/*
			 * The first two bytes of the nop are used for
			 * something else, see the explanation
			 * at is_overwritable_nop in intercept_desc.c
			 */

			/*
			 * Return to libc:
			 * just jump to instruction right after the place
			 * where the syscall instruction was originally.
			 */
			patch->return_address =
			    patch->syscall_addr + SYSCALL_INS_SIZE;

		} else {
			/*
			 * No padding space is available, so check the
			 * instructions surrounding the syscall instruction.
			 * If they can be relocated, then they can be
			 * overwritten. Of course some instructions depend
			 * on the value of the RIP register, these can not
			 * be relocated.
			 */

			check_surrounding_instructions(desc, patch);

			/*
			 * Count the number of overwritable bytes
			 * in the variable length.
			 * Sum up the bytes that can be overwritten.
			 * The 2 bytes of the syscall instruction can
			 * be overwritten definitely, so length starts
			 * as SYSCALL_INS_SIZE ( 2 bytes ).
			 */
			unsigned length = SYSCALL_INS_SIZE;

			patch->dst_jmp_patch = patch->syscall_addr;

			/*
			 * If the preceding instruction is relocatable,
			 * add its length. Also, the the instruction right
			 * before that.
			 */
			if (patch->uses_prev_ins) {
				length += patch->preceding_ins.length;
				patch->dst_jmp_patch -=
				    patch->preceding_ins.length;

				if (patch->uses_prev_ins_2) {
					length += patch->preceding_ins_2.length;
					patch->dst_jmp_patch -=
					    patch->preceding_ins_2.length;
				}
			}

			/*
			 * If the following instruction is relocatable,
			 * add its length. This also affects the return address.
			 * Normally, the library would return to libc after
			 * handling the syscall by jumping to instruction
			 * right after the syscall. But if that instruction
			 * is overwritten, the returning jump must jump to
			 * the instruction after it.
			 */
			if (patch->uses_next_ins) {
				length += patch->following_ins.length;

				/*
				 * Address of the syscall instruction
				 * plus 2 bytes
				 * plus the length of the following instruction
				 *
				 * adds up to:
				 *
				 * the address of the second instruction after
				 * the syscall.
				 */
				patch->return_address = patch->syscall_addr +
				    SYSCALL_INS_SIZE +
				    patch->following_ins.length;
			} else {
				/*
				 * Address of the syscall instruction
				 * plus 2 bytes
				 *
				 * adds up to:
				 *
				 * the address of the first instruction after
				 * the syscall ( just like in the case of
				 * using padding bytes ).
				 */
				patch->return_address =
					patch->syscall_addr + SYSCALL_INS_SIZE;
			}

			/*
			 * If the length is at least 5, then a jump instruction
			 * with a 32 bit displacement can fit.
			 *
			 * Otherwise give up
			 */
			if (length < JUMP_INS_SIZE) {
				char buffer[0x1000];

				int l = snprintf(buffer, sizeof(buffer),
					"unintercepted syscall at: %s 0x%lx\n",
					desc->path,
					patch->syscall_offset);

				intercept_log(buffer, (size_t)l);
				xabort("not enough space for patching"
				    " around syscal");
			}
		}

		mark_jump(desc, patch->return_address);

		create_wrapper(patch,
			desc->c_destination, desc->c_destination_clone_child,
			desc->uses_trampoline_table,
			desc->path);
	}
}

/*
 * Referencing symbols defined in intercept_template.s
 */
extern unsigned char intercept_asm_wrapper_tmpl[];
extern unsigned char intercept_asm_wrapper_end;
extern unsigned char intercept_asm_wrapper_prefix;
extern unsigned char intercept_asm_wrapper_postfix;
extern unsigned char intercept_asm_wrapper_call;
extern unsigned char intercept_asm_wrapper_simd_save;
extern unsigned char intercept_asm_wrapper_simd_restore;
extern unsigned char intercept_asm_wrapper_return_jump;
extern unsigned char intercept_asm_wrapper_push_origin_addr;
extern unsigned char intercept_asm_wrapper_mov_return_addr_r11_no_syscall;
extern unsigned char intercept_asm_wrapper_mov_return_addr_r11_syscall;
extern unsigned char intercept_asm_wrapper_mov_libpath_r11;
extern unsigned char intercept_asm_wrapper_mov_phaddr_r11;
extern unsigned char intercept_asm_wrapper_mov_ph2addr_r11;
extern unsigned char intercept_asm_wrapper_simd_save_YMM;
extern unsigned char intercept_asm_wrapper_simd_save_YMM_end;
extern unsigned char intercept_asm_wrapper_simd_restore_YMM;
extern unsigned char intercept_asm_wrapper_simd_restore_YMM_end;
extern unsigned char intercept_asm_wrapper_return_and_no_syscall;
extern unsigned char intercept_asm_wrapper_return_and_syscall;
extern unsigned char intercept_asm_wrapper_push_stack_first_return_addr;
extern unsigned char intercept_asm_wrapper_mov_r11_stack_first_return_addr;
extern unsigned char intercept_asm_wrapper_clone_wrapper;
extern unsigned char intercept_asm_wrapper_call_clone_child_intercept;

extern void backtrace_placeholder();
extern void backtrace_placeholder_2();

static size_t tmpl_size;
static ptrdiff_t o_prefix;
static ptrdiff_t o_postfix;
static ptrdiff_t o_call;
static ptrdiff_t o_ret_no_syscall;
static ptrdiff_t o_ret_syscall;
static ptrdiff_t o_ret_jump;
static ptrdiff_t o_push_origin;
static ptrdiff_t o_simd_save;
static ptrdiff_t o_simd_restore;
static ptrdiff_t o_mov_return_r11_no_syscall;
static ptrdiff_t o_mov_return_r11_syscall;
static ptrdiff_t o_mov_libpath_r11;
static ptrdiff_t o_move_phaddr_r11;
static ptrdiff_t o_move_ph2addr_r11;
static ptrdiff_t o_push_first_return_addr;
static ptrdiff_t o_mov_r11_first_return_addr;
static ptrdiff_t o_clone_wrapper;
static ptrdiff_t o_call_clone_child_intercept;
static size_t simd_save_YMM_size;
static size_t simd_restore_YMM_size;

static bool must_save_ymm_registers;

/*
 * init_patcher
 * Some variables need to be initialized before patching.
 * This routine must be called once before patching any library.
 */
void
init_patcher(void)
{
	unsigned char *begin = &intercept_asm_wrapper_tmpl[0];

	assert(&intercept_asm_wrapper_end > begin);
	assert(&intercept_asm_wrapper_prefix > begin);
	assert(&intercept_asm_wrapper_postfix > begin);
	assert(&intercept_asm_wrapper_call > begin);
	assert(&intercept_asm_wrapper_return_and_no_syscall > begin);
	assert(&intercept_asm_wrapper_return_and_syscall > begin);
	assert(&intercept_asm_wrapper_return_jump > begin);
	assert(&intercept_asm_wrapper_push_origin_addr > begin);
	assert(&intercept_asm_wrapper_simd_save > begin);
	assert(&intercept_asm_wrapper_simd_restore > begin);
	assert(&intercept_asm_wrapper_mov_return_addr_r11_no_syscall > begin);
	assert(&intercept_asm_wrapper_mov_return_addr_r11_syscall > begin);
	assert(&intercept_asm_wrapper_mov_libpath_r11 > begin);
	assert(&intercept_asm_wrapper_mov_phaddr_r11 > begin);
	assert(&intercept_asm_wrapper_mov_ph2addr_r11 > begin);
	assert(&intercept_asm_wrapper_mov_r11_stack_first_return_addr > begin);
	assert(&intercept_asm_wrapper_push_stack_first_return_addr > begin);
	assert(&intercept_asm_wrapper_simd_save_YMM_end >
	    &intercept_asm_wrapper_simd_save_YMM);
	assert(&intercept_asm_wrapper_simd_restore_YMM_end >
	    &intercept_asm_wrapper_simd_restore_YMM);

	tmpl_size = (size_t)(&intercept_asm_wrapper_end - begin);
	o_prefix = &intercept_asm_wrapper_prefix - begin;
	o_postfix = &intercept_asm_wrapper_postfix - begin;
	o_call = &intercept_asm_wrapper_call - begin;
	o_ret_no_syscall = &intercept_asm_wrapper_return_and_no_syscall - begin;
	o_ret_syscall = &intercept_asm_wrapper_return_and_syscall - begin;
	o_ret_jump = &intercept_asm_wrapper_return_jump - begin;
	o_push_origin = &intercept_asm_wrapper_push_origin_addr - begin;
	o_simd_save = &intercept_asm_wrapper_simd_save - begin;
	o_simd_restore = &intercept_asm_wrapper_simd_restore - begin;
	o_mov_return_r11_no_syscall =
	    &intercept_asm_wrapper_mov_return_addr_r11_no_syscall - begin;
	o_mov_return_r11_syscall =
	    &intercept_asm_wrapper_mov_return_addr_r11_syscall - begin;
	o_mov_libpath_r11 = &intercept_asm_wrapper_mov_libpath_r11 - begin;
	o_move_phaddr_r11 = &intercept_asm_wrapper_mov_phaddr_r11 - begin;
	o_move_ph2addr_r11 = &intercept_asm_wrapper_mov_ph2addr_r11 - begin;
	o_mov_r11_first_return_addr =
	    &intercept_asm_wrapper_mov_r11_stack_first_return_addr - begin;
	o_push_first_return_addr =
	    &intercept_asm_wrapper_push_stack_first_return_addr - begin;
	o_clone_wrapper = &intercept_asm_wrapper_clone_wrapper - begin;
	o_call_clone_child_intercept =
	    &intercept_asm_wrapper_call_clone_child_intercept - begin;
	simd_save_YMM_size = (size_t)(&intercept_asm_wrapper_simd_save_YMM_end -
	    &intercept_asm_wrapper_simd_save_YMM);
	simd_restore_YMM_size =
	    (size_t)(&intercept_asm_wrapper_simd_restore_YMM_end -
	    &intercept_asm_wrapper_simd_restore_YMM);

	/*
	 * has_ymm_registers -- checks if AVX instructions are supported,
	 * thus YMM registers can be used on this CPU.
	 *
	 * in util.s
	 */
	extern bool has_ymm_registers(void);

	must_save_ymm_registers = has_ymm_registers();
}

/*
 * copy_ymm_handler_code
 * This routine copies the code saving/restoring the YMM (256 bit wide )
 * registers in an assembly wrapper template. Without this, the default
 * code for saving/restoring the XMM (128 bit wide) registers stays
 * in the generated code.
 */
static void
copy_ymm_handler_code(unsigned char *asm_wrapper)
{
	memcpy(asm_wrapper + o_simd_save,
	    &intercept_asm_wrapper_simd_save_YMM, simd_save_YMM_size);
	memcpy(asm_wrapper + o_simd_restore,
	    &intercept_asm_wrapper_simd_restore_YMM, simd_restore_YMM_size);
}

/*
 * create_push_imm
 * Generates a push instruction, that pushes a 32 bit constant to the stack.
 */
static void
create_push_imm(unsigned char *push, uint32_t syscall_offset)
{
	push[0] = PUSH_IMM_OPCODE;
	push[1] = (unsigned char)((syscall_offset >> 0) & 0xff);
	push[2] = (unsigned char)((syscall_offset >> 8) & 0xff);
	push[3] = (unsigned char)((syscall_offset >> 16) & 0xff);
	push[4] = (unsigned char)((syscall_offset >> 24) & 0xff);
}

/*
 * create_movabs_r11
 * Generates a movabs instruction, that assigns a 64 bit constant to
 * the R11 register.
 */
static void
create_movabs_r11(unsigned char *code, uint64_t value)
{
	unsigned char *bytes = (unsigned char *)&value;

	code[0] = 0x49; /* movabs opcode */
	code[1] = 0xbb; /* specifiy r11 as destination */
	code[2] = bytes[0];
	code[3] = bytes[1];
	code[4] = bytes[2];
	code[5] = bytes[3];
	code[6] = bytes[4];
	code[7] = bytes[5];
	code[8] = bytes[6];
	code[9] = bytes[7];
}

/*
 * create_wrapper
 * Generates an assembly wrapper. Copies the template written in
 * intercept_template.s, and generates the instructions specific
 * to a particular syscall into the new copy.
 * After this wrapper is created, a syscall can be replaced with a
 * jump to this wrapper, and wrapper is going to call dest_routine
 * (actually only after a call to mprotect_asm_wrappers).
 */
static void
create_wrapper(struct patch_desc *patch,
	void *dest_routine, void *dest_routine_clone_child,
	bool use_absolute_return,
	const char *libpath)
{
	unsigned char *begin;

	/* Create a new copy of the template */
	patch->asm_wrapper = begin = next_asm_wrapper_space();
	memcpy(begin, intercept_asm_wrapper_tmpl, tmpl_size);

	/* Copy the prev/next instructions, if they are copiable */
	if (patch->uses_prev_ins) {
		size_t length = patch->preceding_ins.length;
		if (patch->uses_prev_ins_2)
			length += patch->preceding_ins_2.length;

		memcpy(begin + o_prefix, patch->syscall_addr - length, length);
	}
	if (patch->uses_next_ins) {
		memcpy(begin + o_postfix,
		    patch->syscall_addr + SYSCALL_INS_SIZE,
		    patch->following_ins.length);
	}

	if (patch->syscall_offset > UINT32_MAX)
		xabort("patch->syscall_offset > UINT32_MAX");
		/* libc larger than 2 gigabytes? wow */

	/* the instruction pushing the syscall's address to the stack */
	create_push_imm(begin + o_push_origin, (uint32_t)patch->syscall_offset);

	create_movabs_r11(begin + o_mov_return_r11_no_syscall,
	    (uint64_t)(begin + o_ret_no_syscall));

	create_movabs_r11(begin + o_mov_return_r11_syscall,
	    (uint64_t)(begin + o_ret_syscall));

	create_movabs_r11(begin + o_move_phaddr_r11,
	    (uint64_t)&backtrace_placeholder + 1);

	create_movabs_r11(begin + o_move_ph2addr_r11,
	    (uint64_t)&backtrace_placeholder_2 + 1);

#ifndef NDEBUG

	create_movabs_r11(begin + o_mov_r11_first_return_addr,
	    ((uint64_t)patch->syscall_addr) + 2);

	/*
	 * write a 'push %r11' instruction
	 * overwriting the 'subq $0x8, %rsp' instruction
	 */
	begin[o_push_first_return_addr] = 0x41;
	begin[o_push_first_return_addr + 1] = 0x53;
	begin[o_push_first_return_addr + 2] = 0x90;
	begin[o_push_first_return_addr + 3] = 0x90;
	begin[o_push_first_return_addr + 4] = 0x90;
	begin[o_push_first_return_addr + 5] = 0x90;
	begin[o_push_first_return_addr + 6] = 0x90;
	begin[o_push_first_return_addr + 7] = 0x90;

#endif

	create_movabs_r11(begin + o_mov_libpath_r11, (uint64_t)libpath);

	/* Create the jump instructions returning to the original code */
	if (use_absolute_return)
		create_absolute_jump(begin + o_ret_jump, patch->return_address);
	else
		create_jump(JMP_OPCODE, begin + o_ret_jump,
				patch->return_address);

	/* Create the jump instruction calling the intended C function */
	create_jump(JMP_OPCODE, begin + o_call, dest_routine);

	/*
	 * Create the call instruction calling the intended C function
	 * - clone child
	 */
	create_jump(CALL_OPCODE, begin + o_call_clone_child_intercept,
	    dest_routine_clone_child);

	if (must_save_ymm_registers)
		copy_ymm_handler_code(begin);
}

/*
 * create_short_jump
 * Generates a 2 byte jump instruction. The to address must be reachable
 * using an 8 bit displacement.
 */
static void
create_short_jump(unsigned char *from, unsigned char *to)
{
	ptrdiff_t d = to - (from + 2);

	if (d < - 128 || d > 127)
		xabort("create_short_jump distance check");

	from[0] = SHORT_JMP_OPCODE;
	from[1] = (unsigned char)((char)d);
}

/*
 * after_nop -- get the address of the instruction
 * following the nop.
 */
static unsigned char *
after_nop(const struct range *nop)
{
	return nop->address + nop->size;
}

static void
mprotect_no_intercept(void *addr, size_t len, int prot,
			const char *msg_on_error)
{
	long result = syscall_no_intercept(SYS_mprotect, addr, len, prot);

	xabort_on_syserror(result, msg_on_error);
}

/*
 * activate_patches()
 * Loop over all the patches, and and overwrite each syscall.
 */
void
activate_patches(struct intercept_desc *desc)
{
	unsigned char *first_page;
	size_t size;

	if (desc->count == 0)
		return;

	first_page = round_down_address(desc->text_start);
	size = (size_t)(desc->text_end - first_page);

	mprotect_no_intercept(first_page, size,
	    PROT_READ | PROT_WRITE | PROT_EXEC,
	    "mprotect PROT_READ | PROT_WRITE | PROT_EXEC");

	for (unsigned i = 0; i < desc->count; ++i) {
		const struct patch_desc *patch = desc->items + i;

		if (patch->dst_jmp_patch < desc->text_start ||
		    patch->dst_jmp_patch > desc->text_end)
			xabort("dst_jmp_patch outside text");

		/*
		 * The dst_jmp_patch pointer contains the address where
		 * the actual jump instruction escaping the patched text
		 * segment should be written.
		 * This is either at the place of the original syscall
		 * instruction, or at some usable padding space close to
		 * it (an overwritable NOP instruction).
		 */

		if (desc->uses_trampoline_table) {
			/*
			 * First jump to the trampoline table, which
			 * should be in a 2 gigabyte range. From there,
			 * jump to the asm_wrapper.
			 */
			check_trampoline_usage(desc);

			/* jump - escape the text segment */
			create_jump(JMP_OPCODE,
				patch->dst_jmp_patch, desc->next_trampoline);

			/* jump - escape the 2 GB range of the text segment */
			create_absolute_jump(
				desc->next_trampoline, patch->asm_wrapper);

			desc->next_trampoline += TRAMPOLINE_SIZE;
		} else {
			create_jump(JMP_OPCODE,
				patch->dst_jmp_patch, patch->asm_wrapper);
		}

		if (patch->uses_nop_trampoline) {
			/*
			 * Create a mini trampoline jump.
			 * The first two bytes of the NOP instruction are
			 * overwritten by a short jump instruction
			 * (with 8 bit displacement), to make sure whenever
			 * this the execution reaches the address where this
			 * NOP resided originally, it continues uninterrupted.
			 * The rest of the bytes occupied by this instruction
			 * are used as an mini extra trampoline table.
			 *
			 * See also: the is_overwritable_nop function in
			 * the intercept_desc.c source file.
			 */

			/* jump from syscall to mini trampoline */
			create_short_jump(patch->syscall_addr,
			    patch->dst_jmp_patch);

			/*
			 * Short jump to next instruction, skipping the newly
			 * created trampoline jump.
			 */
			create_short_jump(patch->nop_trampoline.address,
			    after_nop(&patch->nop_trampoline));
		} else {
			unsigned char *byte;

			for (byte = patch->dst_jmp_patch + JUMP_INS_SIZE;
				byte < patch->return_address;
				++byte) {
				*byte = INT3_OPCODE;
			}
		}
	}

	mprotect_no_intercept(first_page, size,
	    PROT_READ | PROT_EXEC,
	    "mprotect PROT_READ | PROT_EXEC");
}

/*
 * next_asm_wrapper_space
 * Assigns a memory region in syscall_intercept's memory region
 * for an asm wrapper instance.
 * This is trivial memory allocation, using the asm_wrapper_space
 * array as a memory pool.
 */
static unsigned char *
next_asm_wrapper_space(void)
{
	static size_t next = 0x1000;

	unsigned char *result;

	if (next + tmpl_size + PAGE_SIZE > sizeof(asm_wrapper_space))
		xabort("not enough space in asm_wrapper_space");

	result = asm_wrapper_space + next;

	next += tmpl_size;

	return result;
}

/*
 * mprotect_asm_wrappers
 * The code generated into the data segment at the asm_wrapper_space
 * array is not executable by default. This routine sets that memory region
 * to be executable, must called before attempting to execute any patched
 * syscall.
 */
void
mprotect_asm_wrappers(void)
{
	mprotect_no_intercept(
	    round_down_address(asm_wrapper_space + PAGE_SIZE),
	    sizeof(asm_wrapper_space) - PAGE_SIZE,
	    PROT_READ | PROT_EXEC,
	    "mprotect_asm_wrappers PROT_READ | PROT_EXEC");
}
