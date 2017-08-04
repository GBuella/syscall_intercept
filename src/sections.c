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

#include "sections.h"
#include "intercept_util.h"

#include <assert.h>
#include <string.h>
#include <unistd.h>

/*
 * add_text_info -- Fill the appropriate fields in an obj_desc struct
 * about the corresponding code text.
 */
static void
add_text_info(struct obj_desc *obj, struct sections *sections,
		const Elf64_Shdr *header, Elf64_Half index)
{
	obj->text_offset = header->sh_offset;
	obj->text_start = obj->base_addr + header->sh_addr;
	obj->text_end = obj->text_start + header->sh_size - 1;
	sections->text_section_index = index;
}

static void
add_table_info(struct sections *secs,
		struct section_list *list, const Elf64_Shdr *header)
{
	if (list->count < secs->section_count) {
		list->headers[list->count] = *header;
		list->count++;
	} else {
		xabort("allocated section_list exhausted");
	}
}


/*
 * find_sections
 *
 * See: man elf
 */
void
find_sections(struct obj_desc *obj, struct sections *sections, long fd)
{
	Elf64_Ehdr elf_header;

	sections->symbol_tables.count = 0;
	sections->rela_tables.count = 0;

	xread(fd, &elf_header, sizeof(elf_header));

	sections->section_count = elf_header.e_shnum;

	if (elf_header.e_shnum == 0) {
		sections->symbol_tables.headers = NULL;
		sections->rela_tables.headers = NULL;
		return;
	}

	Elf64_Shdr sec_headers[elf_header.e_shnum];

	sections->symbol_tables.headers =
	    xmmap_anon(sizeof(sections->symbol_tables.headers[0]) *
			    elf_header.e_shnum);
	sections->rela_tables.headers =
	    xmmap_anon(sizeof(sections->symbol_tables.headers[0]) *
			    elf_header.e_shnum);

	xlseek(fd, elf_header.e_shoff, SEEK_SET);
	xread(fd, sec_headers, elf_header.e_shnum * sizeof(Elf64_Shdr));

	char sec_string_table[sec_headers[elf_header.e_shstrndx].sh_size];

	xlseek(fd, sec_headers[elf_header.e_shstrndx].sh_offset, SEEK_SET);
	xread(fd, sec_string_table,
	    sec_headers[elf_header.e_shstrndx].sh_size);

	bool text_section_found = false;

	for (Elf64_Half i = 0; i < elf_header.e_shnum; ++i) {
		const Elf64_Shdr *section = &sec_headers[i];
		char *name = sec_string_table + section->sh_name;

		debug_dump("looking at section: \"%s\" type: %ld\n",
		    name, (long)section->sh_type);
		if (strcmp(name, ".text") == 0) {
			text_section_found = true;
			add_text_info(obj, sections, section, i);
		} else if (section->sh_type == SHT_SYMTAB ||
		    section->sh_type == SHT_DYNSYM) {
			debug_dump("found symbol table: %s\n", name);
			add_table_info(sections,
					&sections->symbol_tables, section);
		} else if (section->sh_type == SHT_RELA) {
			debug_dump("found relocation table: %s\n", name);
			add_table_info(sections,
					&sections->rela_tables, section);
		}
	}

	if (!text_section_found)
		xabort("text section not found");
}

void
dispose_section_info(struct sections *sections)
{
	if (sections->symbol_tables.headers != NULL)
		xmunmap(sections->symbol_tables.headers,
		    sections->section_count *
		    sizeof(sections->symbol_tables.headers[0]));

	if (sections->rela_tables.headers != NULL)
		xmunmap(sections->rela_tables.headers,
		    sections->section_count *
		    sizeof(sections->rela_tables.headers[0]));
}

/*
 * find_jumps_in_section_syms
 *
 * Read the .symtab or .dynsym section, which stores an array of Elf64_Sym
 * structs. Some of these symbols are functions in the .text section,
 * thus their entry points are jump destinations.
 *
 * The st_value fields holds the virtual address of the symbol
 * relative to the base address.
 *
 * The format of the entries:
 *
 * typedef struct
 * {
 *   Elf64_Word	st_name;            Symbol name (string tbl index)
 *   unsigned char st_info;         Symbol type and binding
 *   unsigned char st_other;        Symbol visibility
 *   Elf64_Section st_shndx;        Section index
 *   Elf64_Addr	st_value;           Symbol value
 *   Elf64_Xword st_size;           Symbol size
 * } Elf64_Sym;
 *
 * The field st_value is offset of the symbol in the object file.
 */
void
find_jumps_in_section_syms(struct obj_desc *obj, struct sections *sections,
			Elf64_Shdr *section, long fd)
{
	assert(section->sh_type == SHT_SYMTAB ||
		section->sh_type == SHT_DYNSYM);

	size_t sym_count = section->sh_size / sizeof(Elf64_Sym);

	Elf64_Sym syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC)
			continue; /* it is not a function */

		if (syms[i].st_shndx != sections->text_section_index)
			continue; /* it is not in the text section */

		debug_dump("jump target: %lx\n",
		    (unsigned long)syms[i].st_value);

		unsigned char *address = obj->base_addr + syms[i].st_value;

		/* a function entry point in .text, mark it */
		mark_jump(obj, address);

		/* a function's end in .text, mark it */
		if (syms[i].st_size != 0)
			mark_jump(obj, address + syms[i].st_size);
	}
}

/*
 * find_jumps_in_section_rela - look for offsets in relocation entries
 *
 * The constant SHT_RELA refers to "Relocation entries with addends" -- see the
 * elf.h header file.
 *
 * The format of the entries:
 *
 * typedef struct
 * {
 *   Elf64_Addr	r_offset;      Address
 *   Elf64_Xword r_info;       Relocation type and symbol index
 *   Elf64_Sxword r_addend;    Addend
 * } Elf64_Rela;
 *
 */
void
find_jumps_in_section_rela(struct obj_desc *obj,
			Elf64_Shdr *section, long fd)
{
	assert(section->sh_type == SHT_RELA);

	size_t sym_count = section->sh_size / sizeof(Elf64_Rela);

	Elf64_Rela syms[sym_count];

	xlseek(fd, section->sh_offset, SEEK_SET);
	xread(fd, &syms, section->sh_size);

	for (size_t i = 0; i < sym_count; ++i) {
		switch (ELF64_R_TYPE(syms[i].r_info)) {
			case R_X86_64_RELATIVE:
			case R_X86_64_RELATIVE64:
				/* Relocation type: "Adjust by program base" */

				debug_dump("jump target: %lx\n",
				    (unsigned long)syms[i].r_addend);

				unsigned char *address =
				    obj->base_addr + syms[i].r_addend;

				mark_jump(obj, address);

				break;
		}
	}
}
