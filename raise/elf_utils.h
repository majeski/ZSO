#ifndef ELF_UTILS__H
#define ELF_UTILS__H

#include <asm/ldt.h>
#include <linux/elf.h>
#include <sys/procfs.h>

/*
 * NT_FILE note header, described here:
 * http://lxr.free-electrons.com/source/fs/binfmt_elf.c#L1515
 */
typedef struct _Elf32_FNhdr {
    long count;
    long page_size;
} Elf32_FNhdr;

/*
 * first three fields come from NT_FILE note
 *
 * filename_ofs - filename offset in core file
 * filename_len - filename lenght (including '\0') in core file
 */
typedef struct _file_info {
    long start;
    long end;
    long file_ofs;

    long filename_ofs;
    long filename_len;
} file_info;

/*
 * validates type, machine, version and flags
 */
extern void check_header(Elf32_Ehdr *header);

/*
 * returns pointer to note entry in program headers
 */
extern Elf32_Phdr *get_note_header(Elf32_Phdr *program_hdrs, int hdrs_c);

/*
 * skips name or desc in note with respect to padding
 */
extern ssize_t skip_note_section(int core_fd, off_t size);

/*
 * - allocates memory and saves note description there
 * with additional byte '\0' after end for convenience
 * - saves offset of description
 */
extern void *read_files_desc(int core_fd, off_t *files_desc_off);

extern void get_notes(int core_fd, Elf32_Phdr *note_header,
                      struct elf_prstatus *prstatus, struct user_desc *tls,
                      off_t *files_entry_offset);

extern void get_file_infos(char *note_desc, file_info infos[]);

#endif