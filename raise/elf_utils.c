#include <memory.h>

#include "elf_utils.h"
#include "err.h"
#include "raw_syscalls.h"
#include "static_heap.h"

void raw_safe_pread(int fd, void *buf, size_t count, off_t offset) {
    char *cur_buf = (char *)buf;
    while (count) {
        ssize_t read_res = raw_pread(fd, cur_buf, count, offset);
        RAW_ASSERT(read_res != -1, "pread error");
        RAW_ASSERT(read_res != 0, "pread error: unexpected EOF");
        offset += read_res;
        cur_buf += read_res;
        count -= read_res;
    }
}

void safe_pread(int fd, void *buf, size_t count, off_t offset) {
    char *cur_buf = (char *)buf;
    while (count) {
        ssize_t read_res = pread(fd, cur_buf, count, offset);
        CHECK_ERR(read_res != -1);
        if (read_res == 0) {
            user_err("pread error: unexpected EOF");
        }
        offset += read_res;
        cur_buf += read_res;
        count -= read_res;
    }
}

void safe_read(int fd, void *buf, size_t count) {
    char *cur_buf = (char *)buf;
    while (count) {
        ssize_t read_res = read(fd, cur_buf, count);
        CHECK_ERR(read_res != -1);
        if (read_res == 0) {
            user_err("read error: unexpected EOF");
        }
        cur_buf += read_res;
        count -= read_res;
    }
}

void check_header(Elf32_Ehdr *header) {
    ASSERT_EXPECTED(memcmp(header->e_ident, ELFMAG, SELFMAG), 0,
                    "Incorrect ELF: magic number");
    ASSERT_EXPECTED(header->e_type, ET_CORE, "Incorrect ELF: object file type");
    ASSERT_EXPECTED(header->e_machine, EM_386, "Incorrect ELF: architecture");
    ASSERT_EXPECTED(header->e_version, EV_CURRENT,
                    "Incorrect ELF: object file version");
    if (header->e_phnum == 0) {
        user_err("Incorrect ELF: no program header table");
    }
}

Elf32_Phdr *get_note_header(Elf32_Phdr *program_hdrs, int hdrs_c) {
    Elf32_Phdr *result = NULL;
    int i;
    for (i = 0; i < hdrs_c; i++) {
        if (program_hdrs[i].p_type == PT_NOTE) {
            if (result != NULL) {
                user_err("Incorrect ELF: multiple NOTE sections");
            }
            result = program_hdrs + i;
        }
    }

    if (result == NULL) {
        user_err("Incorrect ELF: cannot find note header");
    }
    return result;
}

void get_notes(int core_fd, Elf32_Phdr *note_header,
               struct elf_prstatus *prstatus, struct user_desc **tls,
               int *tls_num, off_t *files_entry_offset) {
    int prstatus_found = 0;
    int files_found = 0;
    *tls_num = 0;
    int bytes_left = note_header->p_filesz;
    int to_read;
    Elf32_Nhdr note;

    CHECK_ERR(lseek(core_fd, note_header->p_offset, SEEK_SET) != -1);
    while (bytes_left > 0) {
        to_read = sizeof(Elf32_Nhdr);
        safe_read(core_fd, (void *)&note, to_read);
        bytes_left -= to_read;

        if (note.n_type == NT_FILE) {
            if (files_found) {
                user_err("Incorrect ELF: multiple NT_FILE");
            }
            // get offset to current note's desc
            *files_entry_offset = lseek(core_fd, 0, SEEK_CUR);
            CHECK_ERR(*files_entry_offset != -1);
            *files_entry_offset -= sizeof(Elf32_Nhdr);
            files_found = 1;
        }

        // skip name
        if (note.n_namesz > 0) {
            bytes_left -= skip_note_section(core_fd, note.n_namesz);
        }

        if (note.n_type == NT_PRSTATUS) {
            if (prstatus_found) {
                user_err("Incorrect ELF: multiple NT_PRSTATUS");
            }
            to_read = sizeof(struct elf_prstatus);
            safe_read(core_fd, (void *)prstatus, to_read);
            bytes_left -= to_read;
            prstatus_found = 1;
        } else if (note.n_type == NT_386_TLS) {
            if (*tls_num != 0) {
                user_err("Incorrect ELF: multiple NT_386_TLS");
            }
            *tls = static_alloc(note.n_descsz);
            *tls_num = note.n_descsz / sizeof(struct user_desc);

            to_read = note.n_descsz;
            safe_read(core_fd, (void *)(*tls), to_read);
            bytes_left -= to_read;
        } else {
            // skip other types
            bytes_left -= skip_note_section(core_fd, note.n_descsz);
        }
    }

    if (bytes_left < 0) {
        user_err("Incorrect ELF: something wrong in PT_NOTE");
    }

    if (!prstatus_found) {
        user_err("Incorrect ELF: cannot find NT_PRSTATUS");
    }
    if (!files_found) {
        user_err("Incorrect ELF: cannot find NT_FILE");
    }
}

void *read_files_desc(int core_fd, off_t *files_desc_off) {
    Elf32_Nhdr note;
    int to_read = sizeof(Elf32_Nhdr);
    safe_read(core_fd, (void *)&note, to_read);
    skip_note_section(core_fd, note.n_namesz);

    *files_desc_off = lseek(core_fd, 0, SEEK_CUR);
    CHECK_ERR(*files_desc_off != -1);

    to_read = note.n_descsz;
    void *desc = malloc(to_read + 1);
    CHECK_ERR(desc != NULL);
    safe_read(core_fd, desc, to_read);
    ((char *)desc)[to_read] = 0;
    return desc;
}

ssize_t skip_note_section(int core_fd, off_t size) {
    if (size % 4) {
        size += 4 - (size % 4);
    }
    CHECK_ERR(lseek(core_fd, size, SEEK_CUR) != -1);
    return size;
}

void get_file_infos(char *note_desc, file_info infos[]) {
    char *begin = note_desc;
    int to_read;

    Elf32_FNhdr header;
    to_read = sizeof(Elf32_FNhdr);
    memcpy(&header, note_desc, to_read);
    note_desc += to_read;

    int i;
    for (i = 0; i < header.count; i++) {
        to_read = 3 * sizeof(long);
        memcpy(infos + i, note_desc, to_read);
        note_desc += to_read;
    }

    for (i = 0; i < header.count; i++) {
        infos[i].filename_ofs = note_desc - begin;
        infos[i].filename_len = strlen(note_desc);
        note_desc += infos[i].filename_len + 1;
    }
}