#include <memory.h>

#include "elf_utils.h"
#include "err.h"

void check_header(Elf32_Ehdr *header) {
    ASSERT_EXPECTED(header->e_type, ET_CORE, "Incorrect ELF: object file type");
    ASSERT_EXPECTED(header->e_machine, EM_386, "Incorrect ELF: architecture");
    ASSERT_EXPECTED(header->e_version, EV_CURRENT,
                    "Incorrect ELF: object file version");
    ASSERT_EXPECTED(header->e_flags, 0,
                    "Incorrect ELF: processor-specific flags");

    if (header->e_phnum == 0) {
        user_err("Incorrect ELF: no program header table");
    }
}

Elf32_Phdr *get_note_header(Elf32_Phdr *program_hdrs, int hdrs_c) {
    Elf32_Phdr *result = NULL;
    int i;
    for (i = 0; i < hdrs_c; i++) {
        if (program_hdrs[i].p_type == PT_NOTE) {
            result = program_hdrs + i;
        }
    }

    if (result == NULL) {
        user_err("Incorrect ELF: cannot find note header");
    }
    return result;
}

void get_notes(int core_fd, Elf32_Phdr *note_header,
               struct elf_prstatus *prstatus, struct user_desc *tls,
               off_t *files_entry_offset) {
    int prstatus_found = 0;
    int tls_found = 0;
    int files_found = 0;
    int bytes_left = note_header->p_filesz;
    int to_read;
    Elf32_Nhdr note;

    CHECK_ERR(lseek(core_fd, note_header->p_offset, SEEK_SET) != -1);
    while (bytes_left > 0) {
        to_read = sizeof(Elf32_Nhdr);
        CHECK_ERR(read(core_fd, (void *)&note, to_read) == to_read);
        bytes_left -= to_read;

        if (note.n_type == NT_FILE) {
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
            to_read = sizeof(struct elf_prstatus);
            CHECK_ERR(read(core_fd, (void *)prstatus, to_read) == to_read);
            bytes_left -= to_read;
            prstatus_found = 1;
        } else if (note.n_type == NT_386_TLS) {
            to_read = sizeof(struct user_desc);
            CHECK_ERR(read(core_fd, (void *)tls, to_read) == to_read);
            bytes_left -= to_read;
            tls_found = 1;
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
    if (!tls_found) {
        user_err("Incorrect ELF: cannot find NT_386_TLS");
    }
    if (!files_found) {
        user_err("Incorrect ELF: cannot find NT_FILE");
    }
}

void *read_files_desc(int core_fd, off_t *files_desc_off) {
    Elf32_Nhdr note;
    int to_read = sizeof(Elf32_Nhdr);
    CHECK_ERR(read(core_fd, (void *)&note, to_read) == to_read);
    skip_note_section(core_fd, note.n_namesz);

    *files_desc_off = lseek(core_fd, 0, SEEK_CUR);
    CHECK_ERR(*files_desc_off != -1);

    to_read = note.n_descsz;
    void *desc = malloc(to_read + 1);
    CHECK_ERR(desc != NULL);
    CHECK_ERR(read(core_fd, desc, to_read) == to_read);
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