#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <memory.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <ucontext.h>

#include "elf_utils.h"
#include "err.h"
#include "jmp_function.h"
#include "raw_syscalls.h"
#include "static_heap.h"

static ucontext_t uctx_main, context;
static char *core_path;

static char stack[8192];
static void real_main();

int main(int argc, char **argv) {
    if (argc != 2 || !argv[1]) {
        printf("Incorrect arguments\nUsage: %s path_to_core_file\n", argv[0]);
        exit(EXIT_SUCCESS);
    }
    core_path = argv[1];

    CHECK_ERR(getcontext(&context) == 0);

    context.uc_stack.ss_sp = stack;
    context.uc_stack.ss_size = sizeof(stack);
    context.uc_link = NULL;
    makecontext(&context, real_main, 0);

    CHECK_ERR(swapcontext(&uctx_main, &context) == 0);
    return EXIT_FAILURE;
}

static void map_memory(int core_fd, file_info *infos, int infos_num,
                       Elf32_Phdr *hdrs, int hdrs_num);

static void real_main() {
    int core_fd = open(core_path, O_RDONLY);
    CHECK_ERR(core_fd != -1);

    // get ELF header
    Elf32_Ehdr elf_header;
    {
        ssize_t size = sizeof(Elf32_Ehdr);
        safe_read(core_fd, (void *)&elf_header, size);
        check_header(&elf_header);
    }

    // get program headers
    Elf32_Phdr *program_hdrs;
    {
        ssize_t size = sizeof(Elf32_Phdr) * elf_header.e_phnum;
        program_hdrs = static_alloc(size);
        safe_pread(core_fd, (void *)program_hdrs, size, elf_header.e_phoff);
    }

    // get information from NT_NOTE
    struct elf_prstatus prstatus;
    struct user_desc *tls;
    int tls_num = 0;
    file_info *file_infos;
    int file_infos_num;
    {
        off_t files_entry_offset;
        off_t files_desc_offset;

        // get note header
        Elf32_Phdr *note_header =
            get_note_header(program_hdrs, elf_header.e_phnum);
        get_notes(core_fd, note_header, &prstatus, &tls, &tls_num,
                  &files_entry_offset);

        // get note description
        CHECK_ERR(lseek(core_fd, files_entry_offset, SEEK_SET) != -1);
        void *files_note = read_files_desc(core_fd, &files_desc_offset);

        // get file infos from description
        Elf32_FNhdr file_note_header;
        memcpy(&file_note_header, files_note, sizeof(Elf32_FNhdr));
        file_infos_num = file_note_header.count;
        file_infos = static_alloc(sizeof(file_info) * file_infos_num);
        get_file_infos(files_note, file_infos);

        /*
         * file_infos contain offsets from the beggining of the description,
         * but we need offsets from the beggining of the core
         */
        int i;
        for (i = 0; i < file_infos_num; i++) {
            file_infos[i].filename_ofs += files_desc_offset;
        }

        free(files_note);
    }

    jmp_function final_jump = create_jmp_function(
        (void *)0x04000000, (struct pt_regs *)&prstatus.pr_reg);
    map_memory(core_fd, file_infos, file_infos_num, program_hdrs,
               elf_header.e_phnum);

    RAW_ASSERT(raw_syscall1(__NR_close, (int32_t)core_fd) != -1,
               "close failed");
    int i;
    for (i = 0; i < tls_num; i++) {
        RAW_ASSERT(raw_syscall1(__NR_set_thread_area, (int32_t)(tls + i)) != -1,
                   "set_thread_area failed");
    }
    final_jump();
}

static void map_empty_areas(Elf32_Phdr *hdrs, int hdrs_num);
static void map_files(int core_fd, file_info *infos, int infos_num);
static void override_from_load(int core_fd, Elf32_Phdr *hdrs, int hdrs_num);

/*
 * after mmaps heap, tls became undefined and glibc functions may not work
 */
static void map_memory(int core_fd, file_info *infos, int infos_num,
                       Elf32_Phdr *hdrs, int hdrs_num) {
    map_empty_areas(hdrs, hdrs_num);
    map_files(core_fd, infos, infos_num);
    override_from_load(core_fd, hdrs, hdrs_num);
}

/*
 * maps empty areas with PROT_NONE
 */
static void map_empty_areas(Elf32_Phdr *hdrs, int hdrs_num) {
    int i;
    for (i = 0; i < hdrs_num; i++) {
        if (hdrs[i].p_type == PT_LOAD && hdrs[i].p_memsz > 0) {
            void *mmap_r =
                raw_mmap((void *)hdrs[i].p_vaddr, hdrs[i].p_memsz, PROT_NONE,
                         MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
            RAW_ASSERT(mmap_r == (void *)hdrs[i].p_vaddr, "empty mmap failed");
        }
    }
}

/*
 * maps files with PROT_NONE
 */
static void map_files(int core_fd, file_info *infos, int infos_num) {
    int i;

    // prepare buffer
    ssize_t max_fname_len = 1;
    for (i = 0; i < infos_num; i++) {
        if (infos[i].filename_len > max_fname_len) {
            max_fname_len = infos[i].filename_len;
        }
    }
    void *filename = raw_mmap(NULL, max_fname_len, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    RAW_ASSERT(filename != MAP_FAILED, "filename mmap failed");

    // actual mmap
    for (i = 0; i < infos_num; i++) {
        raw_safe_pread(core_fd, filename, infos[i].filename_len + 1,
                       infos[i].filename_ofs);
        int fd = raw_open((char *)filename, O_RDONLY);
        RAW_ASSERT(fd != -1, "open failed");

        void *mmap_r =
            raw_mmap((void *)infos[i].start, infos[i].end - infos[i].start,
                     PROT_NONE, MAP_FIXED | MAP_PRIVATE, fd, infos[i].file_ofs);
        RAW_ASSERT(mmap_r == (void *)infos[i].start, "file mmap failed");

        RAW_ASSERT(raw_syscall1(__NR_close, fd) != -1, "close failed");
    }

    // remove buffer
    RAW_ASSERT(raw_munmap(filename, max_fname_len) == 0,
               "filename munmap failed");
}

static int load_prot_to_mmap_prot(int flags);

/*
 * maps areas from LOAD and updates protection
 */
static void override_from_load(int core_fd, Elf32_Phdr *hdrs, int hdrs_num) {
    int i;
    for (i = 0; i < hdrs_num; i++) {
        if (hdrs[i].p_type == PT_LOAD) {
            if (hdrs[i].p_filesz > 0) {
                void *mmap_r = raw_mmap(
                    (void *)hdrs[i].p_vaddr, hdrs[i].p_filesz, PROT_NONE,
                    MAP_FIXED | MAP_PRIVATE, core_fd, hdrs[i].p_offset);
                RAW_ASSERT(mmap_r == (void *)hdrs[i].p_vaddr,
                           "file mmap failed");
            }
            int prot = load_prot_to_mmap_prot(hdrs[i].p_flags);
            RAW_ASSERT(raw_mprotect((void *)hdrs[i].p_vaddr, hdrs[i].p_memsz,
                                    prot) == 0,
                       "mprotect failed");
        }
    }
}

static int load_prot_to_mmap_prot(int flags) {
    int prot = 0;
    if (flags & PF_X) {
        prot |= PROT_EXEC;
    }
    if (flags & PF_R) {
        prot |= PROT_READ;
    }
    if (flags & PF_W) {
        prot |= PROT_WRITE;
    }
    if (prot == 0) {
        prot = PROT_NONE;
    }
    return prot;
}