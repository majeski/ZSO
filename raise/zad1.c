#include <asm/ldt.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/elf.h>
#include <memory.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

extern void *mmap_asm(void *addr, int memsiz, int prot, int flags, int fd, int offset);
extern int mprotect_asm(void *addr, int len, int prot);
extern int syscall_asm(int nr, void *arg);

void print(Elf32_Ehdr *header) {
//    printf("object file type %hd\n", header->e_type);
//    printf("version %u\n", header->e_version);
//    printf("program header offset %u\n", header->e_phoff);
//    printf("section header offset %u\n", header->e_shoff);
//    printf("program header table entry size %hd\n", header->e_phentsize);
//    printf("program header table entry count %hd\n", header->e_phnum);
//    printf("---\n");
}

void print2(Elf32_Phdr *header) {
    printf("type %u\n", header->p_type);
    printf("offset %x\n", header->p_offset);
    printf("vaddr %x\n", header->p_vaddr);
    printf("filesz %x\n", header->p_filesz);
    printf("memsz %x\n", header->p_memsz);
    printf("--\n");
}

typedef struct file_info {
    long start;
    long end;
    long file_ofs;
} f_info;

static struct elf_prstatus prstatus;
static struct user_desc tls;

void read_files(int fd, int *to_read, Elf32_Phdr *hdrs, int hdrs_s) {
    long count;
    long page_size;
    
    read(fd, (void *)&count, sizeof(count));
    read(fd, (void *)&page_size, sizeof(page_size));
    *to_read -= sizeof(long) * 2;
    
    printf("count %ld\n", count);
    printf("page_size %ld\n", page_size);
    
    f_info info[count];
    
    read(fd, (void *)info, count * sizeof(f_info));
    *to_read -= count * sizeof(f_info);
    
    char buf[256];
    int files[count];
    int end;
    int i;
    for (i = 0; i < count; i++) {
        end = -1;
        do {
            end++;
            read(fd, buf + end, 1);
            *to_read -= 1;
        } while (buf[end]);
        printf("%d: %lx %lx filename: %s\n", i, info[i].start, info[i].end, buf);
        files[i] = open(buf, O_RDONLY);
        assert(files[i] != -1);
    }
    
    char code[] = {
        0xb8, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%eax
        0x50,                               // push   %eax
        0x9d,                               // popf
        0xb9, 0xff, 0xff, 0xff, 0xff,       // mov    $0xffffffff,%ecx
        0xba, 0xff, 0xff, 0xff, 0xff,       // mov    $0xffffffff,%edx
        0xbb, 0xff, 0xff, 0xff, 0xff,       // mov    $0xffffffff,%ebx
        0xbc, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%esp
        0xbd, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%ebp
        0xbe, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%esi
        0xbf, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%edi
        0xb8, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%eax
        0x8e, 0xe8,                         // mov    %eax,%gs
        0xb8, 0xff, 0xff, 0xff, 0xff,      	// mov    $0xffffffff,%eax
        0x68, 0xff, 0xff, 0xff, 0xff,       // push   $0xffffffff
        0xc3};                              // ret
    
    struct pt_regs *regs = (struct pt_regs *)(&prstatus.pr_reg);
    memcpy(code + 1, &(regs->eflags), 4);
    memcpy(code + 8, &(regs->ecx), 4);
    memcpy(code + 13, &(regs->edx), 4);
    memcpy(code + 18, &(regs->ebx), 4);
    memcpy(code + 23, &(regs->esp), 4);
    memcpy(code + 28, &(regs->ebp), 4);
    memcpy(code + 33, &(regs->esi), 4);
    memcpy(code + 38, &(regs->edi), 4);
    memcpy(code + 43, &(regs->xgs), 4);
    memcpy(code + 50, &(regs->eax), 4);
    memcpy(code + 55, &(regs->eip), 4);
    
    printf("%x\n", regs->xgs);
    
    void *addr = mmap((void *)0x07040000, sizeof(code),
                      PROT_EXEC | PROT_READ | PROT_WRITE,
                      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    printf("%p\n", addr);
    memcpy(addr, code, sizeof(code));
    
    void *mmap_r;
    
    // load empty
//    printf("step 1\n");
    for (i = 0; i < hdrs_s; i++) {
        if (hdrs[i].p_type == PT_LOAD && hdrs[i].p_memsz > 0) {
//            printf("mapping %x %x\n", hdrs[i].p_vaddr, hdrs[i].p_memsz);
            mmap_r = mmap_asm((void *)hdrs[i].p_vaddr, hdrs[i].p_memsz,
                          PROT_NONE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
//            printf("%p\n", mmap_r);
            assert(mmap_r == (void *)hdrs[i].p_vaddr);
        }
    }
    
    // load from files
//    printf("step 2\n");
    for (i = 0; i < count; i++) {
//        printf("mapping %lx %lx\n", info[i].start, info[i].end - info[i].start);
        mmap_r = mmap_asm((void *)info[i].start, info[i].end - info[i].start,
                      PROT_NONE, MAP_FIXED | MAP_PRIVATE, files[i], info[i].file_ofs * page_size);
//        printf("%p\n", mmap_r);
        assert(mmap_r == (void *)info[i].start);
    }
    
    // override from LOAD
    int prot;
    
//    printf("step 3\n");
    for (i = 0; i < hdrs_s; i++) {
        if (hdrs[i].p_type == PT_LOAD) {
            if (hdrs[i].p_filesz > 0) {
//                printf("mapping %x %x\n", hdrs[i].p_vaddr, hdrs[i].p_filesz);
                mmap_r = mmap_asm((void *)hdrs[i].p_vaddr, hdrs[i].p_filesz,
                              PROT_NONE, MAP_FIXED | MAP_PRIVATE, fd, hdrs[i].p_offset);
//                printf("%p\n", mmap_r);
                assert(mmap_r == (void *)hdrs[i].p_vaddr);
            }
            
            prot = 0;
            if (hdrs[i].p_flags & PF_X) {
                prot |= PROT_EXEC;
            }
            if (hdrs[i].p_flags & PF_R) {
                prot |= PROT_READ;
            }
            if (hdrs[i].p_flags & PF_W) {
                prot |= PROT_WRITE;
            }
            if (prot == 0) {
                prot = PROT_NONE;
            }
        
            mprotect_asm((void *)hdrs[i].p_vaddr, hdrs[i].p_memsz, prot);
//            printf("mprotect %d\n", mprotect((void *)hdrs[i].p_vaddr, hdrs[i].p_memsz, prot));
        }
    }
    
    for (i = 0; i < count; i++) {
        syscall_asm(__NR_close, (void *)files[i]);
    }
    
    syscall_asm(__NR_set_thread_area, &tls);
//    printf("after set thread\n");
    void (*f)() = addr;
    f();
}



void read_note(int fd, int *to_read, Elf32_Phdr *hdrs, int hdrs_s) {
    int namesz;
    int descsz;
    int type;
    int old_to_read = *to_read;
    
    Elf32_Nhdr note;
    read(fd, (void *)&note, sizeof(Elf32_Nhdr));
    
    type = note.n_type;
    namesz = note.n_namesz;
    descsz = note.n_descsz;
    *to_read -= sizeof(Elf32_Nhdr);
    
    if (type == NT_PRSTATUS) {
        printf("type: NT_PRSTATUS\n");
    }
    else if (type == NT_PRPSINFO) {
        printf("type: NT_PRPSINFO\n");
    }
    else if (type == NT_SIGINFO) {
        printf("type: NT_SIGINFO\n");
    }
    else if (type == NT_AUXV) {
        printf("type: NT_AUXV\n");
    }
    else if (type == NT_FILE) {
        printf("type: NT_FILE\n");
    }
    else if (type == NT_386_TLS) {
        printf("type: NT_386_TLS\n");
    }
    else {
        printf("type: other\n");
    }
    
    if (namesz > 0) {
        char name[namesz + 1];
        read(fd, (void *)name, namesz);
        printf("name %s\n", name);
        *to_read -= namesz;
        
        if (namesz % 4 > 0) {
            *to_read -= 4 - (namesz % 4);
            lseek(fd, 4 - (namesz % 4), SEEK_CUR);
        }
    }
    
    if (type == NT_PRSTATUS && descsz > 0) {
        read(fd, (void *)&prstatus, sizeof(struct elf_prstatus));
        *to_read -= sizeof(prstatus);
    } else if (type == NT_FILE && descsz > 0) {
        read_files(fd, to_read, hdrs, hdrs_s);
        
        if (descsz % 4 > 0) {
            *to_read -= 4 - (descsz % 4);
            lseek(fd, 4 - (descsz % 4), SEEK_CUR);
        }
    } else if (type == NT_386_TLS && descsz > 0) {
//        struct user_desc tls;
//        read(fd, (void *)&tls, sizeof(tls));
//        *to_read -= sizeof(tls);
//        
//        syscall(__NR_set_thread_area, &tls);
        assert(0 && "should not happen");
    } else if (descsz > 0) {
        char desc[descsz + 1];
        read(fd, (void *)desc, descsz);
        *to_read -= descsz;
        
        if (descsz % 4 > 0) {
            *to_read -= 4 - (descsz % 4);
            lseek(fd, 4 - (descsz % 4), SEEK_CUR);
        }
    }
    
    printf("read: %x\n--\n", old_to_read - *to_read);
    printf("to read: %x\n", *to_read);
}

void read_tls(int fd, int *to_read) {
    int namesz;
    int descsz;
    int type;
    
    Elf32_Nhdr note;
    read(fd, (void *)&note, sizeof(Elf32_Nhdr));
    
    type = note.n_type;
    namesz = note.n_namesz;
    descsz = note.n_descsz;
    *to_read -= sizeof(Elf32_Nhdr);
    
    if (type == NT_PRSTATUS) {
        printf("type: NT_PRSTATUS\n");
    }
    else if (type == NT_PRPSINFO) {
        printf("type: NT_PRPSINFO\n");
    }
    else if (type == NT_SIGINFO) {
        printf("type: NT_SIGINFO\n");
    }
    else if (type == NT_AUXV) {
        printf("type: NT_AUXV\n");
    }
    else if (type == NT_FILE) {
        printf("type: NT_FILE\n");
    }
    else if (type == NT_386_TLS) {
        printf("type: NT_386_TLS\n");
    }
    else {
        printf("type: other\n");
    }
    
    if (namesz > 0) {
        char name[namesz + 1];
        read(fd, (void *)name, namesz);
        printf("name %s\n", name);
        *to_read -= namesz;
        
        if (namesz % 4 > 0) {
            *to_read -= 4 - (namesz % 4);
            lseek(fd, 4 - (namesz % 4), SEEK_CUR);
        }
    }
    
    if (type == NT_386_TLS && descsz > 0) {
        read(fd, (void *)&tls, sizeof(tls));
        *to_read -= sizeof(tls);
    } else if (descsz > 0) {
        char desc[descsz + 1];
        read(fd, (void *)desc, descsz);
        *to_read -= descsz;
        
        if (descsz % 4 > 0) {
            *to_read -= 4 - (descsz % 4);
            lseek(fd, 4 - (descsz % 4), SEEK_CUR);
        }
    }
}

static void main2() {
    volatile int x1;
    printf("main2: %p\n", &x1);
    
    Elf32_Ehdr header;
    
    FILE *input = fopen("test_core", "r");
    assert(input != NULL);
    
    int fd = fileno(input);
    
    printf("read %u\n", read(fd, (void *)&header, sizeof(Elf32_Ehdr)));
    print(&header);
    
    lseek(fd, header.e_phoff, SEEK_SET);
    
    Elf32_Phdr program_hdrs[header.e_phnum];
    printf("read %u\n", read(fd, (void *)program_hdrs, sizeof(Elf32_Phdr) * header.e_phnum));
    
    int i;
    Elf32_Phdr *note_header;
    
    for (i = 0; i < header.e_phnum; i++) {
        printf("%d\n", i);
        if (program_hdrs[i].p_type == PT_NOTE) {
            printf("NOTE\n");
            note_header = program_hdrs + i;
        }
        
        print2(program_hdrs + i);
    }
    
    lseek(fd, note_header->p_offset, SEEK_SET);
    int to_read = note_header->p_filesz;
    while (to_read > 0) {
        read_tls(fd, &to_read);
    }
    
    lseek(fd, note_header->p_offset, SEEK_SET);
    to_read = note_header->p_filesz;
    while (to_read > 0) {
        read_note(fd, &to_read, program_hdrs, header.e_phnum);
    }
    
    printf("the end\n");
}

static ucontext_t uctx_main, context;
static char stack[65536];

int main() {
    volatile int x1;
    printf("main: %p\n", &x1);
    
    if (getcontext(&context) == -1) {
        assert(0 && "get");
    }
    
    printf("after make\n");
    context.uc_stack.ss_sp = stack;
    context.uc_stack.ss_size = 65536;
    context.uc_link = NULL;
    makecontext(&context, main2, 0);
    
    printf("before swap\n");
    if (swapcontext(&uctx_main, &context) == -1) {
        assert(0 && "swap");
    }
    assert(0);
}