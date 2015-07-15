#include <mach/mach.h>
#if __IPHONE_OS_VERSION_MIN_REQUIRED
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_region(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t *size, vm_region_flavor_t flavor, vm_region_info_t info, mach_msg_type_number_t *infoCnt, mach_port_t *object_name);
int proc_pidpath(int pid, void * buffer, uint32_t  buffersize);
int proc_regionfilename(int pid, uint64_t address, void * buffer, uint32_t buffersize);
#else
#include <mach/mach_vm.h>
#include <libproc.h>
#endif
#include <stdio.h>
#include <assert.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <setjmp.h>
#include <sys/queue.h>
#include <sys/param.h>
#if !__IPHONE_OS_VERSION_MIN_REQUIRED
#include <pwd.h>
#include <unistd.h>
#include <Security/Security.h>
#endif

static bool is_64bit;
static mach_port_t task;
static int pid;
static task_dyld_info_data_t dyld_info;
static jmp_buf recovery_buf;

static void ask_for_access() {
#if !__IPHONE_OS_VERSION_MIN_REQUIRED
    // copied from gdb
    AuthorizationRights rights = {1, (AuthorizationItem[]) {{"system.privilege.taskport", 0, NULL, 0}}};
    AuthorizationRef author;
    AuthorizationFlags auth_flags =
        kAuthorizationFlagExtendRights |   
        kAuthorizationFlagPreAuthorize;
        /* no InteractionAllowed */
    assert(errAuthorizationSuccess == AuthorizationCreate(
        NULL,
        kAuthorizationEmptyEnvironment,
        auth_flags,
        &author));
    AuthorizationRights *more_rights;
    if(errAuthorizationSuccess == AuthorizationCopyRights(
        author,
        &rights,
        kAuthorizationEmptyEnvironment,
        auth_flags,
        &more_rights))
        return; 
    // derp, I don't like password windows
    OSStatus ret;
    do {
        printf("Admin username (%s): ", getlogin());
        char name[MAXLOGNAME];
        if(!fgets(name, sizeof(name), stdin))
            exit(1);
        name[strlen(name) - 1] = 0;
        if(name[0] == 0)
            strcpy(name, getlogin());

        char *pass = getpass("Password: ");
        if(!pass)
            exit(1);

        AuthorizationEnvironment env = {
            3,
            (AuthorizationItem[]) {
                { kAuthorizationEnvironmentUsername, strlen(name), name, 0 },
                { kAuthorizationEnvironmentPassword, strlen(pass), pass, 0 },
                { kAuthorizationEnvironmentShared, 0, NULL, 0 }
            }
        };
        ret = AuthorizationCopyRights(
            author,
            &rights,
            &env,
            auth_flags,
            &more_rights);
        memset(pass, 0, strlen(pass));
        printf("%d\n", ret);
    } while(errAuthorizationSuccess != ret);
#endif
}

static void read_from_task(void *p, mach_vm_address_t addr, mach_vm_size_t size) {
    mach_vm_size_t outsize;
    kern_return_t kr = mach_vm_read_overwrite(task, addr, size, (mach_vm_address_t) p, &outsize);
    if(kr || outsize != size) {
        fprintf(stderr, "read_from_task(0x%llx, 0x%llx): ", (long long) addr, (long long) size);
        if(kr)
            fprintf(stderr, "kr=%d\n", (int) kr);
        else
            fprintf(stderr, "short read\n");
        _longjmp(recovery_buf, 1);
    }
}

static uint64_t read_64(char **pp) {
    return *(*(uint64_t **)pp)++;
}
static uint32_t read_32(char **pp) {
    return *(*(uint32_t **)pp)++;
}
static mach_vm_address_t read_ptr(char **pp) {
    return is_64bit ? read_64(pp) : read_32(pp);
}

static struct region {
    mach_vm_address_t addr;
    mach_vm_size_t size;
    char *label;
} *regions;
int num_regions = 0, alloc_regions = 0;

static struct region *new_region() {
    if(num_regions == alloc_regions) {
        alloc_regions += 100;
        regions = realloc(regions, alloc_regions * sizeof(*regions));
    }
    return &regions[num_regions++];
}

static void do_image(mach_vm_address_t load_address, const char *path) {
    struct mach_header mh;
    read_from_task(&mh, load_address, sizeof(mh));

    bool m64;
    if(mh.magic == MH_MAGIC_64)
        m64 = true;
    else if(mh.magic == MH_MAGIC)
        m64 = false;
    else {
        fprintf(stderr, "unknown magic %x\n", (int) mh.magic);
        return;
    }
        
    if(mh.sizeofcmds > 100000)
        goto mal;
    char *lcs = malloc(mh.sizeofcmds), *end = lcs + mh.sizeofcmds;
    read_from_task(lcs, load_address + (m64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header)), mh.sizeofcmds);

    mach_vm_address_t slide = 0;

    int region_base = num_regions;

    while((size_t) (end - lcs) >= sizeof(struct load_command)) {
        struct load_command *lc = (void *) lcs;
        if((size_t) (end - lcs) < lc->cmdsize)
            goto mal;

        switch(lc->cmd) {
            mach_vm_address_t vmaddr;
            mach_vm_size_t vmsize;
            uint32_t fileoff, filesize;
            char segname[16];

            case LC_SEGMENT: {
                struct segment_command *seg = (void *) lcs;
                if(lc->cmdsize < sizeof(*seg))
                    goto mal;
                vmaddr = seg->vmaddr;
                vmsize = seg->vmsize;
                fileoff = seg->fileoff;
                filesize = seg->filesize;
                strlcpy(segname, seg->segname, 16);
                goto segment;
            }
            case LC_SEGMENT_64: {
                struct segment_command_64 *seg = (void *) lcs;
                if(lc->cmdsize < sizeof(*seg))
                    goto mal;
                vmaddr = seg->vmaddr;
                vmsize = seg->vmsize;
                fileoff = seg->fileoff;
                filesize = seg->filesize;
                strlcpy(segname, seg->segname, 16);
                goto segment;
            }
            segment: {
                if(fileoff == 0 && filesize != 0)
                    slide = load_address - vmaddr;
                struct region *r = new_region();
                r->addr = vmaddr;
                r->size = vmsize;
                asprintf(&r->label, "%s (%s)", segname, path);
                break;
            }
        }

        lcs += lc->cmdsize;
    }
    if(end != lcs)
        goto mal;

    for(int i = region_base; i < num_regions; i++) {
        regions[i].addr += slide;
        asprintf(&regions[i].label, "%s slide=%llx", regions[i].label, (long long) slide);
    }
    
    return;
mal:
    fprintf(stderr, "** malformed mach-o image %s\n", path);
}

static void lookup_dyld_images() {
    char all_images[12], *p = all_images;
    read_from_task(p, dyld_info.all_image_info_addr + 4, 12);
    uint32_t info_array_count = read_32(&p);
    mach_vm_address_t info_array = read_ptr(&p);
    if(info_array_count > 10000) {
        fprintf(stderr, "** dyld image info had malformed data.\n");
        return;
    }

    size_t size = (is_64bit ? 24 : 12) * info_array_count;
    char *image_info = malloc(size);
    p = image_info;
    read_from_task(p, info_array, size);

    for(uint32_t i = 0; i < info_array_count; i++) {
        mach_vm_address_t
            load_address = read_ptr(&p),
            file_path_addr = read_ptr(&p);
        read_ptr(&p); // file_mod_date
        if(_setjmp(recovery_buf))
            continue;
        char path[MAXPATHLEN + 1];
        read_from_task(path, file_path_addr, sizeof(path));
        if(strnlen(path, sizeof(path)) == sizeof(path))
            fprintf(stderr, "** dyld image info had malformed data.\n");
        else 
            do_image(load_address, strdup(path));
    }

    return;
}

static void print_addr(mach_vm_address_t addr) {
    printf(is_64bit ? "%016llx" : "%08llx", (long long) addr);
}

static void print_prot(vm_prot_t prot) {
    printf("%c%c%c",
        (prot & VM_PROT_READ)    ? 'r' : '-',
        (prot & VM_PROT_WRITE)   ? 'w' : '-',
        (prot & VM_PROT_EXECUTE) ? 'x' : '-');
}


int main(int argc, char **argv) {
    bool verbose = false;
    bool got_pid = false;
    bool got_showaddr = false;
    mach_vm_address_t showaddr;
    bool introspect = true;
    for(int i = 1; i < argc; i++) {
        if(!strcmp(argv[i], "-v"))
            verbose = true;
        else if(!strcmp(argv[i], "-n"))
            introspect = false;
        else if(!got_pid) {
            pid = atoi(argv[i]);
            got_pid = true;
        } else if(!got_showaddr) {
            showaddr = strtoll(argv[i], NULL, 16);
            got_showaddr = true;  
        } else
            goto usage;
    }
    if(!got_pid) goto usage;

    ask_for_access();
        
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if(kr) {
        fprintf(stderr, "task_for_pid failed: kr=%d\n", (int) kr);
#if __IPHONE_OS_VERSION_MIN_REQUIRED
        fprintf(stderr, "you need to sign this binary with the right entitlements.\n");
#else
        fprintf(stderr, "you need to trust this binary:\n");
#endif
        return 1;
    }

    char path[MAXPATHLEN];
    size_t path_size;

    if((path_size = proc_pidpath(pid, path, sizeof(path))))
        path[path_size] = 0;
    else
        strcpy(path, "???");
    printf("%d: %s\n", pid, path);

    assert(!task_info(task, TASK_DYLD_INFO, (task_info_t) &dyld_info, (mach_msg_type_number_t[]) {TASK_DYLD_INFO_COUNT}));
    is_64bit = dyld_info.all_image_info_addr >= (1ull << 32);
    if(!got_showaddr) {
        printf("DYLD all image info: "); print_addr(dyld_info.all_image_info_addr); printf("+%llx format=%d\n", (long long) dyld_info.all_image_info_size, (int) dyld_info.all_image_info_format);
    }
    
    if(introspect) {
        lookup_dyld_images();
    }
        

    mach_vm_address_t addr = got_showaddr ? showaddr : 0;
    while(1) {
        mach_vm_size_t size;
        struct vm_region_basic_info_64 basic_info;
        struct vm_region_extended_info extended_info;
        mach_port_t object_name;
        kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &basic_info, (mach_msg_type_number_t[]) {VM_REGION_BASIC_INFO_COUNT_64}, &object_name);
        if(kr == KERN_INVALID_ADDRESS || kr == KERN_NO_SPACE) break;
        assert(!kr);
        assert(!mach_vm_region(task, &addr, &size, VM_REGION_EXTENDED_INFO, (vm_region_info_t) &extended_info, (mach_msg_type_number_t[]) {VM_REGION_EXTENDED_INFO_COUNT}, &object_name));

        if(got_showaddr && addr > showaddr)
            break;

        print_addr(addr);
        printf("-");
        print_addr(addr+size);
        
        mach_vm_size_t hsize = size;
        if(hsize >= 1024*1024) {
            char c = 'M';
            if(hsize >= 1024*1024*1024) {
                hsize /= 1024;
                c = 'G';
            }
            hsize = (hsize * 10) / (1024*1024);
            printf(" [%4d.%d%c] ", (int) (hsize / 10), (int) (hsize % 10), c);
        } else {
            printf(" [%6dK] ", (int) (hsize / 1024));
        }
        print_prot(basic_info.protection);
        printf("/");
        print_prot(basic_info.max_protection);
        if(basic_info.behavior != VM_BEHAVIOR_DEFAULT) {
            printf(" B=");
            static const char *behaviors[] = {
#define X(x) [VM_BEHAVIOR_##x] = #x
                X(DEFAULT), X(RANDOM), X(SEQUENTIAL),
                X(RSEQNTL), X(WILLNEED), X(DONTNEED),
                X(FREE), X(ZERO_WIRED_PAGES),
                X(REUSABLE), X(REUSE), X(CAN_REUSE)
#undef X
            };
            if(basic_info.behavior <= VM_BEHAVIOR_CAN_REUSE)
                printf("%s", behaviors[basic_info.behavior]);
            else
                printf("%d", (int) basic_info.behavior);
        }

        printf(" SM=");
        static const char *share_modes[] = {
#define X(x) [SM_##x] = #x
            "0", X(COW), X(PRIVATE), X(EMPTY),
            X(SHARED), X(TRUESHARED), X(PRIVATE_ALIASED),
            X(SHARED_ALIASED), X(LARGE_PAGE)
#undef X
        };
        if(extended_info.share_mode <= SM_LARGE_PAGE)
            printf("%s", share_modes[extended_info.share_mode]);
        else
            printf("%d", (int) extended_info.share_mode);

        if(verbose)
            printf(" shadow_depth=%u", extended_info.shadow_depth);

        if(extended_info.user_tag) {
            static const char *tags[] = {
#define X(x) [VM_MEMORY_##x] = #x
                "0", X(MALLOC), X(MALLOC_SMALL), X(MALLOC_LARGE), X(MALLOC_HUGE),
                X(SBRK), X(REALLOC), X(MALLOC_TINY), X(MALLOC_LARGE_REUSABLE),
                X(MALLOC_LARGE_REUSED), X(ANALYSIS_TOOL), X(MACH_MSG),
                X(IOKIT), X(STACK), X(GUARD), X(SHARED_PMAP), X(DYLIB),
                X(OBJC_DISPATCHERS), X(APPKIT), X(FOUNDATION), X(COREGRAPHICS_MISC),
                X(CARBON), X(JAVA), X(ATS), X(LAYERKIT), X(CGIMAGE), X(TCMALLOC),
                X(COREGRAPHICS_DATA), X(COREGRAPHICS_SHARED),
                X(COREGRAPHICS_FRAMEBUFFERS), X(COREGRAPHICS_BACKINGSTORES),
                X(DYLD), X(DYLD_MALLOC), X(SQLITE), X(JAVASCRIPT_CORE),
                X(JAVASCRIPT_JIT_EXECUTABLE_ALLOCATOR),
                X(JAVASCRIPT_JIT_REGISTER_FILE), X(GLSL), X(OPENCL),
                X(COREIMAGE), X(WEBCORE_PURGEABLE_BUFFERS), X(IMAGEIO),
                X(COREPROFILE), X(ASSETSD)
#undef X
            };

            if(extended_info.user_tag <= VM_MEMORY_ASSETSD && tags[extended_info.user_tag]) {
                printf(" <%s>", tags[extended_info.user_tag]);
            } else {
                printf(" <tag %d>", (int) extended_info.user_tag);
            }
        }
        
        printf("\n");
        if(verbose)
            printf("    wired=%hu resident=%u shared_now_private=%u swapped_out=%u dirtied=%u ref_count=%u\n",
                basic_info.user_wired_count,
                extended_info.pages_resident,
                extended_info.pages_shared_now_private,
                extended_info.pages_swapped_out,
                extended_info.pages_dirtied,
                extended_info.ref_count);

        for(int i = 0; i < num_regions; i++) {
            if((regions[i].addr <= addr && addr < regions[i].addr + regions[i].size) ||
               (addr <= regions[i].addr && regions[i].addr < addr + size))
                printf("    %llx-%llx: %s\n", (long long) regions[i].addr, (long long) (regions[i].addr + regions[i].size), regions[i].label);
        }
        
        if((path_size = proc_regionfilename(pid, addr, path, sizeof(path)))) {
            path[path_size] = 0;
            printf("    (offset %llx) %s\n", (long long) basic_info.offset, path);
        }
        
        addr += size;
        if(got_showaddr)
            break;
    }
    return 0;

usage:
    fprintf(stderr, "usage: myvmmap pid\n");
    return 1;
}
