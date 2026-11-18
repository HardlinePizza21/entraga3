#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MMG_PROT_WRITE 0x2
#define MMG_MAP_SHARED 0x01
#define MMG_MAP_SHARED_VALIDATE 0x03
#define MMG_MAP_TYPE 0x0f
#define MMG_S_IFMT 00170000
#define MMG_S_IFREG 0100000
#define MMG_EACCES 13

SEC("lsm/mmap_file")
int BPF_PROG(mmap_guard_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret)
{
    unsigned int mode;
    unsigned long map_type;

    (void)reqprot;
    if (ret)
        return ret;
    if (!file || !(prot & MMG_PROT_WRITE))
        return 0;

    mode = BPF_CORE_READ(file, f_inode, i_mode);
    if ((mode & MMG_S_IFMT) != MMG_S_IFREG)
        return 0;

    map_type = flags & MMG_MAP_TYPE;
    if (map_type == MMG_MAP_SHARED ||
        map_type == MMG_MAP_SHARED_VALIDATE)
        return -MMG_EACCES;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
