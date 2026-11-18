#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h> 

#include "mmap_guard.skel.h"

static volatile sig_atomic_t running = 1;

static void stop_loader(int signal_number)
{
    (void)signal_number;
    running = 0;
}

static int parse_seconds(int argc, char **argv, unsigned int *seconds)
{
    char *end = NULL;
    unsigned long value;

    if (argc == 1) {
        *seconds = 0;
        return 0;
    }

    if (argc != 3 || strcmp(argv[1], "--seconds") != 0) {
        fprintf(stderr, "Uso: %s [--seconds N]\n", argv[0]);
        return -1;
    }

    errno = 0;
    value = strtoul(argv[2], &end, 10);
    if (errno || !end || *end != '\0' || value == 0 || value > 86400) {
        fprintf(stderr, "N debe estar entre 1 y 86400 segundos\n");
        return -1;
    }

    *seconds = (unsigned int)value;
    return 0;
}

int main(int argc, char **argv)
{
    struct mmap_guard_bpf *skeleton;
    struct bpf_link *link;
    struct sigaction action = {0};
    unsigned int seconds;
    unsigned int elapsed = 0;
    int error;

    if (parse_seconds(argc, argv, &seconds) != 0)
        return EXIT_FAILURE;

    skeleton = mmap_guard_bpf__open_and_load();
    if (!skeleton) {
        fprintf(stderr, "No se pudo cargar el programa eBPF LSM\n");
        return EXIT_FAILURE;
    }

    link = bpf_program__attach_lsm(skeleton->progs.mmap_guard_mmap_file);
    error = libbpf_get_error(link);
    if (error) {
        fprintf(stderr, "No se pudo adjuntar el hook LSM: %d\n", error);
        mmap_guard_bpf__destroy(skeleton);
        return EXIT_FAILURE;
    }

    action.sa_handler = stop_loader;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) != 0 ||
        sigaction(SIGTERM, &action, NULL) != 0) {
        perror("sigaction");
        bpf_link__destroy(link);
        mmap_guard_bpf__destroy(skeleton);
        return EXIT_FAILURE;
    }

    printf("Política activa. Ctrl-C para detener.\n");
    fflush(stdout);
    while (running && (!seconds || elapsed < seconds)) {
        struct timespec delay = {.tv_sec = 1, .tv_nsec = 0};
        while (running) {
            if (nanosleep(&delay, &delay) == 0)
                break;
            if (errno != EINTR) {
                perror("nanosleep");
                bpf_link__destroy(link);
                mmap_guard_bpf__destroy(skeleton);
                return EXIT_FAILURE;
            }
        }
        elapsed++;
    }

    bpf_link__destroy(link);
    mmap_guard_bpf__destroy(skeleton);
    return EXIT_SUCCESS;
}
