#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define THREAD_COUNT 4
#define ATTEMPTS_PER_THREAD 100
#define MADVISE_ITERATIONS 1000

struct map_worker {
    int fd;
    unsigned int failures;
};

struct madvise_worker {
    int *word;
    atomic_bool stop;
};

static int verify_shared_write_is_denied(int fd)
{
    void *mapping;

    errno = 0;
    mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mapping != MAP_FAILED) {
        munmap(mapping, 4096);
        fprintf(stderr, "FALLO: MAP_SHARED escribible fue permitido\n");
        return -1;
    }
    if (errno != EACCES) {
        fprintf(stderr, "FALLO: se esperaba EACCES, se obtuvo: %s\n",
                strerror(errno));
        return -1;
    }

    puts("OK: MAP_SHARED escribible fue rechazado");
    return 0;
}

static void *try_shared_mappings(void *argument)
{
    struct map_worker *worker = argument;
    unsigned int i;

    for (i = 0; i < ATTEMPTS_PER_THREAD; i++) {
        void *mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_SHARED, worker->fd, 0);
        if (mapping != MAP_FAILED) {
            munmap(mapping, 4096);
            worker->failures++;
        } else if (errno != EACCES) {
            worker->failures++;
        }
    }

    return NULL;
}

static int verify_concurrent_attempts_are_denied(int fd)
{
    pthread_t threads[THREAD_COUNT];
    struct map_worker workers[THREAD_COUNT];
    unsigned int started = 0;
    unsigned int i;
    unsigned int failures = 0;

    for (i = 0; i < THREAD_COUNT; i++) {
        workers[i].fd = fd;
        workers[i].failures = 0;
        if (pthread_create(&threads[i], NULL, try_shared_mappings,
                           &workers[i]) != 0) {
            fprintf(stderr, "FALLO: no se pudo iniciar un hilo de prueba\n");
            break;
        }
        started++;
    }

    for (i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "FALLO: no se pudo esperar un hilo de prueba\n");
            failures++;
        } else {
            failures += workers[i].failures;
        }
    }
    if (started != THREAD_COUNT || failures != 0) {
        fprintf(stderr, "FALLO: %u intentos concurrentes no fueron bloqueados\n",
                failures);
        return -1;
    }

    puts("OK: 400 intentos concurrentes de mapeo fueron rechazados");
    return 0;
}

static int verify_private_write_is_not_persistent(int fd, int read_only_fd)
{
    char original;
    char persisted;
    void *mapping;

    if (pwrite(fd, "A", 1, 0) != 1) {
        perror("pwrite");
        return -1;
    }
    mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                   read_only_fd, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap MAP_PRIVATE");
        return -1;
    }

    ((char *)mapping)[0] = 'B';
    original = ((char *)mapping)[0];
    if (pread(read_only_fd, &persisted, 1, 0) != 1) {
        perror("pread");
        munmap(mapping, 4096);
        return -1;
    }
    munmap(mapping, 4096);

    if (original != 'B' || persisted != 'A') {
        fprintf(stderr, "FALLO: MAP_PRIVATE alteró los datos respaldados\n");
        return -1;
    }

    puts("OK: MAP_PRIVATE permite escritura privada sin alterar el archivo");
    return 0;
}

static void *write_private_page(void *argument)
{
    struct madvise_worker *worker = argument;

    while (!atomic_load_explicit(&worker->stop, memory_order_acquire))
        __atomic_store_n(worker->word, 1, __ATOMIC_RELAXED);

    return NULL;
}

static int verify_madvise_race_is_bounded(int read_only_fd)
{
    struct madvise_worker worker;
    pthread_t thread;
    char persisted;
    void *mapping;
    unsigned int i;
    int result = 0;

    mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE,
                   read_only_fd, 0);
    if (mapping == MAP_FAILED) {
        perror("mmap para prueba MADV_DONTNEED");
        return -1;
    }

    worker.word = mapping;
    atomic_init(&worker.stop, false);
    if (pthread_create(&thread, NULL, write_private_page, &worker) != 0) {
        fprintf(stderr, "FALLO: no se pudo iniciar el hilo de escritura\n");
        munmap(mapping, 4096);
        return -1;
    }

    for (i = 0; i < MADVISE_ITERATIONS; i++) {
        if (madvise(mapping, 4096, MADV_DONTNEED) != 0) {
            perror("madvise MADV_DONTNEED");
            result = -1;
            break;
        }
    }
    atomic_store_explicit(&worker.stop, true, memory_order_release);
    if (pthread_join(thread, NULL) != 0) {
        fprintf(stderr, "FALLO: no se pudo esperar el hilo de escritura\n");
        return -1;
    }
    if (pread(read_only_fd, &persisted, 1, 0) != 1 || persisted != 'A') {
        fprintf(stderr, "FALLO: la prueba cambió los datos del archivo\n");
        result = -1;
    }
    if (munmap(mapping, 4096) != 0) {
        perror("munmap");
        result = -1;
    }
    if (result == 0)
        puts("OK: escrituras privadas concurrentes con MADV_DONTNEED no persistieron");
    return result;
}

int main(int argc, char **argv)
{
    char path[] = "/tmp/mmap-guard-test-XXXXXX";
    int fd = mkstemp(path);
    int read_only_fd;
    int cow_only = argc == 2 && strcmp(argv[1], "--cow-only") == 0;
    int race_only = argc == 2 && strcmp(argv[1], "--race-only") == 0;
    int result = EXIT_FAILURE;

    if (argc > 1 && !cow_only && !race_only) {
        fprintf(stderr, "Uso: %s [--cow-only | --race-only]\n", argv[0]);
        return EXIT_FAILURE;
    }
    if (fd < 0) {
        perror("mkstemp");
        return EXIT_FAILURE;
    }
    read_only_fd = open(path, O_RDONLY);
    if (read_only_fd < 0) {
        perror("open read-only");
        close(fd);
        unlink(path);
        return EXIT_FAILURE;
    }
    if (unlink(path) != 0) {
        perror("unlink");
        close(read_only_fd);
        close(fd);
        return EXIT_FAILURE;
    }
    if (ftruncate(fd, 4096) != 0) {
        perror("ftruncate");
        close(read_only_fd);
        close(fd);
        return EXIT_FAILURE;
    }

    if (verify_private_write_is_not_persistent(fd, read_only_fd) == 0) {
        if (cow_only) {
            result = EXIT_SUCCESS;
        } else if (race_only) {
            if (verify_madvise_race_is_bounded(read_only_fd) == 0)
                result = EXIT_SUCCESS;
        } else if (verify_shared_write_is_denied(fd) == 0 &&
                   verify_concurrent_attempts_are_denied(fd) == 0 &&
                   verify_madvise_race_is_bounded(read_only_fd) == 0) {
            result = EXIT_SUCCESS;
        }
    }

    if (close(read_only_fd) != 0) {
        perror("close read-only");
        result = EXIT_FAILURE;
    }
    if (close(fd) != 0) {
        perror("close");
        result = EXIT_FAILURE;
    }
    return result;
}
