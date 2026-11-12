/* Test-only sendmmsg interposer. Build outside the daemon and preload only into
 * a functional QUIC test process, never a throughput measurement. Every fifth
 * call sends one packet; every seventh injects EAGAIN before sending any.
 * Leave libssl/libcrypto calls alone: testbed clients/origins use OpenSSL.
 * This exercises retained batch suffixes without relying on socket saturation.
 * Build: cc -shared -fPIC -o batch-send-faults.so batch-send-faults.c -ldl -pthread
 */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_once_t initialized = PTHREAD_ONCE_INIT;
static int (*real_sendmmsg)(int, struct mmsghdr*, unsigned int, int);
static atomic_ulong calls, blocked, shortened;

static void resolve_sendmmsg(void) {
    real_sendmmsg = dlsym(RTLD_NEXT, "sendmmsg");
    if (!real_sendmmsg) abort();
}

int sendmmsg(int fd, struct mmsghdr* messages, unsigned int count, int flags) {
    pthread_once(&initialized, resolve_sendmmsg);
    Dl_info caller;
    if (dladdr(__builtin_return_address(0), &caller) && caller.dli_fname
        && (strstr(caller.dli_fname, "libssl.") || strstr(caller.dli_fname, "libcrypto.")))
        return real_sendmmsg(fd, messages, count, flags);
    unsigned long call = atomic_fetch_add(&calls, 1) + 1;
    if (call % 7 == 0) {
        atomic_fetch_add(&blocked, 1);
        errno = EAGAIN;
        return -1;
    }
    if (call % 5 == 0 && count > 1) {
        atomic_fetch_add(&shortened, 1);
        count = 1;
    }
    return real_sendmmsg(fd, messages, count, flags);
}

__attribute__((destructor)) static void report_faults(void) {
    fprintf(stderr, "batch-send-faults calls=%lu blocked=%lu shortened=%lu\n",
            atomic_load(&calls), atomic_load(&blocked), atomic_load(&shortened));
}
