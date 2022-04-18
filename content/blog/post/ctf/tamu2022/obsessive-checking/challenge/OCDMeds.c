#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

/* Paste this on the file you want to debug. */
#include <execinfo.h>
void print_trace(void) {
    char **strings;
    size_t i, size;
    enum Constexpr { MAX_SIZE = 1024 };
    void *array[MAX_SIZE];
    size = backtrace(array, MAX_SIZE);
    strings = backtrace_symbols(array, size);
    for (i = 0; i < size; i++)
        printf("%s\n", strings[i]);
    puts("");
    free(strings);
}

void *memcpy(void *dst, const void *src, size_t n) {
    printf("dst %p src %p size: %ld\n", dst, src, n);
    if (n == 16 || n==24 || n==32 || n==80) {
        const char *buf = (const char*)src;
        for (int i=0; i<n ; i++) {
            printf("%02hhx", buf[i]);
        }
        puts("");
        for (int i=0; i<n; i++) {
            printf("%c", buf[i]);
        }
        puts("");
		print_trace();
    }

    void *handle = dlopen("/usr/lib/x86_64-linux-gnu/libc-2.31.so", RTLD_NOW);
    void *(*orig_func)() = dlsym(handle, "memcpy");
    return orig_func(dst, src, n);
}
