#define _GNU_SOURCE
#include <dlfcn.h>

#include "malloc_interceptor.h"




void peak_init()
{
    //gum_init_embedded();
    malloc_interceptor_attach();
}

void peak_fini()
{
    malloc_interceptor_dettach();
}

#if defined(__APPLE__)
__attribute__((used, section("__DATA,__mod_init_func"))) void* __init = peak_init;
__attribute__((used, section("__DATA,__mod_fini_func"))) void* __fini = peak_fini;
#elif defined(__ELF__)
//__attribute__((section(".init_array"))) void* __init = peak_init;
//__attribute__((section(".fini_array"))) void* __fini = peak_fini;
typedef int (*main_fn)(int, char**, char**);
typedef int (*libc_start_main_fn)(main_fn, int, char**, 
                                  int (*)(int, char**, char**),
                                  void (*)(void), void (*)(void), void*);

static main_fn real_main = NULL;
static libc_start_main_fn real___libc_start_main = NULL;

// Original function pointer for `exit`
static void (*original_exit)(int) = NULL;
static GumInterceptor* exit_interceptor = NULL;
static gpointer* exit_address = NULL;
void exit_interceptor_detach();

static void
peak_exit(int status) {
    //g_printerr("Custom exit called with status: %d\n", status);

    peak_fini();
    atexit(exit_interceptor_detach);

    // Call the original `exit` function to terminate the process
    original_exit(status);
}

/**
 * @brief Attaches the interceptor to the `exit` function.
 *
 * This function uses the Gum API to intercept calls to the `exit` function, 
 * replacing it with a custom implementation (`peak_exit`).
 *
 * @return 0 on success, -1 on failure.
 */
int exit_interceptor_attach() {
    gum_init_embedded();
    GumReplaceReturn replace_check = -1;
    exit_interceptor = gum_interceptor_obtain();

    gum_interceptor_begin_transaction(exit_interceptor);
    // gum_find_function causes seg faults with running within apptainer. This needs further investigation
    //exit_address = gum_find_function("exit");
    exit_address = (void*)exit;
    if (exit_address) {
        replace_check = gum_interceptor_replace_fast(exit_interceptor,
                                      exit_address, (gpointer*)&peak_exit,
                                      (gpointer*)(&original_exit));
    }
    gum_interceptor_end_transaction(exit_interceptor);
    return replace_check;
}

/**
 * @brief Detaches the interceptor from the `exit` function.
 *
 * This function reverts the interception of the `exit` function, restoring its 
 * original behavior.
 */
void exit_interceptor_detach() {
    gum_interceptor_revert(exit_interceptor, exit_address);
    g_object_unref(exit_interceptor);
    gum_deinit_embedded();
}

static int main_wrapper(int argc, char** argv, char** envp) {
    // Call peak_init before main
    // fprintf(stderr, "[LD_PRELOAD] main started. Running my code now.\n");
    if (!exit_interceptor_attach())
        peak_init();

    int ret = real_main(argc, argv, envp);

    return ret;
}

__attribute__((visibility("default")))
int __libc_start_main(main_fn main, int argc, char** argv,
                      int (*init)(int, char**, char**),
                      void (*fini)(void), void (*rtld_fini)(void), void* stack_end) {
    // fprintf(stderr, "Running my code now.\n");
    if (!real___libc_start_main) {
        real___libc_start_main = (libc_start_main_fn)dlsym(RTLD_NEXT, "__libc_start_main");
        if (!real___libc_start_main) {
            fprintf(stderr, "Error: dlsym failed to find __libc_start_main\n");
            _exit(1);
        }
    }

    // Store the original main function pointer
    real_main = main;

    return real___libc_start_main(main_wrapper, argc, argv, init, fini, rtld_fini, stack_end);
}
#else
#error Unsupported platform
#endif