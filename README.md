# MAI (Memory Allocation Interception)
MAI is a library that transparently intercepts memory allocation functions in any applications to provide fallback mechanisms when standard allocations fail. When a program runs out of heap memory, MAI automatically falls back to using memory-mapped files, ensuring the application continues running even under memory pressure.

## Key Features
- Intercepts standard memory functions (malloc, free, calloc, realloc, aligned_alloc, posix_memalign)
- Provides seamless mmap-based fallback when heap allocations fail
- Maintains memory usage statistics
- Configurable mmap directory via environment variables
- Thread-safe implementation

MAI is perfect for applications that need to handle large memory allocations or operate in memory-constrained environments without crashing.

## To Compile:

```
mkdir build
cd build
cmake --install-prefix=$HOME ..
make
``` 

## To Use: 

``LD_PRELOAD=libmai.so ./target_application_here`` 

## Settings
```
 MAI_MMAP_PATH=./                 # Directory to store the mmap file. The default is `./`, the current directory.
```
