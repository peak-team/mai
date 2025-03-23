# MAI (Memory Allocation Interception)

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
