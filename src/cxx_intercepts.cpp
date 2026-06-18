#include <cstddef>
#include <new>

extern "C" void* mai_operator_new_allocate(std::size_t size);
extern "C" void* mai_operator_new_aligned_allocate(std::size_t size, std::size_t alignment);
extern "C" void mai_operator_delete_free(void* ptr);

static void* mai_cxx_new(std::size_t size) {
    void* ptr = mai_operator_new_allocate(size);
    if (!ptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

static void* mai_cxx_new_aligned(std::size_t size, std::align_val_t alignment) {
    void* ptr = mai_operator_new_aligned_allocate(size, static_cast<std::size_t>(alignment));
    if (!ptr) {
        throw std::bad_alloc();
    }
    return ptr;
}

__attribute__((visibility("default")))
void* operator new(std::size_t size) {
    return mai_cxx_new(size);
}

__attribute__((visibility("default")))
void* operator new[](std::size_t size) {
    return mai_cxx_new(size);
}

__attribute__((visibility("default")))
void operator delete(void* ptr) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete[](void* ptr) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete(void* ptr, std::size_t) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete[](void* ptr, std::size_t) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return mai_cxx_new(size);
    } catch (...) {
        return nullptr;
    }
}

__attribute__((visibility("default")))
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try {
        return mai_cxx_new(size);
    } catch (...) {
        return nullptr;
    }
}

__attribute__((visibility("default")))
void operator delete(void* ptr, const std::nothrow_t&) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete[](void* ptr, const std::nothrow_t&) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void* operator new(std::size_t size, std::align_val_t alignment) {
    return mai_cxx_new_aligned(size, alignment);
}

__attribute__((visibility("default")))
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return mai_cxx_new_aligned(size, alignment);
}

__attribute__((visibility("default")))
void operator delete(void* ptr, std::align_val_t) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete[](void* ptr, std::align_val_t) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete(void* ptr, std::size_t, std::align_val_t) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete[](void* ptr, std::size_t, std::align_val_t) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void* operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try {
        return mai_cxx_new_aligned(size, alignment);
    } catch (...) {
        return nullptr;
    }
}

__attribute__((visibility("default")))
void* operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try {
        return mai_cxx_new_aligned(size, alignment);
    } catch (...) {
        return nullptr;
    }
}

__attribute__((visibility("default")))
void operator delete(void* ptr, std::align_val_t, const std::nothrow_t&) noexcept {
    mai_operator_delete_free(ptr);
}

__attribute__((visibility("default")))
void operator delete[](void* ptr, std::align_val_t, const std::nothrow_t&) noexcept {
    mai_operator_delete_free(ptr);
}
