#pragma once

#include <cstdlib>
#include <memory>

struct FreeDeleter {
    void operator()(void *p) const noexcept { std::free(p); }
};

template <typename T>
using HeapPtr = std::unique_ptr<T, FreeDeleter>;
