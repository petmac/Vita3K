#pragma once

#include <functional>
#include <memory>
#include <vector>

typedef uint32_t Address;
typedef std::unique_ptr<uint8_t[], std::function<void(uint8_t *)>> Memory;
typedef std::vector<size_t> Allocated;

struct MemState
{
    size_t page_size = 0;
    size_t generation = 0;
    Memory memory;
    Allocated allocated_pages;
};

constexpr size_t KB(size_t kb)
{
    return kb * 1024;
}

constexpr size_t MB(size_t mb)
{
    return mb * KB(1024);
}

constexpr size_t GB(size_t gb)
{
    return gb * MB(1024);
}

bool init(MemState *state);
Address alloc(MemState *state, size_t size);
void reserve(MemState *state, Address address, size_t size);
