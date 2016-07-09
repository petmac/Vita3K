#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

typedef uint32_t Address;
typedef size_t Generation;
typedef std::unique_ptr<uint8_t[], std::function<void(uint8_t *)>> Memory;
typedef std::vector<Generation> Allocated;
typedef std::map<Generation, std::string> GenerationNames;

struct MemState
{
    size_t page_size = 0;
    Generation generation = 0;
    Memory memory;
    Allocated allocated_pages;
    GenerationNames generation_names;
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
Address alloc(MemState *state, size_t size, const char *name);
const char *mem_name(Address address, const MemState *state);
