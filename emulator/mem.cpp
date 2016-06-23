#include "mem.h"

#include <assert.h>
#include <math.h>

#include <algorithm>

#include <sys/mman.h>
#include <unistd.h>

static void delete_memory(uint8_t *memory)
{
    if (memory != nullptr)
    {
        munmap(memory, GB(4));
    }
}

static void alloc_inner(MemState *state, Address address, size_t page_count, Allocated::iterator block, const char *name)
{
    uint8_t *const memory = &state->memory[address];
    const size_t aligned_size = page_count * state->page_size;
    
    const Generation generation = ++state->generation;
    std::fill_n(block, page_count, generation);
    state->generation_names[generation] = name;
    
    mprotect(memory, aligned_size, PROT_READ | PROT_WRITE);
    std::fill_n(memory, aligned_size, 0);
}

bool init(MemState *state)
{
    state->page_size = sysconf(_SC_PAGESIZE);
    assert(state->page_size >= 4096); // Limit imposed by Unicorn.
    
    // http://man7.org/linux/man-pages/man2/mmap.2.html
    void *const addr = nullptr;
    const size_t length = GB(4);
    const int prot = PROT_NONE;
    const int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    const int fd = 0;
    const off_t offset = 0;
    state->memory = Memory(static_cast<uint8_t *>(mmap(addr, length, prot, flags, fd, offset)), delete_memory);
    if (!state->memory)
    {
        return false;
    }
    
    state->allocated_pages.resize(length / state->page_size);
    const Address null_address = alloc(state, 1, "NULL");
    assert(null_address == 0);
    mprotect(mem_ptr<void>(null_address, state), state->page_size, PROT_NONE);
    
    return true;
}

Address alloc(MemState *state, size_t size, const char *name)
{
    const size_t page_count = (size + (state->page_size - 1)) / state->page_size;
    const Allocated::iterator block = std::search_n(state->allocated_pages.begin(), state->allocated_pages.end(), page_count, 0);
    if (block == state->allocated_pages.end())
    {
        assert(false);
        return 0;
    }
    
    const size_t block_page_index = block - state->allocated_pages.begin();
    const Address address = static_cast<Address>(block_page_index * state->page_size);
    
    alloc_inner(state, address, page_count, block, name);
    
    return static_cast<Address>(address);
}

void reserve(MemState *state, Address address, size_t size, const char *name)
{
    assert((address % state->page_size) == 0);
    
    const size_t page_count = (size + (state->page_size - 1)) / state->page_size;
    const size_t block_page_index = address / state->page_size;
    const Allocated::iterator block = state->allocated_pages.begin() + block_page_index;
    
    alloc_inner(state, address, page_count, block, name);
}

const char *mem_name(Address address, const MemState *state)
{
    const size_t page = address / state->page_size;
    assert(page >= 0);
    assert(page < state->allocated_pages.size());
    
    const Generation generation = state->allocated_pages[page];
    if (generation == 0)
    {
        return "UNALLOCATED";
    }
    
    const GenerationNames::const_iterator found = state->generation_names.find(generation);
    assert(found != state->generation_names.end());
    if (found == state->generation_names.end())
    {
        return "UNNAMED";
    }
    
    return found->second.c_str();
}
