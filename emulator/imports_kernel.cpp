#include "import.h"

#include <iostream>
#include <map>

enum ResultCode : int32_t
{
    SCE_OK,
    UNKNOWN_UID
};

typedef uint32_t SceUID;
typedef std::map<SceUID, Address> Blocks;

static Blocks blocks;
static SceUID next_uid;

IMP_SIG(sceKernelAllocMemBlock)
{
    const char *const name = mem_ptr<const char>(r0, mem);
    const uint32_t type = r1;
    const uint32_t size = r2;
    const uint32_t unknown = r3;
    assert(name != nullptr);
    assert(type != 0);
    assert(size != 0);
    assert(unknown == 0);
    
    std::cout << "name = " << name << std::endl;
    std::cout << "type = " << type << std::endl;
    std::cout << "size = " << size << std::endl;
    std::cout << "unknown = " << unknown << std::endl;
    
    const Address address = alloc(mem, size, name);
    if (address == 0)
    {
        return -1; // TODO What should this be?
    }
    
    const SceUID uid = next_uid++;
    blocks.insert(Blocks::value_type(uid, address));
    
    return uid;
}

IMP_SIG(sceKernelCreateLwMutex)
{
    return 0;
}

IMP_SIG(sceKernelGetMemBlockBase)
{
    const SceUID uid = r0;
    Address *const address = mem_ptr<Address>(r1, mem);
    assert(uid >= 0);
    assert(address != nullptr);
    
    const Blocks::const_iterator block = blocks.find(uid);
    if (block == blocks.end())
    {
        // TODO Write address?
        return UNKNOWN_UID;
    }
    
    *address = block->second;
    
    return SCE_OK;
}
