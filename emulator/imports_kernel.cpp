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
typedef std::map<SceUID, Address> SlotToAddress;
typedef std::map<SceUID, SlotToAddress> ThreadToSlotToAddress;

static Blocks blocks;
static SceUID next_uid;
static ThreadToSlotToAddress tls;

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
    // TODO Create.
    return 0;
}

IMP_SIG(sceKernelCreateMutex)
{
    // TODO Create.
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

IMP_SIG(sceKernelGetTLSAddr)
{
    const SceUID slot = r0;
    const SceUID thread = 0; // TODO Use the real thread ID.
    SlotToAddress *const slot_to_address = &tls[thread];
    
    const SlotToAddress::const_iterator existing = slot_to_address->find(slot);
    if (existing != slot_to_address->end())
    {
        return existing->second;
    }
    
    // TODO Use a finer-grained allocator.
    // TODO This is a memory leak.
    const Address address = alloc(mem, sizeof(Address), "TLS");
    slot_to_address->insert(SlotToAddress::value_type(slot, address));
    
    return address;
}

IMP_SIG(sceKernelGetThreadId)
{
    // TODO What should this be?
    return 0;
}
