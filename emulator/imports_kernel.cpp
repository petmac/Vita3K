#include "import.h"

#include "events.h"

#include <SDL2/SDL_timer.h>
#include <unicorn/unicorn.h>

#include <iostream>
#include <time.h>

static const size_t MAX_NAME_LEN = 32;

struct LWMutexWorkArea
{
    char name[MAX_NAME_LEN];
};

enum LWMutexAttr : uint32_t
{
    LW_MUTEX_ATTR_A = 0,
    LW_MUTEX_ATTR_B = 2,
};

IMP_SIG(sceKernelAllocMemBlock)
{
    MemState *const mem = &emu->mem;
    const char *const name = Ptr<const char>(r0).get(mem);
    const uint32_t type = r1;
    const uint32_t size = r2;
    const uint32_t unknown = r3;
    assert(name != nullptr);
    assert(type != 0);
    assert(size != 0);
    assert(unknown == 0);
    
    const Ptr<void> address(alloc(mem, size, name));
    if (!address)
    {
        return -1; // TODO What should this be?
    }
    
    KernelState *const state = &emu->kernel;
    const SceUID uid = state->next_uid++;
    state->blocks.insert(Blocks::value_type(uid, address));
    
    return uid;
}

IMP_SIG(sceKernelCreateLwMutex)
{
    const MemState *const mem = &emu->mem;
    LWMutexWorkArea *const workarea = Ptr<LWMutexWorkArea>(r0).get(mem);
    const char *const name = Ptr<const char>(r1).get(mem);
    const LWMutexAttr attr = static_cast<LWMutexAttr>(r2);
    const int32_t count = r3;
    const Ptr<Ptr<const void>> stack = sp.cast<Ptr<const void>>();
    const void *const options = stack.get(mem)->get(mem);
    assert(workarea != nullptr);
    assert((attr == LW_MUTEX_ATTR_A) || (attr == LW_MUTEX_ATTR_B));
    assert(count == 0);
    assert(options == nullptr);
    
    strncpy(workarea->name, name, MAX_NAME_LEN);
    workarea->name[MAX_NAME_LEN - 1] = '\0';
    
    // TODO Investigate further and implement.
    return 0;
}

IMP_SIG(sceKernelCreateMutex)
{
    // TODO Create.
    return 0;
}

IMP_SIG(sceKernelDelayThread)
{
    const uint32_t delay = r0;
    
    const uint32_t delay_ms = delay / 1000;
    const uint32_t t1 = SDL_GetTicks();
    uint32_t elapsed;
    do
    {
        if (handle_events(thread->uc))
        {
            const uint32_t t2 = SDL_GetTicks();
            elapsed = t2 - t1;
        }
        else
        {
            elapsed = delay_ms;
        }
    }
    while (elapsed < delay_ms);
    
    return SCE_OK;
}

IMP_SIG(sceKernelExitProcess)
{
    // TODO Handle exit code?
    // TODO Stop all threads, not just this one.
    uc_emu_stop(thread->uc);
    
    return SCE_OK;
}

IMP_SIG(sceKernelFreeMemBlock)
{
    // https://psp2sdk.github.io/sysmem_8h.html
    const SceUID uid = r0;
    assert(uid != SCE_UID_INVALID_UID);
    
    KernelState *const state = &emu->kernel;
    const Blocks::const_iterator block = state->blocks.find(uid);
    assert(block != state->blocks.end());
    
    // TODO Free block.
    state->blocks.erase(block);
    
    return SCE_OK;
}

IMP_SIG(sceKernelGetMemBlockBase)
{
    const SceUID uid = r0;
    const MemState *const mem = &emu->mem;
    Ptr<void> *const address = Ptr<Ptr<void>>(r1).get(mem);
    assert(uid >= 0);
    assert(address != nullptr);
    
    const KernelState *const state = &emu->kernel;
    const Blocks::const_iterator block = state->blocks.find(uid);
    if (block == state->blocks.end())
    {
        // TODO Write address?
        return UNKNOWN_UID;
    }
    
    *address = block->second;
    
    return SCE_OK;
}

IMP_SIG(sceKernelGetProcessTimeWide)
{
    static_assert(CLOCKS_PER_SEC == 1000000, "CLOCKS_PER_SEC doesn't match Vita.");
    
    const clock_t clocks = clock();
    
    r0 = static_cast<uint32_t>(clocks);
    r1 = static_cast<uint32_t>(clocks >> 32);
    
    return ImportResult(r0, r1);
}

IMP_SIG(sceKernelGetTLSAddr)
{
    const SceUID slot = r0;
    const SceUID thread_id = 0; // TODO Use the real thread ID.
    KernelState *const state = &emu->kernel;
    SlotToAddress *const slot_to_address = &state->tls[thread_id];
    
    const SlotToAddress::const_iterator existing = slot_to_address->find(slot);
    if (existing != slot_to_address->end())
    {
        return existing->second.address();
    }
    
    // TODO Use a finer-grained allocator.
    // TODO This is a memory leak.
    MemState *const mem = &emu->mem;
    const Ptr<Ptr<void>> address(alloc(mem, sizeof(Ptr<void>), "TLS"));
    slot_to_address->insert(SlotToAddress::value_type(slot, address));
    
    return address.address();
}

IMP_SIG(sceKernelGetThreadId)
{
    // TODO What should this be?
    return 0;
}

IMP_SIG(sceKernelLockLwMutex)
{
    const MemState *const mem = &emu->mem;
    LWMutexWorkArea *const workarea = Ptr<LWMutexWorkArea>(r0).get(mem);
    const int32_t count = r1;
    uint32_t *const timeout = Ptr<uint32_t>(r2).get(mem);
    assert(workarea != nullptr);
    assert(count == 1);
    assert(timeout == nullptr);
    
    // TODO Investigate further and implement.
    return 0;
}

IMP_SIG(sceKernelUnlockLwMutex)
{
    const MemState *const mem = &emu->mem;
    LWMutexWorkArea *const workarea = Ptr<LWMutexWorkArea>(r0).get(mem);
    const int32_t count = r1;
    assert(workarea != nullptr);
    assert(count == 1);
    
    // TODO Investigate further and implement.
    return 0;
}
