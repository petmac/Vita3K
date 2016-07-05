#include "import.h"

enum GxmMemoryAttrib
{
    // https://github.com/xerpi/vitahelloworld/blob/master/draw.c
    SCE_GXM_MEMORY_ATTRIB_RW = 3
};

struct SceGxmInitializeParams
{
    // This is guesswork based on Napier tutorial 3 PDF.
    uint32_t flags = 0;
    uint32_t displayQueueMaxPendingCount = 0;
    Address displayQueueCallback;
    Address displayQueueCallbackDataSize = 0;
    uint32_t parameterBufferSize = 0;
};

IMP_SIG(sceGxmInitialize)
{
    const SceGxmInitializeParams *const params = mem_ptr<const SceGxmInitializeParams>(r0, &emu->mem);
    (void)params;
    
    // TODO Implement.
    return SCE_OK;
}

IMP_SIG(sceGxmMapMemory)
{
    const void *const address = mem_ptr<const void>(r0, &emu->mem);
    const size_t size = r1;
    const GxmMemoryAttrib attributes = static_cast<GxmMemoryAttrib>(r2);
    assert(address != nullptr);
    assert(size > 0);
    assert(attributes == SCE_GXM_MEMORY_ATTRIB_RW);
    
    return SCE_OK;
}

IMP_SIG(sceGxmTerminate)
{
    return SCE_OK;
}

IMP_SIG(sceGxmUnmapMemory)
{
    const void *const address = mem_ptr<const void>(r0, &emu->mem);
    assert(address != nullptr);
    
    return SCE_OK;
}
