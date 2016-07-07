#include "import.h"

struct GxmContext
{
};

enum GxmMemoryAttrib
{
    // https://github.com/xerpi/vitahelloworld/blob/master/draw.c
    SCE_GXM_MEMORY_ATTRIB_READ = 1,
    SCE_GXM_MEMORY_ATTRIB_RW = 3
};

struct SceGxmContextParams
{
    // https://psp2sdk.github.io/structSceGxmContextParams.html
    Ptr<void> hostMem;
    uint32_t hostMemSize;
    Ptr<void> vdmRingBufferMem;
    uint32_t vdmRingBufferMemSize;
    Ptr<void> vertexRingBufferMem;
    uint32_t vertexRingBufferMemSize;
    Ptr<void> fragmentRingBufferMem;
    uint32_t fragmentRingBufferMemSize;
    Ptr<void> fragmentUsseRingBufferMem;
    uint32_t fragmentUsseRingBufferMemSize;
    uint32_t fragmentUsseRingBufferOffset;
};

// https://psp2sdk.github.io/gxm_8h.html
typedef void SceGxmDisplayQueueCallback(Ptr<const void> callbackData);

struct SceGxmInitializeParams
{
    // This is guesswork based on Napier tutorial 3 PDF.
    uint32_t flags = 0;
    uint32_t displayQueueMaxPendingCount = 0;
    Ptr<SceGxmDisplayQueueCallback> displayQueueCallback;
    uint32_t displayQueueCallbackDataSize = 0;
    uint32_t parameterBufferSize = 0;
};

struct SceGxmRenderTarget
{
};

struct SceGxmRenderTargetParams
{
    // Napier tutorial 3.
    // https://psp2sdk.github.io/structSceGxmRenderTargetParams.html
    uint32_t flags = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t scenesPerFrame = 1;
    uint16_t multisampleMode = 0;
    uint32_t multisampleLocations = 0;
    SceUID driverMemBlock = SCE_UID_INVALID_UID;
};

IMP_SIG(sceGxmCreateContext)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmContextParams *const params = Ptr<const SceGxmContextParams>(r0).get(&emu->mem);
    Ptr<GxmContext> *const context = Ptr<Ptr<GxmContext>>(r1).get(&emu->mem);
    assert(params != nullptr);
    assert(context != nullptr);
    
    *context = Ptr<GxmContext>(alloc(&emu->mem, sizeof(GxmContext), __FUNCTION__));
    if (!*context)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmCreateRenderTarget)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmRenderTargetParams *const params = Ptr<const SceGxmRenderTargetParams>(r0).get(&emu->mem);
    Ptr<SceGxmRenderTarget> *const renderTarget = Ptr<Ptr<SceGxmRenderTarget>>(r1).get(&emu->mem);
    assert(params != nullptr);
    assert(renderTarget != nullptr);
    
    *renderTarget = Ptr<SceGxmRenderTarget>(alloc(&emu->mem, sizeof(SceGxmRenderTarget), __FUNCTION__));
    if (!*renderTarget)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmInitialize)
{
    const SceGxmInitializeParams *const params = Ptr<const SceGxmInitializeParams>(r0).get(&emu->mem);
    (void)params;
    
    // TODO Implement.
    return SCE_OK;
}

IMP_SIG(sceGxmMapFragmentUsseMemory)
{
    void *const base = Ptr<void>(r0).get(&emu->mem);
    const uint32_t size = r1;
    uint32_t *const offset = Ptr<uint32_t>(r2).get(&emu->mem);
    assert(base != nullptr);
    assert(size > 0);
    assert(offset != nullptr);
    
    // TODO What should this be?
    *offset = r0;
    
    return SCE_OK;
}

IMP_SIG(sceGxmMapMemory)
{
    const void *const address = Ptr<const void>(r0).get(&emu->mem);
    const size_t size = r1;
    const GxmMemoryAttrib attributes = static_cast<GxmMemoryAttrib>(r2);
    assert(address != nullptr);
    assert(size > 0);
    assert((attributes == SCE_GXM_MEMORY_ATTRIB_READ) || (attributes == SCE_GXM_MEMORY_ATTRIB_RW));
    
    return SCE_OK;
}

IMP_SIG(sceGxmTerminate)
{
    return SCE_OK;
}

IMP_SIG(sceGxmUnmapMemory)
{
    const void *const address = Ptr<const void>(r0).get(&emu->mem);
    assert(address != nullptr);
    
    return SCE_OK;
}
