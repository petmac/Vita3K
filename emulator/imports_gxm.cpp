#include "import.h"

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
    const SceGxmInitializeParams *const params = mem_ptr<const SceGxmInitializeParams>(r0, mem);
    (void)params;
    
    // TODO Implement.
    return SCE_OK;
}
