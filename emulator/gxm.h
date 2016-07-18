#pragma once

#include "ptr.h"

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

struct GxmState
{
    SceGxmInitializeParams params;
};
