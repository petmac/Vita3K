#pragma once

#include <Remotery.h>

#define SHADERGEN_PROFILE(name)                         \
    RMT_OPTIONAL(RMT_ENABLED, {                         \
        static rmtU32 rmt_sample_hash = 0;              \
        _rmt_BeginCPUSample(name, 0, &rmt_sample_hash); \
    } rmt_EndCPUSampleOnScopeExit rmt_ScopedCPUSample##__LINE__)
