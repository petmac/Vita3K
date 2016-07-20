#include "emulator.h"

#include <SDL2/SDL_video.h>

// Copied from
// http://processors.wiki.ti.com/index.php/Cortex-A8#How_to_enable_NEON
//
// Converted to hex using
// http://armconverter.com/
//
// MRC p15, #0, r1, c1, c0, #2
// ORR r1, r1, #(0xf << 20)
// MCR p15, #0, r1, c1, c0, #2
// MOV r1, #0
// MCR p15, #0, r1, c7, c5, #4
// MOV r0, #0x40000000
// FMXR FPEXC, r0
// SVC #1

// ARM GDB/LLDB
static const uint32_t bootstrap_arm[] =
{
    0xEE111F50,
    0xE381160F,
    0xEE011F50,
    0xE3A01000,
    0xEE071F95,
    0xE3A00101,
    0xEEE80A10,
    0xEF000001
};

// Thumb-2 GDB/LLDB
static const uint32_t bootstrap_thumb[] =
{
    0x1F50EE11,
    0x0170F441,
    0x1F50EE01,
    0x0100F04F,
    0x1F95EE07,
    0x4080F04F,
    0x0A10EEE8,
    0x0000DF01
};

static Trampoline load_bootstrap(const void *bootstrap, size_t size, MemState *mem)
{
    const Ptr<void> buffer(alloc(mem, size, __FUNCTION__));
    if (buffer)
    {
        memcpy(buffer.get(mem), bootstrap, size);
    }
    
    Trampoline trampoline;
    trampoline.name = "Bootstrap";
    trampoline.entry_point = buffer;
    
    return trampoline;
}

bool init(EmulatorState *state)
{
    state->window = WindowPtr(SDL_CreateWindow("Emulator", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 960, 544, 0), SDL_DestroyWindow);
    if (!state->window || !init(&state->disasm) || !init(&state->mem))
    {
        return false;
    }
    
    state->bootstrap_arm = load_bootstrap(bootstrap_arm, sizeof(bootstrap_arm), &state->mem);
    state->bootstrap_thumb = load_bootstrap(bootstrap_thumb, sizeof(bootstrap_thumb), &state->mem);
    
    return state->bootstrap_arm.entry_point && state->bootstrap_thumb.entry_point;
}
