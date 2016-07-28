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
static const uint32_t bootstrap[] =
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

static const uint8_t arm_to_thumb[] =
{
    // ARM HEX
    0x04, 0x00, 0x2D, 0xE5, // push {r0}
    0x0F, 0x00, 0xA0, 0xE1, // mov r0, pc
    0x05, 0x00, 0x80, 0xE2, // add r0, #5
    0x10, 0xFF, 0x2F, 0xE1, // bx r0
    
    // Thumb HEX
    0x01, 0xBC, // pop {r0}
    0x01, 0xDF, // svc #1
};

static const uint8_t stop[] =
{
    0x01, 0x00, 0x00, 0xef // #svc #1
};

static Trampoline load_bootstrap(const char *name, const void *bootstrap, size_t size, MemState *mem)
{
    const Ptr<void> buffer(alloc(mem, size, __FUNCTION__));
    if (buffer)
    {
        memcpy(buffer.get(mem), bootstrap, size);
    }
    
    Trampoline trampoline;
    trampoline.name = name;
    trampoline.entry_point = buffer;
    
    return trampoline;
}

bool init(EmulatorState *state)
{
    state->window = WindowPtr(SDL_CreateWindow("Emulator", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 960, 544, SDL_WINDOW_OPENGL), SDL_DestroyWindow);
    if (!state->window || !init(&state->disasm) || !init(&state->mem))
    {
        return false;
    }
    
    state->bootstrap = load_bootstrap("Enable FP and FVP", bootstrap, sizeof(bootstrap), &state->mem);
    state->arm_to_thumb = load_bootstrap("ARM to Thumb", arm_to_thumb, sizeof(arm_to_thumb), &state->mem);
    state->stop = load_bootstrap("Stop", stop, sizeof(stop), &state->mem);
    
    return state->bootstrap.entry_point && state->arm_to_thumb.entry_point && state->stop.entry_point;
}
