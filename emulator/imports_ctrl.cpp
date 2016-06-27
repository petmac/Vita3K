#include "import.h"

#include <SDL2/SDL_keyboard.h>

static uint64_t timestamp;

// https://github.com/vitasdk/vita-headers/blob/master/include/psp2/ctrl.h
enum Button : uint32_t
{
    SCE_CTRL_SELECT = 0x1,
    SCE_CTRL_START = 0x8,
    SCE_CTRL_UP = 0x10,
    SCE_CTRL_RIGHT = 0x20,
    SCE_CTRL_DOWN = 0x40,
    SCE_CTRL_LEFT = 0x80,
    SCE_CTRL_LTRIGGER = 0x100,
    SCE_CTRL_RTRIGGER = 0x200,
    SCE_CTRL_TRIANGLE = 0x1000,
    SCE_CTRL_CIRCLE = 0x2000,
    SCE_CTRL_CROSS = 0x4000,
    SCE_CTRL_SQUARE = 0x8000,
    SCE_CTRL_ANY = 0x10000
};

// https://github.com/vitasdk/vita-headers/blob/master/include/psp2/ctrl.h
struct SceCtrlData
{
    uint64_t timeStamp = 0;
    uint32_t buttons = 0;
    uint8_t lx = 0;
    uint8_t ly = 0;
    uint8_t rx = 0;
    uint8_t ry = 0;
    uint8_t reserved[16];
};

struct ButtonBinding
{
    SDL_Scancode scancode;
    Button button;
};

static const ButtonBinding button_bindings[] =
{
    { SDL_SCANCODE_RSHIFT, SCE_CTRL_SELECT },
    { SDL_SCANCODE_RETURN, SCE_CTRL_START },
    { SDL_SCANCODE_UP, SCE_CTRL_UP },
    { SDL_SCANCODE_RIGHT, SCE_CTRL_RIGHT },
    { SDL_SCANCODE_DOWN, SCE_CTRL_DOWN },
    { SDL_SCANCODE_LEFT, SCE_CTRL_LEFT },
    { SDL_SCANCODE_Q, SCE_CTRL_LTRIGGER },
    { SDL_SCANCODE_E, SCE_CTRL_RTRIGGER },
    { SDL_SCANCODE_V, SCE_CTRL_TRIANGLE },
    { SDL_SCANCODE_C, SCE_CTRL_CIRCLE },
    { SDL_SCANCODE_X, SCE_CTRL_CROSS },
    { SDL_SCANCODE_Z, SCE_CTRL_SQUARE },
};

static const size_t button_binding_count = sizeof(button_bindings) / sizeof(button_bindings[0]);

static uint8_t keys_to_axis(const uint8_t *keys, SDL_Scancode code1, SDL_Scancode code2)
{
    int32_t temp = 128;
    if (keys[code1])
    {
        temp -= 128;
    }
    if (keys[code2])
    {
        temp += 127;
    }
    
    assert(temp >= 0);
    assert(temp <= UINT8_MAX);
    
    return static_cast<uint8_t>(temp);
}

IMP_SIG(sceCtrlPeekBufferPositive)
{
    const int32_t port = r0;
    SceCtrlData *const data = mem_ptr<SceCtrlData>(r1, mem);
    const int32_t count = r2;
    assert(port == 0);
    assert(data != nullptr);
    assert(count == 1);
    
    memset(data, 0, sizeof(*data));
    data->timeStamp = timestamp++; // TODO Use the real time and units.
    
    const uint8_t *const keys = SDL_GetKeyboardState(nullptr);
    for (int i = 0; i < button_binding_count; ++i)
    {
        const ButtonBinding &binding = button_bindings[i];
        if (keys[binding.scancode])
        {
            data->buttons |= (binding.button | SCE_CTRL_ANY);
        }
    }
    
    data->lx = keys_to_axis(keys, SDL_SCANCODE_A, SDL_SCANCODE_D);
    data->ly = keys_to_axis(keys, SDL_SCANCODE_W, SDL_SCANCODE_S);
    data->rx = keys_to_axis(keys, SDL_SCANCODE_J, SDL_SCANCODE_L);
    data->ry = keys_to_axis(keys, SDL_SCANCODE_I, SDL_SCANCODE_K);
    
    return SCE_OK;
}
