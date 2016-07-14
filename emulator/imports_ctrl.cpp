#include "import.h"

#include <SDL2/SDL_gamecontroller.h>
#include <SDL2/SDL_keyboard.h>

#include <array>
#include <algorithm>

// TODO Move elsewhere.
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

struct KeyBinding
{
    SDL_Scancode scancode;
    Button button;
};

struct ControllerBinding
{
    SDL_GameControllerButton controller;
    Button button;
};

static const KeyBinding key_bindings[] =
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

static const size_t key_binding_count = sizeof(key_bindings) / sizeof(key_bindings[0]);

static const ControllerBinding controller_bindings[] =
{
    { SDL_CONTROLLER_BUTTON_BACK, SCE_CTRL_SELECT },
    { SDL_CONTROLLER_BUTTON_START, SCE_CTRL_START },
    { SDL_CONTROLLER_BUTTON_DPAD_UP, SCE_CTRL_UP },
    { SDL_CONTROLLER_BUTTON_DPAD_RIGHT, SCE_CTRL_RIGHT },
    { SDL_CONTROLLER_BUTTON_DPAD_DOWN, SCE_CTRL_DOWN },
    { SDL_CONTROLLER_BUTTON_DPAD_LEFT, SCE_CTRL_LEFT },
    { SDL_CONTROLLER_BUTTON_LEFTSHOULDER, SCE_CTRL_LTRIGGER },
    { SDL_CONTROLLER_BUTTON_RIGHTSHOULDER, SCE_CTRL_RTRIGGER },
    { SDL_CONTROLLER_BUTTON_Y, SCE_CTRL_TRIANGLE },
    { SDL_CONTROLLER_BUTTON_B, SCE_CTRL_CIRCLE },
    { SDL_CONTROLLER_BUTTON_A, SCE_CTRL_CROSS },
    { SDL_CONTROLLER_BUTTON_X, SCE_CTRL_SQUARE },
};

static const size_t controller_binding_count = sizeof(controller_bindings) / sizeof(controller_bindings[0]);

static bool operator<(const SDL_JoystickGUID &a, const SDL_JoystickGUID &b)
{
    return memcmp(&a, &b, sizeof(a)) < 0;
}

static float keys_to_axis(const uint8_t *keys, SDL_Scancode code1, SDL_Scancode code2)
{
    float temp = 0;
    if (keys[code1])
    {
        temp -= 1;
    }
    if (keys[code2])
    {
        temp += 1;
    }
    
    return temp;
}

static void apply_keyboard(uint32_t *buttons, float axes[4])
{
    const uint8_t *const keys = SDL_GetKeyboardState(nullptr);
    for (int i = 0; i < key_binding_count; ++i)
    {
        const KeyBinding &binding = key_bindings[i];
        if (keys[binding.scancode])
        {
            *buttons |= binding.button;
        }
    }
    
    axes[0] += keys_to_axis(keys, SDL_SCANCODE_A, SDL_SCANCODE_D);
    axes[1] += keys_to_axis(keys, SDL_SCANCODE_W, SDL_SCANCODE_S);
    axes[2] += keys_to_axis(keys, SDL_SCANCODE_J, SDL_SCANCODE_L);
    axes[3] += keys_to_axis(keys, SDL_SCANCODE_I, SDL_SCANCODE_K);
}

static float axis_to_axis(int16_t axis)
{
    const float unsigned_axis = axis - INT16_MIN;
    assert(unsigned_axis >= 0);
    assert(unsigned_axis <= UINT16_MAX);
    
    const float f = unsigned_axis / UINT16_MAX;
    
    const float output = (f * 2) - 1;
    assert(output >= -1);
    assert(output <= 1);
    
    return output;
}

static void apply_controller(uint32_t *buttons, float axes[4], SDL_GameController *controller)
{
    for (int i = 0; i < controller_binding_count; ++i)
    {
        const ControllerBinding &binding = controller_bindings[i];
        if (SDL_GameControllerGetButton(controller, binding.controller))
        {
            *buttons |= binding.button;
        }
    }
    
    axes[0] += axis_to_axis(SDL_GameControllerGetAxis(controller, SDL_CONTROLLER_AXIS_LEFTX));
    axes[1] += axis_to_axis(SDL_GameControllerGetAxis(controller, SDL_CONTROLLER_AXIS_LEFTY));
    axes[2] += axis_to_axis(SDL_GameControllerGetAxis(controller, SDL_CONTROLLER_AXIS_RIGHTX));
    axes[3] += axis_to_axis(SDL_GameControllerGetAxis(controller, SDL_CONTROLLER_AXIS_RIGHTY));
}

static uint8_t float_to_byte(float f)
{
    const float mapped = (f * 0.5f) + 0.5f;
    const float clamped = std::max(0.0f, std::min(mapped, 1.0f));
    assert(clamped >= 0);
    assert(clamped <= 1);
    
    return static_cast<uint8_t>(clamped * 255);
}

static void remove_disconnected_controllers(CtrlState *state)
{
    for (GameControllerList::iterator controller = state->controllers.begin(); controller != state->controllers.end();)
    {
        if (SDL_GameControllerGetAttached(controller->second.get()))
        {
            ++controller;
        }
        else
        {
            controller = state->controllers.erase(controller);
        }
    }
}

static void add_new_controllers(CtrlState *state)
{
    const int num_joysticks = SDL_NumJoysticks();
    for (int joystick_index = 0; joystick_index < num_joysticks; ++joystick_index)
    {
        if (SDL_IsGameController(joystick_index))
        {
            const SDL_JoystickGUID guid = SDL_JoystickGetDeviceGUID(joystick_index);
            if (state->controllers.find(guid) == state->controllers.end())
            {
                const GameControllerPtr controller(SDL_GameControllerOpen(joystick_index), SDL_GameControllerClose);
                state->controllers.insert(GameControllerList::value_type(guid, controller));
            }
        }
    }
}

IMP_SIG(sceCtrlPeekBufferPositive)
{
    const int32_t port = r0;
    const MemState *const mem = &emu->mem;
    SceCtrlData *const data = Ptr<SceCtrlData>(r1).get(mem);
    const int32_t count = r2;
    assert(port == 0);
    assert(data != nullptr);
    assert(count == 1);
    
    CtrlState *const state = &emu->ctrl;
    remove_disconnected_controllers(state);
    add_new_controllers(state);
    
    memset(data, 0, sizeof(*data));
    data->timeStamp = timestamp++; // TODO Use the real time and units.
    
    std::array<float, 4> axes;
    axes.fill(0);
    apply_keyboard(&data->buttons, axes.data());
    for (const GameControllerList::value_type &controller : state->controllers)
    {
        apply_controller(&data->buttons, axes.data(), controller.second.get());
    }
    
    data->lx = float_to_byte(axes[0]);
    data->ly = float_to_byte(axes[1]);
    data->rx = float_to_byte(axes[2]);
    data->ry = float_to_byte(axes[3]);
    
    return SCE_OK;
}
