#include "import.h"

#include <SDL2/SDL_mouse.h>
#include <SDL2/SDL_video.h>

// TODO Move elsewhere.
static uint64_t timestamp;

// https://github.com/vitasdk/vita-headers/blob/master/include/psp2/touch.h
struct SceTouchReport
{
    uint8_t id;
    uint8_t force;
    uint16_t x;
    uint16_t y;
    uint8_t reserved[8];
    uint16_t info;
};

struct SceTouchData
{
    uint64_t timeStamp = 0;
    uint32_t status = 0;
    uint32_t reportNum = 0;
    SceTouchReport report[8];
};

IMP_SIG(sceTouchPeek)
{
    const int32_t port = r0;
    const MemState *const mem = &emu->mem;
    SceTouchData *const data = mem_ptr<SceTouchData>(r1, mem);
    const int32_t count = r2;
    assert(port == 0);
    assert(data != nullptr);
    assert(count == 1);
    
    memset(data, 0, sizeof(*data));
    data->timeStamp = timestamp++; // TODO Use the real time and units.
    
    int window_x = 0;
    int window_y = 0;
    const uint32_t buttons = SDL_GetMouseState(&window_x, &window_y);
    
    int window_w = 0;
    int window_h = 0;
    SDL_Window *const window = SDL_GetMouseFocus();
    SDL_GetWindowSize(window, &window_w, &window_h);
    
    const float normalised_x = window_x / static_cast<float>(window_w);
    const float normalised_y = window_y / static_cast<float>(window_h);
    
    if (buttons & SDL_BUTTON_LMASK)
    {
        data->report[data->reportNum].x = static_cast<uint16_t>(normalised_x * 1920);
        data->report[data->reportNum].y = static_cast<uint16_t>(normalised_y * 1088);
        ++data->reportNum;
    }
    
    return SCE_OK;
}
