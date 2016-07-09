#include "import.h"

#include <SDL2/SDL_events.h>
#include <SDL2/SDL_opengl.h>
#include <SDL2/SDL_video.h>
#include <unicorn/unicorn.h>

enum PixelFormat : uint32_t
{
    SCE_DISPLAY_PIXELFORMAT_A8B8G8R8
};

struct SceDisplayFrameBuf
{
    uint32_t size = 0;
    Ptr<const void> base;
    uint32_t pitch = 0;
    PixelFormat pixelformat = SCE_DISPLAY_PIXELFORMAT_A8B8G8R8;
    uint32_t width = 0;
    uint32_t height = 0;
};

enum SetBuf : uint32_t
{
    SCE_DISPLAY_SETBUF_NEXTFRAME = 1
};

IMP_SIG(sceDisplaySetFrameBuf)
{
    const MemState *const mem = &emu->mem;
    const SceDisplayFrameBuf *const fb = mem_ptr<const SceDisplayFrameBuf>(r0, mem);
    const SetBuf set = static_cast<SetBuf>(r1);
    assert(fb != nullptr);
    assert(fb->size == sizeof(SceDisplayFrameBuf));
    assert(fb->base);
    assert(fb->pitch == fb->width);
    assert(fb->pixelformat == SCE_DISPLAY_PIXELFORMAT_A8B8G8R8);
    assert(fb->width == 960);
    assert(fb->height == 544);
    assert(set == SCE_DISPLAY_SETBUF_NEXTFRAME);
    
    const void *const pixels = fb->base.get(mem);
    glDrawPixels(fb->width, fb->height, GL_RGBA, GL_UNSIGNED_BYTE, pixels);
    
    SDL_Window *const window = SDL_GL_GetCurrentWindow();
    assert(window != nullptr);
    
    if (window != nullptr)
    {
        SDL_GL_SwapWindow(window);
    }
    
    return SCE_OK;
}

IMP_SIG(sceDisplayWaitVblankStart)
{
    SDL_Event event;
    while (SDL_PollEvent(&event))
    {
        if (event.type == SDL_QUIT)
        {
            // TODO Stop all threads, not just this one.
            uc_emu_stop(uc);
            break;
        }
    }
    
    return SCE_OK;
}
