#include "import.h"

#include "events.h"

#include <SDL2/SDL_video.h>

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
    typedef std::unique_ptr<SDL_Surface, void (*)(SDL_Surface *)> SurfacePtr;
    
    const MemState *const mem = &emu->mem;
    const SceDisplayFrameBuf *const fb = Ptr<const SceDisplayFrameBuf>(r0).get(mem);
    const SetBuf set = static_cast<SetBuf>(r1);
    assert(fb != nullptr);
    assert(fb->size == sizeof(SceDisplayFrameBuf));
    assert(fb->base);
    assert(fb->pitch >= fb->width);
    assert(fb->pixelformat == SCE_DISPLAY_PIXELFORMAT_A8B8G8R8);
    assert(fb->width == 960);
    assert(fb->height == 544);
    assert(set == SCE_DISPLAY_SETBUF_NEXTFRAME);
    
    void *const pixels = fb->base.cast<void>().get(mem);
    const SurfacePtr framebuffer_surface(SDL_CreateRGBSurfaceFrom(pixels, fb->width, fb->height, 32, fb->pitch * 4, 0xff << 0, 0xff << 8, 0xff << 16, 0), SDL_FreeSurface);
    SDL_Surface *const window_surface = SDL_GetWindowSurface(emu->window.get());
    SDL_UpperBlit(framebuffer_surface.get(), nullptr, window_surface, nullptr);
    SDL_UpdateWindowSurface(emu->window.get());
    
    return SCE_OK;
}

IMP_SIG(sceDisplayWaitVblankStart)
{
    handle_events(thread->uc);
    
    return SCE_OK;
}
