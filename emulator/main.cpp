#include "emulator.h"
#include "module.h"

#include <SDL2/SDL.h>
#include <SDL2/SDL_opengl.h>

#include <assert.h>
#include <memory>

typedef std::unique_ptr<const void, void (*)(const void *)> SDLPtr;
typedef std::unique_ptr<SDL_Window, void (*)(SDL_Window *)> WindowPtr;
typedef std::unique_ptr<void, void (*)(SDL_GLContext)> GLContextPtr;

enum ExitCode
{
    Success = 0,
    IncorrectArgs,
    EmulatorInitFailed,
    ModuleLoadFailed,
    SDLInitFailed,
    CreateWindowFailed,
    CreateContextFailed,
    RunThreadFailed
};

static void term_sdl(const void *succeeded)
{
    assert(succeeded != nullptr);
    
    SDL_Quit();
}

static void term_gl(SDL_GLContext gl)
{
    assert(gl != nullptr);
    
    SDL_GL_MakeCurrent(nullptr, nullptr);
    SDL_GL_DeleteContext(gl);
}

int main(int argc, const char * argv[])
{
    if (argc <= 2)
    {
        return IncorrectArgs;
    }
    
    const SDLPtr sdl(reinterpret_cast<const void *>(SDL_Init(SDL_INIT_GAMECONTROLLER | SDL_INIT_VIDEO) >= 0), term_sdl);
    if (!sdl)
    {
        return SDLInitFailed;
    }
    
    EmulatorState state;
    if (!init(&state))
    {
        return EmulatorInitFailed;
    }
    
    Module module;
    const char *const path = argv[1];
    if (!load(&module, &state.mem, path))
    {
        return ModuleLoadFailed;
    }
    
    const WindowPtr window(SDL_CreateWindow("Emulator", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 960, 544, SDL_WINDOW_OPENGL), SDL_DestroyWindow);
    if (!window)
    {
        return CreateWindowFailed;
    }
    
    const GLContextPtr gl(SDL_GL_CreateContext(window.get()), term_gl);
    if (!gl)
    {
        return CreateContextFailed;
    }
    
    SDL_GL_MakeCurrent(window.get(), gl.get());
    
    glClearColor(0.0625f, 0.125f, 0.25f, 1);
    glPixelZoom(1, -1);
    glRasterPos2f(-1, 1);
    
    if (!run_thread(&state, module.entry_point))
    {
        return RunThreadFailed;
    }
    
    return Success;
}
