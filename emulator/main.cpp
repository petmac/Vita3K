#include "emulator.h"
#include "module.h"
#include "thread.h"

#include <SDL2/SDL.h>

#include <assert.h>

typedef std::unique_ptr<const void, void (*)(const void *)> SDLPtr;

enum ExitCode
{
    Success = 0,
    IncorrectArgs,
    EmulatorInitFailed,
    ModuleLoadFailed,
    SDLInitFailed,
    RunThreadFailed
};

static void term_sdl(const void *succeeded)
{
    assert(succeeded != nullptr);
    
    SDL_Quit();
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
    
    if (!run_thread(&state, module.entry_point))
    {
        return RunThreadFailed;
    }
    
    return Success;
}
