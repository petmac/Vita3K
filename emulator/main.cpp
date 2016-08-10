#include "emulator.h"
#include "module.h"
#include "thread.h"

#include <SDL2/SDL.h>

#include <assert.h>
#include <iostream>

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
    std::cout << "Emulator starting..." << std::endl;
    
    if (argc <= 2)
    {
        std::cerr << "Incorrect args." << std::endl;
        return IncorrectArgs;
    }
    
    const SDLPtr sdl(reinterpret_cast<const void *>(SDL_Init(SDL_INIT_GAMECONTROLLER | SDL_INIT_VIDEO) >= 0), term_sdl);
    if (!sdl)
    {
        std::cerr << "SDL initialisation failed." << std::endl;
        return SDLInitFailed;
    }
    
    EmulatorState state;
    if (!init(&state))
    {
        std::cerr << "Emulator initialisation failed." << std::endl;
        return EmulatorInitFailed;
    }
    
    Module module;
    const char *const path = argv[1];
    if (!load(&module, &state.mem, path))
    {
        std::cerr << "Failed to load module." << std::endl;
        return ModuleLoadFailed;
    }
    
    std::cout << "Emulator initialised. Running main thread..." << std::endl;
    
    if (!run_thread(&state, module.entry_point))
    {
        std::cerr << "Failed to run main thread." << std::endl;
        return RunThreadFailed;
    }
    
    return Success;
}
