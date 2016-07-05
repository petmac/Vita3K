#include "emulator.h"
#include "module.h"

#include <SDL2/SDL.h>
#include <SDL2/SDL_opengl.h>

// TODO This is a bit gross.
extern SDL_Window *window;
SDL_Window *window = nullptr;

int main(int argc, const char * argv[])
{
    if (argc <= 2)
    {
        return 1;
    }
    
    if (SDL_Init(SDL_INIT_VIDEO) < 0)
    {
        return 1;
    }
    
    window = SDL_CreateWindow("Emulator", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, 960, 544, SDL_WINDOW_OPENGL);
    if (window == nullptr)
    {
        return 2;
    }
    
    SDL_GLContext context = SDL_GL_CreateContext(window);
    if (context == nullptr)
    {
        return 3;
    }
    
    SDL_GL_MakeCurrent(window, context);
    
    glClearColor(0.0625f, 0.125f, 0.25f, 1);
    glPixelZoom(1, -1);
    glRasterPos2f(-1, 1);
    
    EmulatorState state;
    if (!init(&state))
    {
        return 4;
    }
    
    Module module;
    const char *const path = argv[1];
    if (!load(&module, &state.mem, path))
    {
        return 5;
    }
    
    const bool result = run_thread(&state, module.entry_point);
    
    SDL_GL_MakeCurrent(window, nullptr);
    SDL_GL_DeleteContext(context);
    context = nullptr;
    
    SDL_DestroyWindow(window);
    window = nullptr;
    
    SDL_Quit();
    
    return result ? 0 : 1;
}
