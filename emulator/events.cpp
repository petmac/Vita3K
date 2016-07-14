#include "events.h"

#include <SDL2/SDL_events.h>
#include <unicorn/unicorn.h>

void handle_events(uc_struct *uc)
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
}
