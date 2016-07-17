#pragma once

#include "ctrl.h"
#include "disasm.h"
#include "kernel.h"

struct SDL_Window;

typedef std::shared_ptr<SDL_Window> WindowPtr;

struct EmulatorState
{
    WindowPtr window;
    CtrlState ctrl;
    DisasmState disasm;
    KernelState kernel;
    MemState mem;
    Ptr<void> bootstrap_arm;
    Ptr<void> bootstrap_thumb;
};

bool init(EmulatorState *state);
bool run_thread(EmulatorState *state, Ptr<const void> entry_point);
