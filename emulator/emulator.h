#pragma once

#include "ctrl.h"
#include "disasm.h"
#include "gxm.h"
#include "kernel.h"
#include "trampoline.h"

struct SDL_Window;

typedef std::shared_ptr<SDL_Window> WindowPtr;

struct EmulatorState
{
    WindowPtr window;
    CtrlState ctrl;
    DisasmState disasm;
    KernelState kernel;
    MemState mem;
    Trampoline bootstrap;
    Trampoline arm_to_thumb;
    Trampoline stop;
    GxmState gxm;
};

bool init(EmulatorState *state);
