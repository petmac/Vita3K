#pragma once

#include "ctrl.h"
#include "disasm.h"
#include "kernel.h"

struct EmulatorState
{
    CtrlState ctrl;
    DisasmState disasm;
    KernelState kernel;
    MemState mem;
};

bool init(EmulatorState *state);
bool run_thread(EmulatorState *state, Ptr<void> entry_point);
