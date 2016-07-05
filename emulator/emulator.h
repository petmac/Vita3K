#pragma once

#include "disasm.h"
#include "kernel.h"
#include "mem.h"

struct EmulatorState
{
    DisasmState disasm;
    KernelState kernel;
    MemState mem;
};

bool init(EmulatorState *state);
bool run_thread(EmulatorState *state, Address entry_point);
