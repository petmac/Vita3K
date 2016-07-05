#pragma once

#include "disasm.h"
#include "mem.h"

struct EmulatorState
{
    DisasmState disasm;
    MemState mem;
};

bool init(EmulatorState *state);
bool run_thread(EmulatorState *state, Address entry_point);
