#pragma once

#include "ptr.h"

struct EmulatorState;

struct ThreadState
{
};

bool run_thread(EmulatorState *state, Ptr<const void> entry_point);
