#pragma once

#include "ptr.h"

struct EmulatorState;

bool run_thread(EmulatorState *state, Ptr<const void> entry_point);
