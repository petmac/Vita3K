#pragma once

#include "trampoline.h"

#include <queue>

struct EmulatorState;

typedef std::queue<Trampoline> TrampolineQueue;

struct ThreadState
{
    uc_struct *uc = nullptr;
    TrampolineQueue trampolines;
};

bool run_thread(EmulatorState *state, Ptr<const void> entry_point);
void add_trampoline(ThreadState *thread, const Trampoline &trampoline);
