#pragma once

#include "trampoline.h"

#include <queue>

struct EmulatorState;

typedef std::queue<Trampoline> TrampolineQueue;

struct ThreadState
{
    uc_struct *uc = nullptr;
    TrampolineQueue trampolines;
    bool log_code = false;
};

bool run_thread(EmulatorState *state, Ptr<const void> entry_point);
void add_trampoline(ThreadState *thread, const Trampoline &trampoline);
