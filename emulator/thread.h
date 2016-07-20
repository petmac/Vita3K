#pragma once

#include "ptr.h"

#include <functional>
#include <queue>
#include <string>

struct EmulatorState;
struct uc_struct;

typedef std::function<void()> TrampolineFn;

struct Trampoline
{
    std::string name;
    Ptr<const void> entry_point;
    TrampolineFn prefix;
    TrampolineFn postfix;
};

typedef std::queue<Trampoline> TrampolineQueue;

struct ThreadState
{
    uc_struct *uc = nullptr;
    TrampolineQueue trampolines;
};

bool run_thread(EmulatorState *state, Ptr<const void> entry_point);
void add_trampoline(ThreadState *thread, const Trampoline &trampoline);
