#pragma once

#include "ptr.h"

#include <functional>
#include <string>

struct uc_struct;

typedef std::function<void()> TrampolineFn;

struct Trampoline
{
    std::string name;
    Ptr<const void> entry_point;
    TrampolineFn prefix;
    TrampolineFn postfix;
};

bool run_trampoline(uc_struct *uc, const Trampoline &trampoline);
