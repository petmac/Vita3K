#pragma once

#include "ptr.h"

struct MemState;

struct Module
{
    Ptr<void> entry_point;
};

bool load(Module *module, MemState *mem, const char *path);
