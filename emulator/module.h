#pragma once

#include "types.h"

struct MemState;

struct Module
{
    Address entry_point = 0;
};

bool load(Module *module, MemState *mem, const char *path);
