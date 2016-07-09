#pragma once

#include "ptr.h"

struct MemState;

struct Module
{
    Ptr<const void> entry_point;
};

bool load(Module *module, MemState *mem, const char *path);
