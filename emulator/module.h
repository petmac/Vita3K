#pragma once

#include "types.h"

#include <stddef.h>
#include <vector>

struct MemState;

struct Segment
{
    Address address = 0;
    size_t size = 0;
};

typedef std::vector<Segment> SegmentList;

struct Module
{
    Address entry_point = 0;
    SegmentList segments;
};

bool load(Module *module, MemState *mem, const char *path);
