#pragma once

#include "ptr.h"

#include <map>
#include <stddef.h>

class MemState;

typedef std::map<size_t, Ptr<void>> SegmentAddresses;

bool relocate(const void *entries, size_t size, const SegmentAddresses &segments, const MemState *mem);
