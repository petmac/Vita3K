#pragma once

#include "types.h"

#include <map>
#include <stddef.h>

class MemState;

typedef std::map<size_t, Address> SegmentAddresses;

void relocate(const void *entries, size_t size, const SegmentAddresses &segments, const MemState *mem);
