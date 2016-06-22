#pragma once

#include "mem.h"

#include <assert.h>

#define IMP_SIG(name) uint32_t import_##name(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, Address sp, MemState *mem)

#define NID(name, nid) IMP_SIG(name);
#include "nids.h"
#undef NID
