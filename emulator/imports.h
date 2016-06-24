#pragma once

#include "types.h"

struct MemState;
struct uc_struct;

typedef uint32_t ImportFn(uint32_t, uint32_t, uint32_t, uint32_t, Address, uc_struct *uc, MemState *);

const char *import_name(uint32_t nid);
ImportFn *import_fn(uint32_t nid);
