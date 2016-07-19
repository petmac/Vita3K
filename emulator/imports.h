#pragma once

#include "ptr.h"

struct EmulatorState;
struct ThreadState;
struct uc_struct;

typedef uint32_t ImportFn(uint32_t, uint32_t, uint32_t, uint32_t, Ptr<void>, uc_struct *, ThreadState *, EmulatorState *);

const char *import_name(uint32_t nid);
ImportFn *import_fn(uint32_t nid);
