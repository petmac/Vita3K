#pragma once

#include "ptr.h"

class ImportResult;
struct EmulatorState;
struct ThreadState;

typedef ImportResult ImportFn(uint32_t, uint32_t, uint32_t, uint32_t, Ptr<void>, ThreadState *, EmulatorState *);

const char *import_name(uint32_t nid);
ImportFn *import_fn(uint32_t nid);
