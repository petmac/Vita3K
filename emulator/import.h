#pragma once

#include <unicorn/unicorn.h>

#define IMP_SIG(name) void import_##name(uc_engine *uc)

#define NID(name, nid) IMP_SIG(name);
#include "nids.h"
#undef NID
