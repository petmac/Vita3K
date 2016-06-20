#pragma once

#define IMP_SIG(name) void import_##name()

#define NID(name, nid) IMP_SIG(name);
#include "nids.h"
#undef NID
