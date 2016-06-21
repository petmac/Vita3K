#pragma once

#include "call.h"

#define IMP_SIG(name) void import_##name(uc_struct *uc)

#define NID(name, nid) IMP_SIG(name);
#include "nids.h"
#undef NID
