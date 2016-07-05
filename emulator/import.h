#pragma once

#include "emulator.h"

#include <assert.h>

struct uc_struct;

enum ResultCode : int32_t
{
    SCE_OK,
    UNKNOWN_UID
};

#define IMP_SIG(name) uint32_t import_##name(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, Address sp, uc_struct *uc, EmulatorState *emu)

#define NID(name, nid) IMP_SIG(name);
#include "nids.h"
#undef NID
