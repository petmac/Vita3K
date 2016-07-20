#pragma once

#include "emulator.h"
#include "thread.h"

#include <assert.h>

struct uc_struct;

// TODO What should these be?
enum ResultCode : int32_t
{
    SCE_OK,
    UNKNOWN_UID = -1,
    OUT_OF_MEMORY = -2,
};

#define IMP_SIG(name) uint32_t import_##name(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3, Ptr<void> sp, ThreadState *thread, EmulatorState *emu)

#define NID(name, nid) IMP_SIG(name);
#include "nids.h"
#undef NID
