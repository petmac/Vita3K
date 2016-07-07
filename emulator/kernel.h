#pragma once

#include "ptr.h"

#include <map>

typedef uint32_t SceUID;

static const SceUID SCE_UID_INVALID_UID = -1;

typedef std::map<SceUID, Ptr<void>> Blocks;
typedef std::map<SceUID, Ptr<Ptr<void>>> SlotToAddress;
typedef std::map<SceUID, SlotToAddress> ThreadToSlotToAddress;

struct KernelState
{
    Blocks blocks;
    SceUID next_uid = 0;
    ThreadToSlotToAddress tls;
};
