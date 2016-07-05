#pragma once

#include "types.h"

#include <map>

typedef uint32_t SceUID;

typedef std::map<SceUID, Address> Blocks;
typedef std::map<SceUID, Address> SlotToAddress;
typedef std::map<SceUID, SlotToAddress> ThreadToSlotToAddress;

struct KernelState
{
    Blocks blocks;
    SceUID next_uid = 0;
    ThreadToSlotToAddress tls;
};
