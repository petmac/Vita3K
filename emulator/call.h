#pragma once

#include "ptr.h"

struct uc_struct;

struct Args
{
    uint32_t r0 = 0;
    uint32_t r1 = 0;
    uint32_t r2 = 0;
    uint32_t r3 = 0;
    Ptr<void> sp;
};

Args read_args(uc_struct *uc);
void write_result(uc_struct *uc, uint32_t result);
