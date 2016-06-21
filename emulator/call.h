#pragma once

#include "types.h"

struct uc_struct;

struct Args
{
    uint32_t r0 = 0;
    uint32_t r1 = 0;
    uint32_t r2 = 0;
    uint32_t r3 = 0;
    Address sp = 0;
};

Args read_args(uc_struct *uc);
void write_result(uc_struct *uc, uint32_t result);
