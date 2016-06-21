#include "call.h"

#include <unicorn/unicorn.h>

#include <assert.h>

static int regs[] = { UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP };

Args read_args(uc_struct *uc)
{
    Args args;
    void *vals[] = { &args.r0, &args.r1, &args.r2, &args.r3, &args.sp };
    const int count = sizeof(regs) / sizeof(regs[0]);
    
    const uc_err err = uc_reg_read_batch(uc, regs, vals, count);
    assert(err == UC_ERR_OK);
    
    return args;
}

void write_result(uc_struct *uc, uint32_t result)
{
    const uc_err err = uc_reg_write(uc, UC_ARM_REG_R0, &result);
    assert(err == UC_ERR_OK);
}
