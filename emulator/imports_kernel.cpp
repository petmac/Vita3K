#include "import.h"

#include <assert.h>

IMP_SIG(sceKernelCreateLwMutex)
{
    uint32_t r0 = 0;
    uint32_t r1 = 1;
    uint32_t r2 = 2;
    uint32_t r3 = 4;
    void *vals[] = { &r0, &r1, &r2, &r3 };
    int regs[] = { UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3 };
    uc_err err = uc_reg_read_batch(uc, regs, vals, 4);
    assert(err == UC_ERR_OK);
    
    r0 = 0;
    err = uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    assert(err == UC_ERR_OK);
}
