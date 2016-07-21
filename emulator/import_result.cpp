#include "import_result.h"

#include <unicorn/unicorn.h>

#include <assert.h>

ImportResult::ImportResult()
{
}

ImportResult::ImportResult(uint32_t r0)
{
    add(UC_ARM_REG_R0, r0);
}

ImportResult::ImportResult(uint32_t r0, uint32_t r1)
{
    add(UC_ARM_REG_R0, r0);
    add(UC_ARM_REG_R1, r1);
}

void ImportResult::apply(uc_struct *uc)
{
    const int count = static_cast<int>(regs.size());
    const uc_err err = uc_reg_write_batch(uc, &regs.front(), &vals.front(), count);
    assert(err == UC_ERR_OK);
}

void ImportResult::add(int reg, uint32_t val)
{
    regs.push_back(reg);
    vals_32.push_back(val);
    void *const ptr = &vals_32.back();
    vals.push_back(ptr);
}
