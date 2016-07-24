#include "import_result.h"

#include <unicorn/unicorn.h>

#include <assert.h>

ImportResult::ImportResult()
{
}

ImportResult::ImportResult(uint32_t r0)
{
    function = [r0](uc_struct *uc)
    {
        const uc_err err = uc_reg_write(uc, UC_ARM_REG_R0, &r0);
        assert(err == UC_ERR_OK);
    };
}

ImportResult::ImportResult(uint32_t r0, uint32_t r1)
{
    function = [r0, r1](uc_struct *uc)
    {
        int regs[] = { UC_ARM_REG_R0, UC_ARM_REG_R1 };
        const void *const vals[] = { &r0, &r1 };
        
        const uc_err err = uc_reg_write_batch(uc, regs, const_cast<void **>(vals), 2);
        assert(err == UC_ERR_OK);
    };
}

void ImportResult::apply(uc_struct *uc) const
{
    if (function)
    {
        function(uc);
    }
}
