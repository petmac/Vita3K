#include "trampoline.h"

#include <unicorn/unicorn.h>

#include <iostream>

bool run_trampoline(uc_struct *uc, const Trampoline &trampoline)
{
    std::cout << "Starting trampoline \"" << trampoline.name << "\"" << std::endl;
    
    if (trampoline.prefix)
    {
        trampoline.prefix();
    }
    
    uc_err err = uc_emu_start(uc, (trampoline.entry_point.address() >> 1) << 1, 0, 0, 0);
    if (err != UC_ERR_OK)
    {
        std::cerr << "Emulation failed:" << std::endl;
        std::cerr << uc_strerror(err) << std::endl;
        uint64_t pc = 0;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        std::cerr << "PC = " << std::hex << pc << std::dec << std::endl;
        
        return false;
    }
    
    if (trampoline.postfix)
    {
        trampoline.postfix();
    }
    
    std::cout << "Finished trampoline \"" << trampoline.name << "\"" << std::endl;
    
    return true;
}
