#pragma once

#include <stdint.h>
#include <list>
#include <vector>

struct uc_struct;

class ImportResult
{
public:
    
    ImportResult();
    ImportResult(uint32_t r0);
    ImportResult(uint32_t r0, uint32_t r1);
    
    void apply(uc_struct *uc); // TODO Make this const?
    
private:
    
    void add(int reg, uint32_t val);
    
    std::vector<int> regs;
    std::list<uint32_t> vals_32;
    std::vector<void *> vals;
};
