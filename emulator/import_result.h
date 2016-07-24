#pragma once

#include <functional>

struct uc_struct;

class ImportResult
{
public:
    
    ImportResult();
    ImportResult(uint32_t r0);
    ImportResult(uint32_t r0, uint32_t r1);
    
    void apply(uc_struct *uc) const;
    
private:
    
    std::function<void(uc_struct *)> function;
};
