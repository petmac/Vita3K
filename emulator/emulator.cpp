#include "emulator.h"

#include <elfio/elfio.hpp>

#include <iostream>

bool emulate(const char *path)
{
    ELFIO::elfio elf;
    if (!elf.load(path))
    {
        std::cerr << "Couldn't load elf '" << path << "'." << std::endl;
        return false;
    }
    
    std::cout << "Loaded '" << path << "'." << std::endl;
    
    std::cout << "Emulation finished." << std::endl;
    
    return true;
}
