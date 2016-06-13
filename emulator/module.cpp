#include "module.h"

#include "mem.h"

#include <elfio/elfio.hpp>

#include <assert.h>
#include <iostream>

// From UVLoader
// https://github.com/yifanlu/UVLoader
struct ModuleInfo // thanks roxfan
{
    uint16_t modattribute; // ??
    uint16_t modversion; // always 1,1?
    char modname[27]; ///< Name of the module
    uint8_t type;  // 6 = user-mode prx?
    uint32_t gp_value; // always 0 on ARM
    uint32_t ent_top; // beginning of the export list (sceModuleExports array)
    uint32_t ent_end; // end of same
    uint32_t stub_top; // beginning of the import list (sceModuleStubInfo array)
    uint32_t stub_end; // end of same
    uint32_t module_nid; // ID of the PRX? seems to be unused
    uint32_t field_38; // unused in samples
    uint32_t field_3C; // I suspect these may contain TLS info
    uint32_t field_40; //
    uint32_t mod_start; // module start function; can be 0 or -1; also present in exports
    uint32_t mod_stop; // module stop function
    uint32_t exidx_start; // ARM EABI style exception tables
    uint32_t exidx_end; //
    uint32_t extab_start; //
    uint32_t extab_end; //
};

bool load(Module *module, MemState *mem, const char *path)
{
    ELFIO::elfio elf;
    if (!elf.load(path))
    {
        std::cerr << "Couldn't load elf '" << path << "'." << std::endl;
        return false;
    }
    
    const unsigned int module_info_segment_index = static_cast<unsigned int>(elf.get_entry() >> 30);
    const Address module_info_offset = elf.get_entry() & 0x3fffffff;
    const ELFIO::segment *const module_info_segment = elf.segments[module_info_segment_index];
    const ModuleInfo *const module_info = reinterpret_cast<const ModuleInfo *>(module_info_segment->get_data() + module_info_offset);
    module->entry_point = static_cast<Address>(module_info_segment->get_virtual_address() + module_info->mod_start);
    
    for (ELFIO::Elf_Half segment_index = 0; segment_index < elf.segments.size(); ++segment_index)
    {
        const ELFIO::segment &src = *elf.segments[segment_index];
        if (src.get_type() == PT_LOAD)
        {
            assert((src.get_virtual_address() % mem->page_size) == 0);
            
            Segment dst;
            dst.address = static_cast<Address>(src.get_virtual_address());
            dst.size = ((src.get_memory_size() + (mem->page_size - 1)) / mem->page_size) * mem->page_size;
            
            reserve(mem, dst.address, dst.size, "segment");
            std::copy_n(src.get_data(), src.get_file_size(), &mem->memory[dst.address]);
            
            module->segments.push_back(dst);
        }
    }
    
    std::cout << "Loaded '" << path << "'." << std::endl;
    return true;
}
