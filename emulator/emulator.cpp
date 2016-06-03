#include "emulator.h"

#include <elfio/elfio.hpp>
#include <unicorn/unicorn.h>

#include <assert.h>
#include <algorithm>
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

typedef uint32_t Address;
typedef std::vector<uint8_t> Buffer;

struct Segment
{
    Address address = 0;
    ELFIO::Elf_Word flags = 0;
    Buffer data;
};

typedef std::vector<Segment> SegmentList;

struct Module
{
    Address entry_point = 0;
    SegmentList segments;
};

static const size_t alignment = 4096;

static bool load(Module *module, const char *path)
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
            const size_t size = ((src.get_memory_size() + (alignment - 1)) / alignment) * alignment;
            Segment dst;
            dst.address = static_cast<Address>(src.get_virtual_address());
            dst.flags = src.get_flags();
            dst.data.resize(size, 0);
            std::copy_n(src.get_data(), src.get_file_size(), dst.data.begin());
            
            module->segments.push_back(dst);
        }
    }
    
    std::cout << "Loaded '" << path << "'." << std::endl;
    return true;
}

bool emulate(const char *path)
{
    Module module;
    if (!load(&module, path))
    {
        return false;
    }
    
    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_ARM, module.entry_point & 1 ? UC_MODE_THUMB : UC_MODE_ARM, &uc);
    assert(err == UC_ERR_OK);
    
    for (Segment &segment : module.segments)
    {
        assert((segment.address % alignment) == 0);
        assert((segment.data.size() % alignment) == 0);
        err = uc_mem_map_ptr(uc, segment.address, segment.data.size(), UC_PROT_ALL, &segment.data.front());
        assert(err == UC_ERR_OK);
    }
    
    err = uc_emu_start(uc, (module.entry_point >> 1) << 1, 0, 0, 0);
    if (err != UC_ERR_OK)
    {
        std::cerr << uc_strerror(err) << std::endl;
    }
    
    std::cout << "Emulation finished." << std::endl;
    
    return true;
}
