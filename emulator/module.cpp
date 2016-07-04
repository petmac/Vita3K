#include "module.h"

#include "imports.h"
#include "mem.h"
#include "relocation.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
#include <elfio/elfio.hpp>
#pragma GCC diagnostic pop

#include <assert.h>
#include <iomanip>
#include <iostream>

static const bool LOG_IMPORTS = false;

// From UVLoader
// https://github.com/yifanlu/UVLoader/blob/master/resolve.h
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

// From UVLoader
// https://github.com/yifanlu/UVLoader/blob/master/resolve.h
struct ModuleImports // thanks roxfan
{
    uint16_t size;               // size of this structure; 0x34 for Vita 1.x
    uint16_t lib_version;        //
    uint16_t attribute;          //
    uint16_t num_functions;      // number of imported functions
    uint16_t num_vars;           // number of imported variables
    uint16_t num_tls_vars;       // number of imported TLS variables
    uint32_t reserved1;          // ?
    uint32_t module_nid;         // NID of the module to link to
    uint32_t lib_name;          // name of module
    uint32_t reserved2;          // ?
    uint32_t func_nid_table;    // array of function NIDs (numFuncs)
    uint32_t func_entry_table; // parallel array of pointers to stubs; they're patched by the loader to jump to the final code
    uint32_t var_nid_table;     // NIDs of the imported variables (numVars)
    uint32_t var_entry_table;  // array of pointers to "ref tables" for each variable
    uint32_t tls_nid_table;     // NIDs of the imported TLS variables (numTlsVars)
    uint32_t tls_entry_table;  // array of pointers to ???
};

static bool load_func_imports(const uint32_t *nids, const Address *entries, size_t count, const MemState &mem)
{
    for (size_t i = 0; i < count; ++i)
    {
        const uint32_t nid = nids[i];
        const Address entry = entries[i];
        
        if (LOG_IMPORTS)
        {
            const char *const name = import_name(nid);
            const char prev_fill = std::cout.fill();
            std::cout << "\tNID " << std::hex << std::setw(8) << std::setfill('0') << nid << std::setfill(prev_fill) << " (" << name << ") at 0x" << entry << std::dec << std::endl;
        }
        
        uint32_t *const stub = mem_ptr<uint32_t>(entry, &mem);
        stub[0] = 0xef000000; // svc #0 - Call our interrupt hook.
        stub[1] = 0xe1a0f00e; // mov pc, lr - Return to the caller.
        stub[2] = nid; // Our interrupt hook will read this.
    }
    
    return true;
}

static bool load_imports(const ModuleInfo &module, Address segment_address, const MemState &mem)
{
    const uint8_t *const base = mem_ptr<const uint8_t>(segment_address, &mem);
    const ModuleImports *const imports_begin = reinterpret_cast<const ModuleImports *>(base + module.stub_top);
    const ModuleImports *const imports_end = reinterpret_cast<const ModuleImports *>(base + module.stub_end);
    
    for (const ModuleImports *imports = imports_begin; imports < imports_end; imports = reinterpret_cast<const ModuleImports *>(reinterpret_cast<const uint8_t *>(imports) + imports->size))
    {
        if (LOG_IMPORTS)
        {
            const char *const lib_name = mem_ptr<const char>(imports->lib_name, &mem);
            std::cout << "Loading imports from " << lib_name << std::endl;
        }
        
        assert(imports->lib_version == 1);
        assert(imports->num_vars == 0);
        assert(imports->num_tls_vars == 0);
        
        const uint32_t *const nids = mem_ptr<const uint32_t>(imports->func_nid_table, &mem);
        const uint32_t *const entries = mem_ptr<const uint32_t>(imports->func_entry_table, &mem);
        if (!load_func_imports(nids, entries, imports->num_functions, mem))
        {
            return false;
        }
    }
    
    return true;
}

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
    
    SegmentAddresses segments;
    for (ELFIO::Elf_Half segment_index = 0; segment_index < elf.segments.size(); ++segment_index)
    {
        const ELFIO::segment &src = *elf.segments[segment_index];
        const uint32_t type = src.get_type();
        if (type == PT_LOAD)
        {
            const Address address = alloc(mem, src.get_memory_size(), "segment");
            std::copy_n(src.get_data(), src.get_file_size(), mem_ptr<uint8_t>(address, mem));
            
            segments[segment_index] = address;
        }
        else if (type == PT_LOOS)
        {
            relocate(src.get_data(), src.get_file_size(), segments, mem);
        }
    }
    
    const Address module_info_segment_address = segments[module_info_segment_index];
    module->entry_point = module_info_segment_address + module_info->mod_start;
    
    if (!load_imports(*module_info, module_info_segment_address, *mem))
    {
        return false;
    }
    
    std::cout << "Loaded '" << path << "'." << std::endl;
    return true;
}
