#include "emulator.h"

#include "disasm.h"
#include "mem.h"

#include <elfio/elfio.hpp>
#include <unicorn/unicorn.h>

#include <assert.h>
#include <iomanip>
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

struct Segment
{
    Address address = 0;
    size_t size = 0;
};

typedef std::vector<Segment> SegmentList;

struct Module
{
    Address entry_point = 0;
    SegmentList segments;
};

struct EmulatorState
{
    DisasmState disasm;
    MemState mem;
};

// Copied from
// http://processors.wiki.ti.com/index.php/Cortex-A8#How_to_enable_NEON
//
// Converted to hex using
// http://armconverter.com/
//
// MRC p15, #0, r1, c1, c0, #2
// ORR r1, r1, #(0xf << 20)
// MCR p15, #0, r1, c1, c0, #2
// MOV r1, #0
// MCR p15, #0, r1, c7, c5, #4
// MOV r0,#0x40000000
// FMXR FPEXC, r0 ; FPEXC = r0

// ARM GDB/LLDB
static const uint32_t bootstrap_arm[] =
{
    0xEE111F50,
    0xE381160F,
    0xEE011F50,
    0xE3A01000,
    0xEE071F95,
    0xE3A00101,
    0xEEE80A10
};

// Thumb-2 GDB/LLDB
static const uint32_t bootstrap_thumb[] =
{
    0x1F50EE11,
    0x0170F441,
    0x1F50EE01,
    0x0100F04F,
    0x1F95EE07,
    0x4080F04F,
    0x0A10EEE8
};

static bool init(EmulatorState *state)
{
    return init(&state->disasm) && init(&state->mem);
}

static bool load(Module *module, MemState *mem, const char *path)
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
            
            reserve(mem, dst.address, dst.size);
            std::copy_n(src.get_data(), src.get_file_size(), &mem->memory[dst.address]);
            
            module->segments.push_back(dst);
        }
    }
    
    std::cout << "Loaded '" << path << "'." << std::endl;
    return true;
}

static void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    EmulatorState *const state = static_cast<EmulatorState *>(user_data);
    const uint8_t *const code = &state->mem.memory[address];
    const size_t buffer_size = GB(4) - address;
    const std::string disassembly = disassemble(&state->disasm, code, buffer_size, address);
    std::cout << std::hex << std::setw(8) << address << std::dec << " " << disassembly << std::endl;
}

static void read_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    std::cout << "READ " << size << " bytes from " << std::hex << address << std::dec << std::endl;
}

static void write_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    std::cout << "WRITE " << size << " bytes to " << std::hex << address << ", value " << value << std::dec << std::endl;
}

static bool run_thread(EmulatorState *state, Address entry_point)
{
    const bool thumb = entry_point & 1;
    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_ARM, thumb ? UC_MODE_THUMB : UC_MODE_ARM, &uc);
    assert(err == UC_ERR_OK);
    
    uc_hook hh = 0;
    err = uc_hook_add(uc, &hh, UC_HOOK_CODE, (void *)&code_hook, state, 1, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_hook_add(uc, &hh, UC_HOOK_MEM_READ, (void *)&read_hook, state, 1, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_hook_add(uc, &hh, UC_HOOK_MEM_WRITE, (void *)&write_hook, state, 1, 0);
    assert(err == UC_ERR_OK);
    
    const size_t stack_size = MB(1);
    const Address stack_bottom = alloc(&state->mem, stack_size);
    const Address stack_top = stack_bottom + stack_size;
    
    err = uc_reg_write(uc, UC_ARM_REG_SP, &stack_top);
    assert(err == UC_ERR_OK);
    
    const size_t bootstrap_size = sizeof(thumb ? bootstrap_thumb : bootstrap_arm);
    const Address bootstrap_address = alloc(&state->mem, bootstrap_size);
    const void *const bootstrap = thumb ? bootstrap_thumb : bootstrap_arm;
    memcpy(&state->mem.memory[bootstrap_address], bootstrap, bootstrap_size);
    
    err = uc_mem_map_ptr(uc, 0, GB(4), UC_PROT_ALL, &state->mem.memory[0]);
    assert(err == UC_ERR_OK);
    
    err = uc_emu_start(uc, bootstrap_address, bootstrap_address + bootstrap_size, 0, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_emu_start(uc, (entry_point >> 1) << 1, 0, 0, 0);
    if (err != UC_ERR_OK)
    {
        std::cerr << "Emulation failed:" << std::endl;
        std::cerr << uc_strerror(err) << std::endl;
        uint64_t pc = 0;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        std::cerr << "PC = " << std::hex << pc << std::dec << std::endl;
        
        return false;
    }
    
    // TODO Free bootstrap and stack.
    
    std::cout << "Emulation succeeded." << std::endl;
    return true;
}

bool emulate(const char *path)
{
    EmulatorState state;
    if (!init(&state))
    {
        return false;
    }
    
    Module module;
    if (!load(&module, &state.mem, path))
    {
        return false;
    }
    
    return run_thread(&state, module.entry_point);
}
