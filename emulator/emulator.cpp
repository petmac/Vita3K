#include "emulator.h"

#include "disasm.h"
#include "imports.h"
#include "mem.h"
#include "module.h"

#include <unicorn/unicorn.h>

#include <assert.h>
#include <iomanip>
#include <iostream>

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

static void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    size_t mode;
    const uc_err err = uc_query(uc, UC_QUERY_MODE, &mode);
    assert(err == UC_ERR_OK);
    
    EmulatorState *const state = static_cast<EmulatorState *>(user_data);
    const uint8_t *const code = mem_ptr<const uint8_t>(static_cast<Address>(address), &state->mem);
    const size_t buffer_size = GB(4) - address;
    const bool thumb = mode & UC_MODE_THUMB;
    const std::string disassembly = disassemble(&state->disasm, code, buffer_size, address, thumb);
    std::cout << std::hex << std::setw(8) << address << std::dec << " " << disassembly << std::endl;
}

static void log_memory_access(const char *type, Address address, int size, int64_t value, const MemState *mem)
{
    const char *const name = mem_name(address, mem);
    std::cout << type << " " << size << " bytes, address 0x" << std::hex << address << " (" << name << "), value 0x" << value << std::dec << std::endl;
}

static void read_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    assert(value == 0);
    
    const MemState *mem = static_cast<const MemState *>(user_data);
    memcpy(&value, mem_ptr<const void>(static_cast<Address>(address), mem), size);
    log_memory_access("Read", static_cast<Address>(address), size, value, mem);
}

static void write_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    const MemState *mem = static_cast<const MemState *>(user_data);
    log_memory_access("Write", static_cast<Address>(address), size, value, mem);
}

static void intr_hook(uc_engine *uc, uint32_t intno, void *user_data)
{
    assert(intno == 2);
    
    uint32_t pc = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    uint32_t nid;
    uc_mem_read(uc, pc + 4, &nid, sizeof(nid));
    
    const char *const name = import_name(nid);
    const char prev_fill = std::cout.fill();
    std::cout << "NID " << std::hex << std::setw(8) << std::setfill('0') << nid << std::setfill(prev_fill) << std::dec << " (" << name << ") called." << std::endl;
    
    ImportFn *const fn = import_fn(nid);
    assert(fn != nullptr);
    if (fn != nullptr)
    {
        (*fn)(uc);
    }
}

static bool run_thread(EmulatorState *state, Address entry_point)
{
    const bool thumb = entry_point & 1;
    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_ARM, thumb ? UC_MODE_THUMB : UC_MODE_ARM, &uc);
    assert(err == UC_ERR_OK);
    
    uc_hook hh = 0;
    err = uc_hook_add(uc, &hh, UC_HOOK_CODE, reinterpret_cast<void *>(&code_hook), state, 1, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_hook_add(uc, &hh, UC_HOOK_MEM_READ, reinterpret_cast<void *>(&read_hook), &state->mem, 1, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_hook_add(uc, &hh, UC_HOOK_MEM_WRITE, reinterpret_cast<void *>(&write_hook), &state->mem, 1, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_hook_add(uc, &hh, UC_HOOK_INTR, reinterpret_cast<void *>(&intr_hook), nullptr, 1, 0);
    assert(err == UC_ERR_OK);
    
    const size_t stack_size = MB(1);
    const Address stack_bottom = alloc(&state->mem, stack_size, "stack");
    const Address stack_top = stack_bottom + stack_size;
    memset(mem_ptr<void>(stack_bottom, &state->mem), 0xcc, stack_size);
    
    err = uc_reg_write(uc, UC_ARM_REG_SP, &stack_top);
    assert(err == UC_ERR_OK);
    
    const size_t bootstrap_size = sizeof(thumb ? bootstrap_thumb : bootstrap_arm);
    const Address bootstrap_address = alloc(&state->mem, bootstrap_size, "bootstrap");
    const void *const bootstrap = thumb ? bootstrap_thumb : bootstrap_arm;
    memcpy(mem_ptr<void>(bootstrap_address, &state->mem), bootstrap, bootstrap_size);
    
    err = uc_mem_map_ptr(uc, 0, GB(4), UC_PROT_ALL, mem_ptr<void>(0, &state->mem));
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
    // TODO Free hooks?
    
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
