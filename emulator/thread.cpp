#include "thread.h"

#include "call.h"
#include "emulator.h"
#include "imports.h"

#include <unicorn/unicorn.h>

#include <assert.h>
#include <iomanip>
#include <iostream>

static const bool LOG_CODE = false;
static const bool LOG_MEM_ACCESS = false;
static const bool LOG_IMPORT_CALLS = false;

struct InterruptParams
{
    EmulatorState *emulator = nullptr;
};

static void code_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    size_t mode;
    const uc_err err = uc_query(uc, UC_QUERY_MODE, &mode);
    assert(err == UC_ERR_OK);
    
    EmulatorState *const state = static_cast<EmulatorState *>(user_data);
    const uint8_t *const code = Ptr<const uint8_t>(static_cast<Address>(address)).get(&state->mem);
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
    memcpy(&value, Ptr<const void>(static_cast<Address>(address)).get(mem), size);
    log_memory_access("Read", static_cast<Address>(address), size, value, mem);
}

static void write_hook(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    const MemState *mem = static_cast<const MemState *>(user_data);
    log_memory_access("Write", static_cast<Address>(address), size, value, mem);
}

static void call_nid(uc_engine *uc, Address pc, InterruptParams *params)
{
    uint32_t nid;
    uc_mem_read(uc, pc + 4, &nid, sizeof(nid));
    
    if (LOG_IMPORT_CALLS)
    {
        const char *const name = import_name(nid);
        const char prev_fill = std::cout.fill();
        std::cout << "NID " << std::hex << std::setw(8) << std::setfill('0') << nid << std::setfill(prev_fill) << std::dec << " (" << name << ") called." << std::endl;
    }
    
    ImportFn *const fn = import_fn(nid);
    assert(fn != nullptr);
    if (fn != nullptr)
    {
        const Args args = read_args(uc);
        const uint32_t result = (*fn)(args.r0, args.r1, args.r2, args.r3, args.sp, uc, params->emulator);
        write_result(uc, result);
    }
}

static void handle_svc(uc_engine *uc, Address pc, InterruptParams *params, uint32_t imm)
{
    switch (imm)
    {
        case 0:
            call_nid(uc, pc, params);
            break;
            
        case 1:
            uc_emu_stop(uc);
            break;
            
        default:
            assert(!"Unhandled SVC immediate value.");
            uc_emu_stop(uc);
            break;
    }
}

static void intr_hook(uc_engine *uc, uint32_t intno, void *user_data)
{
    assert(intno == 2);
    
    InterruptParams *const params = static_cast<InterruptParams *>(user_data);
    
    uint32_t cpsr = 0;
    uc_err err = uc_reg_read(uc, UC_ARM_REG_CPSR, &cpsr);
    assert(err == UC_ERR_OK);
    
    uint32_t pc = 0;
    err = uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    assert(err == UC_ERR_OK);
    
    const bool thumb = (cpsr >> 5) & 1;
    if (thumb)
    {
        const Address svc_address = pc - 2;
        uint16_t svc_instruction = 0;
        err = uc_mem_read(uc, svc_address, &svc_instruction, sizeof(svc_instruction));
        assert(err == UC_ERR_OK);
        const uint8_t imm = svc_instruction & 0xff;
        handle_svc(uc, pc, params, imm);
    }
    else
    {
        const Address svc_address = pc - 4;
        uint32_t svc_instruction = 0;
        err = uc_mem_read(uc, svc_address, &svc_instruction, sizeof(svc_instruction));
        assert(err == UC_ERR_OK);
        const uint32_t imm = svc_instruction & 0xffffff;
        handle_svc(uc, pc, params, imm);
    }
}

bool run_thread(EmulatorState *state, Ptr<const void> entry_point)
{
    InterruptParams interrupt_params;
    interrupt_params.emulator = state;
    
    const bool thumb = entry_point.address() & 1;
    uc_engine *uc = nullptr;
    uc_err err = uc_open(UC_ARCH_ARM, thumb ? UC_MODE_THUMB : UC_MODE_ARM, &uc);
    assert(err == UC_ERR_OK);
    
    uc_hook hh = 0;
    if (LOG_CODE)
    {
        err = uc_hook_add(uc, &hh, UC_HOOK_CODE, reinterpret_cast<void *>(&code_hook), state, 1, 0);
        assert(err == UC_ERR_OK);
    }
    
    if (LOG_MEM_ACCESS)
    {
        err = uc_hook_add(uc, &hh, UC_HOOK_MEM_READ, reinterpret_cast<void *>(&read_hook), &state->mem, 1, 0);
        assert(err == UC_ERR_OK);
        
        err = uc_hook_add(uc, &hh, UC_HOOK_MEM_WRITE, reinterpret_cast<void *>(&write_hook), &state->mem, 1, 0);
        assert(err == UC_ERR_OK);
    }
    
    err = uc_hook_add(uc, &hh, UC_HOOK_INTR, reinterpret_cast<void *>(&intr_hook), &interrupt_params, 1, 0);
    assert(err == UC_ERR_OK);
    
    const size_t stack_size = MB(1);
    const Address stack_bottom = alloc(&state->mem, stack_size, "stack");
    const Address stack_top = stack_bottom + stack_size;
    memset(Ptr<void>(stack_bottom).get(&state->mem), 0xcc, stack_size);
    
    err = uc_reg_write(uc, UC_ARM_REG_SP, &stack_top);
    assert(err == UC_ERR_OK);
    
    err = uc_mem_map_ptr(uc, 0, GB(4), UC_PROT_ALL, &state->mem.memory[0]);
    assert(err == UC_ERR_OK);
    
    const Ptr<const void> bootstrap_address = thumb ? state->bootstrap_thumb : state->bootstrap_arm;
    err = uc_emu_start(uc, bootstrap_address.address(), 0, 0, 0);
    assert(err == UC_ERR_OK);
    
    err = uc_emu_start(uc, (entry_point.address() >> 1) << 1, 0, 0, 0);
    if (err != UC_ERR_OK)
    {
        std::cerr << "Emulation failed:" << std::endl;
        std::cerr << uc_strerror(err) << std::endl;
        uint64_t pc = 0;
        uc_reg_read(uc, UC_ARM_REG_PC, &pc);
        std::cerr << "PC = " << std::hex << pc << std::dec << std::endl;
        
        uc_close(uc);
        uc = nullptr;
        
        return false;
    }
    
    // TODO Free stack.
    // TODO Free hooks?
    
    uc_close(uc);
    uc = nullptr;
    
    std::cout << "Emulation succeeded." << std::endl;
    return true;
}
