#include "disasm.h"

#include <capstone.h>

#include <sstream>

static void delete_insn(cs_insn *insn)
{
    if (insn != nullptr)
    {
        cs_free(insn, 1);
    }
}

bool init(DisasmState *state)
{
    cs_err err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &state->csh);
    if (err != CS_ERR_OK)
    {
        return false;
    }
    
    cs_option(state->csh, CS_OPT_SKIPDATA, CS_OPT_ON);
    
    state->insn = InsnPtr(cs_malloc(state->csh), delete_insn);
    if (!state->insn)
    {
        return false;
    }
    
    return true;
}

std::string disassemble(DisasmState *state, const uint8_t *code, size_t size, uint64_t address)
{
    const bool success = cs_disasm_iter(state->csh, &code, &size, &address, state->insn.get());
    
    std::ostringstream out;
    out << state->insn->mnemonic << " " << state->insn->op_str;
    if (!success)
    {
        const cs_err err = cs_errno(state->csh);
        out << " (" << cs_strerror(err) << ")";
    }
    
    return out.str();
}
