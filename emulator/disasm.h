#pragma once

#include <functional>
#include <memory>
#include <string>

struct cs_insn;

typedef std::unique_ptr<cs_insn, std::function<void(cs_insn *)>> InsnPtr;

struct DisasmState
{
    size_t csh;
    InsnPtr insn;
};

bool init(DisasmState *state);
std::string disassemble(DisasmState *state, const uint8_t *code, size_t size, uint64_t address, bool thumb);
