#include "relocation.h"

#include "mem.h"

#include <assert.h>

enum Code
{
    None = 0,
    Abs32 = 2,
    Rel32 = 3,
    ThumbCall = 10,
    Call = 28,
    Jump24 = 29,
    Target1 = 38,
    V4BX = 40,
    Target2 = 41,
    Prel31 = 42,
    MovwAbsNc = 43,
    MovtAbs = 44,
    ThumbMovwAbsNc = 47,
    ThumbMovtAbs = 48
};

struct Entry
{
    uint8_t is_short : 4;
    uint8_t symbol_segment : 4;
    uint8_t code;
};

struct ShortEntry : Entry
{
    uint16_t data_segment : 4;
    uint16_t offset_lo : 12;
    uint32_t offset_hi : 20;
    uint32_t addend : 12;
};

struct LongEntry : Entry
{
    uint16_t data_segment : 4;
    uint16_t code2 : 8;
    uint16_t dist2 : 4;
    uint32_t addend;
    uint32_t offset;
};

static_assert(sizeof(ShortEntry) == 8, "Short entry has incorrect size.");
static_assert(sizeof(LongEntry) == 12, "Long entry has incorrect size.");

static void write(void *data, uint32_t value)
{
    memcpy(data, &value, sizeof(value));
}

static void write_masked(void *data, uint32_t symbol, uint32_t mask)
{
    write(data, symbol & mask);
}

static void write_thumb_call(void *data, uint32_t symbol)
{
    // This is cribbed from UVLoader, but I used bitfields to get rid of some shifting and masking.
    struct Upper
    {
        uint16_t imm10 : 10;
        uint16_t sign : 1;
        uint16_t ignored : 5;
    };
    
    struct Lower
    {
        uint16_t imm11 : 11;
        uint16_t j2 : 1;
        uint16_t unknown : 1;
        uint16_t j1 : 1;
        uint16_t unknown2 : 2;
    };
    
    struct Pair
    {
        Upper upper;
        Lower lower;
    };
    
    static_assert(sizeof(Pair) == 4, "Incorrect size.");
    
    Pair *const pair = static_cast<Pair *>(data);
    pair->lower.imm11 = symbol >> 1;
    pair->upper.imm10 = symbol >> 12;
    pair->upper.sign = symbol >> 24;
    pair->lower.j2 = pair->upper.sign ^ ((~symbol) >> 22);
    pair->lower.j1 = pair->upper.sign ^ ((~symbol) >> 23);
}

static void write_thumb_mov_abs(void *data, uint16_t symbol)
{
    // This is cribbed from UVLoader, but I used bitfields to get rid of some shifting and masking.
    struct Upper
    {
        uint16_t imm4 : 4;
        uint16_t ignored1 : 6;
        uint16_t i : 1;
        uint16_t ignored2 : 5;
    };
    
    struct Lower
    {
        uint16_t imm8 : 8;
        uint16_t ignored1 : 4;
        uint16_t imm3 : 3;
        uint16_t ignored2 : 1;
    };
    
    struct Pair
    {
        Upper upper;
        Lower lower;
    };
    
    static_assert(sizeof(Pair) == 4, "Incorrect size.");
    
    Pair *const pair = static_cast<Pair *>(data);
    pair->lower.imm8 = symbol;
    pair->lower.imm3 = symbol >> 8;
    pair->upper.i = symbol >> 11;
    pair->upper.imm4 = symbol >> 12;
}

static void relocate(void *data, Code code, uint32_t s, uint32_t a, uint32_t p)
{
    switch (code)
    {
        case None:
            break;
            
        case Abs32:
        case Target1:
            write(data, s + a);
            break;
            
        case Rel32:
            write(data, s + a - p);
            break;
            
        case Prel31:
            write_masked(data, s + a - p, INT32_MAX);
            break;
            
        case ThumbCall:
            write_thumb_call(data, s + a - p);
            break;
            
        case ThumbMovwAbsNc:
            write_thumb_mov_abs(data, s + a);
            break;
            
        case ThumbMovtAbs:
            write_thumb_mov_abs(data, (s + a) >> 16);
            break;
            
        default:
            assert(!"Unhandled relocation code.");
            break;
    }
}

void relocate(const void *entries, size_t size, const SegmentAddresses &segments, const MemState *mem)
{
    const void *const end = static_cast<const uint8_t *>(entries) + size;
    const Entry *entry = static_cast<const Entry *>(entries);
    while (entry < end)
    {
        assert(entry->is_short == 0);
        assert(entry->symbol_segment != 0xf);
        
        const Address symbol_start = segments.find(entry->symbol_segment)->second;
        const Address s = (entry->symbol_segment == 0xf) ? 0 : symbol_start;
        
        if (entry->is_short)
        {
            const ShortEntry *const short_entry = static_cast<const ShortEntry *>(entry);
            entry = short_entry + 1;
        }
        else
        {
            const LongEntry *const long_entry = static_cast<const LongEntry *>(entry);
            assert(long_entry->code2 == 0);
            
            const Address segment_start = segments.find(long_entry->data_segment)->second;
            const Address p = segment_start + long_entry->offset;
            const Address a = long_entry->addend;
            relocate(mem_ptr<uint32_t>(p, mem), static_cast<Code>(entry->code), s, a, p);
            
            entry = long_entry + 1;
        }
    }
}
