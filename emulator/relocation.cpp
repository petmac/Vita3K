#include "relocation.h"

#include "mem.h"

#include <assert.h>
#include <stdint.h>

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

static void relocate(uint32_t *data, uint32_t symbol, uint32_t mask)
{
    *data = (*data & ~mask) | (symbol & mask);
}

static void relocate(uint32_t *data, Code code, uint32_t s, uint32_t a, uint32_t p)
{
    switch (code)
    {
        case None:
            break;
            
        case Abs32:
        case Target1:
            *data = s + a;
            break;
            
        case Rel32:
            *data = s + a - p;
            break;
            
        case Prel31:
            relocate(data, s + a - p, 0x7fffffff);
            break;
            
        case ThumbCall:
            relocate(data, s + a - p, 0x1fffffe);
            break;
            
        case ThumbMovwAbsNc:
            // TODO This is wrong.
            relocate(data, s + a, 0xffff);
            break;
            
        case ThumbMovtAbs:
            // TODO This is wrong.
            relocate(data, s + a, 0xffff0000);
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
