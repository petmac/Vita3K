#include "import.h"

static uint64_t timestamp;

// https://github.com/vitasdk/vita-headers/blob/master/include/psp2/touch.h
struct SceTouchReport
{
    uint8_t id;
    uint8_t force;
    uint16_t x;
    uint16_t y;
    uint8_t reserved[8];
    uint16_t info;
};

struct SceTouchData
{
    uint64_t timeStamp = 0;
    uint32_t status = 0;
    uint32_t reportNum = 0;
    SceTouchReport report;
};

IMP_SIG(sceTouchPeek)
{
    const int32_t port = r0;
    SceTouchData *const data = mem_ptr<SceTouchData>(r1, mem);
    const int32_t count = r2;
    assert(port == 0);
    assert(data != nullptr);
    assert(count == 1);
    
    memset(data, 0, sizeof(*data));
    data->timeStamp = timestamp++; // TODO Use the real time and units.
    
    return SCE_OK;
}
