#include "import.h"

static uint64_t timestamp;

// https://github.com/vitasdk/vita-headers/blob/master/include/psp2/ctrl.h
struct SceCtrlData
{
    uint64_t timeStamp = 0;
    uint32_t buttons = 0;
    uint8_t lx = 0;
    uint8_t ly = 0;
    uint8_t rx = 0;
    uint8_t ry = 0;
    uint8_t reserved[16];
};

IMP_SIG(sceCtrlPeekBufferPositive)
{
    const int32_t port = r0;
    SceCtrlData *const data = mem_ptr<SceCtrlData>(r1, mem);
    const int32_t count = r2;
    assert(port == 0);
    assert(data != nullptr);
    assert(count == 1);
    
    memset(data, 0, sizeof(*data));
    data->timeStamp = timestamp++; // TODO Use the real time and units.
    
    return SCE_OK;
}
