#include "import.h"

struct GxmContext
{
};

enum GxmMemoryAttrib
{
    // https://github.com/xerpi/vitahelloworld/blob/master/draw.c
    SCE_GXM_MEMORY_ATTRIB_READ = 1,
    SCE_GXM_MEMORY_ATTRIB_RW = 3
};

enum SceGxmColorBaseFormat
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_BASE_FORMAT_U8U8U8U8 = 0x00000000,
    SCE_GXM_COLOR_BASE_FORMAT_U8U8U8 = 0x10000000,
    SCE_GXM_COLOR_BASE_FORMAT_U5U6U5 = 0x30000000,
    SCE_GXM_COLOR_BASE_FORMAT_U1U5U5U5 = 0x40000000,
    SCE_GXM_COLOR_BASE_FORMAT_U4U4U4U4 = 0x50000000,
    SCE_GXM_COLOR_BASE_FORMAT_U8U3U3U2 = 0x60000000,
    SCE_GXM_COLOR_BASE_FORMAT_F16 = 0xf0000000,
    SCE_GXM_COLOR_BASE_FORMAT_F16F16 = 0x00800000,
    SCE_GXM_COLOR_BASE_FORMAT_F32 = 0x10800000,
    SCE_GXM_COLOR_BASE_FORMAT_S16 = 0x20800000,
    SCE_GXM_COLOR_BASE_FORMAT_S16S16 = 0x30800000,
    SCE_GXM_COLOR_BASE_FORMAT_U16 = 0x40800000,
    SCE_GXM_COLOR_BASE_FORMAT_U16U16 = 0x50800000,
    SCE_GXM_COLOR_BASE_FORMAT_U2U10U10U10 = 0x60800000,
    SCE_GXM_COLOR_BASE_FORMAT_U8 = 0x80800000,
    SCE_GXM_COLOR_BASE_FORMAT_S8 = 0x90800000,
    SCE_GXM_COLOR_BASE_FORMAT_S5S5U6 = 0xa0800000,
    SCE_GXM_COLOR_BASE_FORMAT_U8U8 = 0xb0800000,
    SCE_GXM_COLOR_BASE_FORMAT_S8S8 = 0xc0800000,
    SCE_GXM_COLOR_BASE_FORMAT_U8S8S8U8 = 0xd0800000,
    SCE_GXM_COLOR_BASE_FORMAT_S8S8S8S8 = 0xe0800000,
    SCE_GXM_COLOR_BASE_FORMAT_F16F16F16F16 = 0x01000000,
    SCE_GXM_COLOR_BASE_FORMAT_F32F32 = 0x11000000,
    SCE_GXM_COLOR_BASE_FORMAT_F11F11F10 = 0x21000000,
    SCE_GXM_COLOR_BASE_FORMAT_SE5M9M9M9 = 0x31000000,
    SCE_GXM_COLOR_BASE_FORMAT_U2F10F10F10 = 0x41000000
};

enum SceGxmColorSwizzle1Mode
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_SWIZZLE1_R = 0x00000000,
    SCE_GXM_COLOR_SWIZZLE1_G = 0x00100000,
    SCE_GXM_COLOR_SWIZZLE1_A = 0x00100000
};

enum SceGxmColorSwizzle2Mode
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_SWIZZLE2_GR = 0x00000000,
    SCE_GXM_COLOR_SWIZZLE2_RG = 0x00100000,
    SCE_GXM_COLOR_SWIZZLE2_RA = 0x00200000,
    SCE_GXM_COLOR_SWIZZLE2_AR = 0x00300000
};

enum SceGxmColorSwizzle3Mode
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_SWIZZLE3_BGR = 0x00000000,
    SCE_GXM_COLOR_SWIZZLE3_RGB = 0x00100000
};

enum SceGxmColorSwizzle4Mode
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_SWIZZLE4_ABGR = 0x00000000,
    SCE_GXM_COLOR_SWIZZLE4_ARGB = 0x00100000,
    SCE_GXM_COLOR_SWIZZLE4_RGBA = 0x00200000,
    SCE_GXM_COLOR_SWIZZLE4_BGRA = 0x00300000
};

enum SceGxmColorFormat
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_FORMAT_U8U8U8U8_ABGR = SCE_GXM_COLOR_BASE_FORMAT_U8U8U8U8 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_U8U8U8U8_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U8U8U8U8 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_U8U8U8U8_RGBA = SCE_GXM_COLOR_BASE_FORMAT_U8U8U8U8 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_U8U8U8U8_BGRA = SCE_GXM_COLOR_BASE_FORMAT_U8U8U8U8 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_U8U8U8_BGR = SCE_GXM_COLOR_BASE_FORMAT_U8U8U8 | SCE_GXM_COLOR_SWIZZLE3_BGR,
    SCE_GXM_COLOR_FORMAT_U8U8U8_RGB = SCE_GXM_COLOR_BASE_FORMAT_U8U8U8 | SCE_GXM_COLOR_SWIZZLE3_RGB,
    SCE_GXM_COLOR_FORMAT_U5U6U5_BGR = SCE_GXM_COLOR_BASE_FORMAT_U5U6U5 | SCE_GXM_COLOR_SWIZZLE3_BGR,
    SCE_GXM_COLOR_FORMAT_U5U6U5_RGB = SCE_GXM_COLOR_BASE_FORMAT_U5U6U5 | SCE_GXM_COLOR_SWIZZLE3_RGB,
    SCE_GXM_COLOR_FORMAT_U1U5U5U5_ABGR = SCE_GXM_COLOR_BASE_FORMAT_U1U5U5U5 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_U1U5U5U5_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U1U5U5U5 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_U5U5U5U1_RGBA = SCE_GXM_COLOR_BASE_FORMAT_U1U5U5U5 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_U5U5U5U1_BGRA = SCE_GXM_COLOR_BASE_FORMAT_U1U5U5U5 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_U4U4U4U4_ABGR = SCE_GXM_COLOR_BASE_FORMAT_U4U4U4U4 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_U4U4U4U4_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U4U4U4U4 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_U4U4U4U4_RGBA = SCE_GXM_COLOR_BASE_FORMAT_U4U4U4U4 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_U4U4U4U4_BGRA = SCE_GXM_COLOR_BASE_FORMAT_U4U4U4U4 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_U8U3U3U2_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U8U3U3U2,
    SCE_GXM_COLOR_FORMAT_F16_R = SCE_GXM_COLOR_BASE_FORMAT_F16 | SCE_GXM_COLOR_SWIZZLE1_R,
    SCE_GXM_COLOR_FORMAT_F16_G = SCE_GXM_COLOR_BASE_FORMAT_F16 | SCE_GXM_COLOR_SWIZZLE1_G,
    SCE_GXM_COLOR_FORMAT_F16F16_GR = SCE_GXM_COLOR_BASE_FORMAT_F16F16 | SCE_GXM_COLOR_SWIZZLE2_GR,
    SCE_GXM_COLOR_FORMAT_F16F16_RG = SCE_GXM_COLOR_BASE_FORMAT_F16F16 | SCE_GXM_COLOR_SWIZZLE2_RG,
    SCE_GXM_COLOR_FORMAT_F32_R = SCE_GXM_COLOR_BASE_FORMAT_F32 | SCE_GXM_COLOR_SWIZZLE1_R,
    SCE_GXM_COLOR_FORMAT_S16_R = SCE_GXM_COLOR_BASE_FORMAT_S16 | SCE_GXM_COLOR_SWIZZLE1_R,
    SCE_GXM_COLOR_FORMAT_S16_G = SCE_GXM_COLOR_BASE_FORMAT_S16 | SCE_GXM_COLOR_SWIZZLE1_G,
    SCE_GXM_COLOR_FORMAT_S16S16_GR = SCE_GXM_COLOR_BASE_FORMAT_S16S16 | SCE_GXM_COLOR_SWIZZLE2_GR,
    SCE_GXM_COLOR_FORMAT_S16S16_RG = SCE_GXM_COLOR_BASE_FORMAT_S16S16 | SCE_GXM_COLOR_SWIZZLE2_RG,
    SCE_GXM_COLOR_FORMAT_U16_R = SCE_GXM_COLOR_BASE_FORMAT_U16 | SCE_GXM_COLOR_SWIZZLE1_R,
    SCE_GXM_COLOR_FORMAT_U16_G = SCE_GXM_COLOR_BASE_FORMAT_U16 | SCE_GXM_COLOR_SWIZZLE1_G,
    SCE_GXM_COLOR_FORMAT_U16U16_GR = SCE_GXM_COLOR_BASE_FORMAT_U16U16 | SCE_GXM_COLOR_SWIZZLE2_GR,
    SCE_GXM_COLOR_FORMAT_U16U16_RG = SCE_GXM_COLOR_BASE_FORMAT_U16U16 | SCE_GXM_COLOR_SWIZZLE2_RG,
    SCE_GXM_COLOR_FORMAT_U2U10U10U10_ABGR = SCE_GXM_COLOR_BASE_FORMAT_U2U10U10U10 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_U2U10U10U10_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U2U10U10U10 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_U10U10U10U2_RGBA = SCE_GXM_COLOR_BASE_FORMAT_U2U10U10U10 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_U10U10U10U2_BGRA = SCE_GXM_COLOR_BASE_FORMAT_U2U10U10U10 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_U8_R = SCE_GXM_COLOR_BASE_FORMAT_U8 | SCE_GXM_COLOR_SWIZZLE1_R,
    SCE_GXM_COLOR_FORMAT_U8_A = SCE_GXM_COLOR_BASE_FORMAT_U8 | SCE_GXM_COLOR_SWIZZLE1_A,
    SCE_GXM_COLOR_FORMAT_S8_R = SCE_GXM_COLOR_BASE_FORMAT_S8 | SCE_GXM_COLOR_SWIZZLE1_R,
    SCE_GXM_COLOR_FORMAT_S8_A = SCE_GXM_COLOR_BASE_FORMAT_S8 | SCE_GXM_COLOR_SWIZZLE1_A,
    SCE_GXM_COLOR_FORMAT_U6S5S5_BGR = SCE_GXM_COLOR_BASE_FORMAT_S5S5U6 | SCE_GXM_COLOR_SWIZZLE3_BGR,
    SCE_GXM_COLOR_FORMAT_S5S5U6_RGB = SCE_GXM_COLOR_BASE_FORMAT_S5S5U6 | SCE_GXM_COLOR_SWIZZLE3_RGB,
    SCE_GXM_COLOR_FORMAT_U8U8_GR = SCE_GXM_COLOR_BASE_FORMAT_U8U8 | SCE_GXM_COLOR_SWIZZLE2_GR,
    SCE_GXM_COLOR_FORMAT_U8U8_RG = SCE_GXM_COLOR_BASE_FORMAT_U8U8 | SCE_GXM_COLOR_SWIZZLE2_RG,
    SCE_GXM_COLOR_FORMAT_U8U8_RA = SCE_GXM_COLOR_BASE_FORMAT_U8U8 | SCE_GXM_COLOR_SWIZZLE2_RA,
    SCE_GXM_COLOR_FORMAT_U8U8_AR = SCE_GXM_COLOR_BASE_FORMAT_U8U8 | SCE_GXM_COLOR_SWIZZLE2_AR,
    SCE_GXM_COLOR_FORMAT_S8S8_GR = SCE_GXM_COLOR_BASE_FORMAT_S8S8 | SCE_GXM_COLOR_SWIZZLE2_GR,
    SCE_GXM_COLOR_FORMAT_S8S8_RG = SCE_GXM_COLOR_BASE_FORMAT_S8S8 | SCE_GXM_COLOR_SWIZZLE2_RG,
    SCE_GXM_COLOR_FORMAT_S8S8_RA = SCE_GXM_COLOR_BASE_FORMAT_S8S8 | SCE_GXM_COLOR_SWIZZLE2_RA,
    SCE_GXM_COLOR_FORMAT_S8S8_AR = SCE_GXM_COLOR_BASE_FORMAT_S8S8 | SCE_GXM_COLOR_SWIZZLE2_AR,
    SCE_GXM_COLOR_FORMAT_U8S8S8U8_ABGR = SCE_GXM_COLOR_BASE_FORMAT_U8S8S8U8 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_U8U8S8S8_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U8S8S8U8 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_U8S8S8U8_RGBA = SCE_GXM_COLOR_BASE_FORMAT_U8S8S8U8 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_S8S8U8U8_BGRA = SCE_GXM_COLOR_BASE_FORMAT_U8S8S8U8 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_S8S8S8S8_ABGR = SCE_GXM_COLOR_BASE_FORMAT_S8S8S8S8 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_S8S8S8S8_ARGB = SCE_GXM_COLOR_BASE_FORMAT_S8S8S8S8 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_S8S8S8S8_RGBA = SCE_GXM_COLOR_BASE_FORMAT_S8S8S8S8 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_S8S8S8S8_BGRA = SCE_GXM_COLOR_BASE_FORMAT_S8S8S8S8 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_F16F16F16F16_ABGR = SCE_GXM_COLOR_BASE_FORMAT_F16F16F16F16 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_F16F16F16F16_ARGB = SCE_GXM_COLOR_BASE_FORMAT_F16F16F16F16 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_F16F16F16F16_RGBA = SCE_GXM_COLOR_BASE_FORMAT_F16F16F16F16 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_F16F16F16F16_BGRA = SCE_GXM_COLOR_BASE_FORMAT_F16F16F16F16 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_F32F32_GR = SCE_GXM_COLOR_BASE_FORMAT_F32F32 | SCE_GXM_COLOR_SWIZZLE2_GR,
    SCE_GXM_COLOR_FORMAT_F32F32_RG = SCE_GXM_COLOR_BASE_FORMAT_F32F32 | SCE_GXM_COLOR_SWIZZLE2_RG,
    SCE_GXM_COLOR_FORMAT_F10F11F11_BGR = SCE_GXM_COLOR_BASE_FORMAT_F11F11F10 | SCE_GXM_COLOR_SWIZZLE3_BGR,
    SCE_GXM_COLOR_FORMAT_F11F11F10_RGB = SCE_GXM_COLOR_BASE_FORMAT_F11F11F10 | SCE_GXM_COLOR_SWIZZLE3_RGB,
    SCE_GXM_COLOR_FORMAT_SE5M9M9M9_BGR = SCE_GXM_COLOR_BASE_FORMAT_SE5M9M9M9 | SCE_GXM_COLOR_SWIZZLE3_BGR,
    SCE_GXM_COLOR_FORMAT_SE5M9M9M9_RGB = SCE_GXM_COLOR_BASE_FORMAT_SE5M9M9M9 | SCE_GXM_COLOR_SWIZZLE3_RGB,
    SCE_GXM_COLOR_FORMAT_U2F10F10F10_ABGR = SCE_GXM_COLOR_BASE_FORMAT_U2F10F10F10 | SCE_GXM_COLOR_SWIZZLE4_ABGR,
    SCE_GXM_COLOR_FORMAT_U2F10F10F10_ARGB = SCE_GXM_COLOR_BASE_FORMAT_U2F10F10F10 | SCE_GXM_COLOR_SWIZZLE4_ARGB,
    SCE_GXM_COLOR_FORMAT_F10F10F10U2_RGBA = SCE_GXM_COLOR_BASE_FORMAT_U2F10F10F10 | SCE_GXM_COLOR_SWIZZLE4_RGBA,
    SCE_GXM_COLOR_FORMAT_F10F10F10U2_BGRA = SCE_GXM_COLOR_BASE_FORMAT_U2F10F10F10 | SCE_GXM_COLOR_SWIZZLE4_BGRA,
    SCE_GXM_COLOR_FORMAT_A8B8G8R8 = SCE_GXM_COLOR_FORMAT_U8U8U8U8_ABGR,
    SCE_GXM_COLOR_FORMAT_A8R8G8B8 = SCE_GXM_COLOR_FORMAT_U8U8U8U8_ARGB,
    SCE_GXM_COLOR_FORMAT_R5G6B5 = SCE_GXM_COLOR_FORMAT_U5U6U5_RGB,
    SCE_GXM_COLOR_FORMAT_A1R5G5B5 = SCE_GXM_COLOR_FORMAT_U1U5U5U5_ARGB,
    SCE_GXM_COLOR_FORMAT_A4R4G4B4 = SCE_GXM_COLOR_FORMAT_U4U4U4U4_ARGB,
    SCE_GXM_COLOR_FORMAT_A8 = SCE_GXM_COLOR_FORMAT_U8_A
};

struct SceGxmTexture
{
    // https://psp2sdk.github.io/structSceGxmTexture.html
    uint32_t controlWords[4];
};

struct SceGxmColorSurface
{
    // https://psp2sdk.github.io/structSceGxmColorSurface.html
    uint32_t pbeSidebandWord;
    uint32_t pbeEmitWords[6];
    uint32_t outputRegisterSize;
    SceGxmTexture backgroundTex;
};

enum SceGxmColorSurfaceScaleMode
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_SURFACE_SCALE_NONE,
    SCE_GXM_COLOR_SURFACE_SCALE_MSAA_DOWNSCALE
};

enum SceGxmColorSurfaceType
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_SURFACE_LINEAR = 0x00000000,
    SCE_GXM_COLOR_SURFACE_TILED = 0x04000000,
    SCE_GXM_COLOR_SURFACE_SWIZZLED = 0x08000000
};

struct SceGxmContextParams
{
    // https://psp2sdk.github.io/structSceGxmContextParams.html
    Ptr<void> hostMem;
    uint32_t hostMemSize;
    Ptr<void> vdmRingBufferMem;
    uint32_t vdmRingBufferMemSize;
    Ptr<void> vertexRingBufferMem;
    uint32_t vertexRingBufferMemSize;
    Ptr<void> fragmentRingBufferMem;
    uint32_t fragmentRingBufferMemSize;
    Ptr<void> fragmentUsseRingBufferMem;
    uint32_t fragmentUsseRingBufferMemSize;
    uint32_t fragmentUsseRingBufferOffset;
};

enum SceGxmDepthStencilFormat
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_DEPTH_STENCIL_FORMAT_DF32 = 0x00044000,
    SCE_GXM_DEPTH_STENCIL_FORMAT_S8 = 0x00022000,
    SCE_GXM_DEPTH_STENCIL_FORMAT_DF32_S8 = 0x00066000,
    SCE_GXM_DEPTH_STENCIL_FORMAT_S8D24 = 0x01266000,
    SCE_GXM_DEPTH_STENCIL_FORMAT_D16 = 0x02444000
};

struct SceGxmDepthStencilSurface
{
    // https://psp2sdk.github.io/structSceGxmDepthStencilSurface.html
    uint32_t zlsControl;
    Ptr<void> depthData;
    Ptr<void> stencilData;
    float backgroundDepth;
    uint32_t backgroundControl;
};

enum SceGxmDepthStencilSurfaceType
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_DEPTH_STENCIL_SURFACE_LINEAR = 0x00000000,
    SCE_GXM_DEPTH_STENCIL_SURFACE_TILED = 0x00011000
};

// https://psp2sdk.github.io/gxm_8h.html
typedef void SceGxmDisplayQueueCallback(Ptr<const void> callbackData);

struct SceGxmInitializeParams
{
    // This is guesswork based on Napier tutorial 3 PDF.
    uint32_t flags = 0;
    uint32_t displayQueueMaxPendingCount = 0;
    Ptr<SceGxmDisplayQueueCallback> displayQueueCallback;
    uint32_t displayQueueCallbackDataSize = 0;
    uint32_t parameterBufferSize = 0;
};

enum SceGxmOutputRegisterSize
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_OUTPUT_REGISTER_SIZE_32BIT,
    SCE_GXM_OUTPUT_REGISTER_SIZE_64BIT
};

struct SceGxmRenderTarget
{
};

struct SceGxmRenderTargetParams
{
    // Napier tutorial 3.
    // https://psp2sdk.github.io/structSceGxmRenderTargetParams.html
    uint32_t flags = 0;
    uint16_t width = 0;
    uint16_t height = 0;
    uint16_t scenesPerFrame = 1;
    uint16_t multisampleMode = 0;
    uint32_t multisampleLocations = 0;
    SceUID driverMemBlock = SCE_UID_INVALID_UID;
};

struct SceGxmSyncObject
{    
};

IMP_SIG(sceGxmColorSurfaceInit)
{
    // https://psp2sdk.github.io/gxm_8h.html
    struct Stack
    {
        SceGxmOutputRegisterSize outputRegisterSize;
        uint32_t width;
        uint32_t height;
        uint32_t strideInPixels;
        Ptr<void> data;
    };
    
    SceGxmColorSurface *const surface = Ptr<SceGxmColorSurface>(r0).get(&emu->mem);
    SceGxmColorFormat colorFormat = static_cast<SceGxmColorFormat>(r1);
    SceGxmColorSurfaceType surfaceType = static_cast<SceGxmColorSurfaceType>(r2);
    SceGxmColorSurfaceScaleMode scaleMode = static_cast<SceGxmColorSurfaceScaleMode>(r3);
    const Stack *const stack = sp.cast<const Stack>().get(&emu->mem);
    void *const data = stack->data.get(&emu->mem);
    assert(surface != nullptr);
    assert(colorFormat == SCE_GXM_COLOR_FORMAT_A8B8G8R8);
    assert(surfaceType == SCE_GXM_COLOR_SURFACE_LINEAR);
    assert(scaleMode == SCE_GXM_COLOR_SURFACE_SCALE_NONE);
    assert(stack->outputRegisterSize == SCE_GXM_OUTPUT_REGISTER_SIZE_32BIT);
    assert(stack->width > 0);
    assert(stack->height > 0);
    assert(stack->strideInPixels > 0);
    assert(data != nullptr);
    
    // TODO Initialise.
    memset(surface, 0, sizeof(*surface));
    surface->outputRegisterSize = stack->outputRegisterSize;
    
    return SCE_OK;
}

IMP_SIG(sceGxmCreateContext)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmContextParams *const params = Ptr<const SceGxmContextParams>(r0).get(&emu->mem);
    Ptr<GxmContext> *const context = Ptr<Ptr<GxmContext>>(r1).get(&emu->mem);
    assert(params != nullptr);
    assert(context != nullptr);
    
    *context = Ptr<GxmContext>(alloc(&emu->mem, sizeof(GxmContext), __FUNCTION__));
    if (!*context)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmCreateRenderTarget)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmRenderTargetParams *const params = Ptr<const SceGxmRenderTargetParams>(r0).get(&emu->mem);
    Ptr<SceGxmRenderTarget> *const renderTarget = Ptr<Ptr<SceGxmRenderTarget>>(r1).get(&emu->mem);
    assert(params != nullptr);
    assert(renderTarget != nullptr);
    
    *renderTarget = Ptr<SceGxmRenderTarget>(alloc(&emu->mem, sizeof(SceGxmRenderTarget), __FUNCTION__));
    if (!*renderTarget)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmDepthStencilSurfaceInit)
{
    // https://psp2sdk.github.io/gxm_8h.html
    struct Stack
    {
        Ptr<void> depthData;
        Ptr<void> stencilData;
    };
    
    SceGxmDepthStencilSurface *const surface = Ptr<SceGxmDepthStencilSurface>(r0).get(&emu->mem);
    const SceGxmDepthStencilFormat depthStencilFormat = static_cast<SceGxmDepthStencilFormat>(r1);
    const SceGxmDepthStencilSurfaceType surfaceType = static_cast<SceGxmDepthStencilSurfaceType>(r2);
    const uint32_t strideInSamples = r3;
    const Stack *const stack = sp.cast<const Stack>().get(&emu->mem);
    void *const depthData = stack->depthData.get(&emu->mem);
    void *const stencilData = stack->stencilData.get(&emu->mem);
    assert(surface != nullptr);
    assert(depthStencilFormat == SCE_GXM_DEPTH_STENCIL_FORMAT_S8D24);
    assert(surfaceType == SCE_GXM_DEPTH_STENCIL_SURFACE_TILED);
    assert(strideInSamples > 0);
    assert(depthData != nullptr);
    assert(stencilData == nullptr);
    
    // TODO What to do here?
    memset(surface, 0, sizeof(*surface));
    surface->depthData = stack->depthData;
    surface->stencilData = stack->stencilData;
    
    return SCE_OK;
}

IMP_SIG(sceGxmInitialize)
{
    const SceGxmInitializeParams *const params = Ptr<const SceGxmInitializeParams>(r0).get(&emu->mem);
    (void)params;
    
    // TODO Implement.
    return SCE_OK;
}

IMP_SIG(sceGxmMapFragmentUsseMemory)
{
    void *const base = Ptr<void>(r0).get(&emu->mem);
    const uint32_t size = r1;
    uint32_t *const offset = Ptr<uint32_t>(r2).get(&emu->mem);
    assert(base != nullptr);
    assert(size > 0);
    assert(offset != nullptr);
    
    // TODO What should this be?
    *offset = r0;
    
    return SCE_OK;
}

IMP_SIG(sceGxmMapMemory)
{
    const void *const address = Ptr<const void>(r0).get(&emu->mem);
    const size_t size = r1;
    const GxmMemoryAttrib attributes = static_cast<GxmMemoryAttrib>(r2);
    assert(address != nullptr);
    assert(size > 0);
    assert((attributes == SCE_GXM_MEMORY_ATTRIB_READ) || (attributes == SCE_GXM_MEMORY_ATTRIB_RW));
    
    return SCE_OK;
}

IMP_SIG(sceGxmMapVertexUsseMemory)
{
    void *const base = Ptr<void>(r0).get(&emu->mem);
    const uint32_t size = r1;
    uint32_t *const offset = Ptr<uint32_t>(r2).get(&emu->mem);
    assert(base != nullptr);
    assert(size > 0);
    assert(offset != nullptr);
    
    // TODO What should this be?
    *offset = r0;
    
    return SCE_OK;
}

IMP_SIG(sceGxmSyncObjectCreate)
{
    Ptr<SceGxmSyncObject> *const syncObject = Ptr<Ptr<SceGxmSyncObject>>(r0).get(&emu->mem);
    assert(syncObject != nullptr);
    
    *syncObject = Ptr<SceGxmSyncObject>(alloc(&emu->mem, sizeof(SceGxmSyncObject), __FUNCTION__));
    if (!*syncObject)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmTerminate)
{
    return SCE_OK;
}

IMP_SIG(sceGxmUnmapMemory)
{
    const void *const address = Ptr<const void>(r0).get(&emu->mem);
    assert(address != nullptr);
    
    return SCE_OK;
}
