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

enum SceGxmAttributeFormat
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_ATTRIBUTE_FORMAT_U8,
    SCE_GXM_ATTRIBUTE_FORMAT_S8,
    SCE_GXM_ATTRIBUTE_FORMAT_U16,
    SCE_GXM_ATTRIBUTE_FORMAT_S16,
    SCE_GXM_ATTRIBUTE_FORMAT_U8N,
    SCE_GXM_ATTRIBUTE_FORMAT_S8N,
    SCE_GXM_ATTRIBUTE_FORMAT_U16N,
    SCE_GXM_ATTRIBUTE_FORMAT_S16N,
    SCE_GXM_ATTRIBUTE_FORMAT_F16,
    SCE_GXM_ATTRIBUTE_FORMAT_F32
};

enum SceGxmColorMask
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_COLOR_MASK_NONE = 0,
    SCE_GXM_COLOR_MASK_A = (1 << 0),
    SCE_GXM_COLOR_MASK_R = (1 << 1),
    SCE_GXM_COLOR_MASK_G = (1 << 2),
    SCE_GXM_COLOR_MASK_B = (1 << 3),
    SCE_GXM_COLOR_MASK_ALL = (SCE_GXM_COLOR_MASK_A | SCE_GXM_COLOR_MASK_R | SCE_GXM_COLOR_MASK_G | SCE_GXM_COLOR_MASK_B)
};

enum SceGxmBlendFactor
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_BLEND_FACTOR_ZERO,
    SCE_GXM_BLEND_FACTOR_ONE,
    SCE_GXM_BLEND_FACTOR_SRC_COLOR,
    SCE_GXM_BLEND_FACTOR_ONE_MINUS_SRC_COLOR,
    SCE_GXM_BLEND_FACTOR_SRC_ALPHA,
    SCE_GXM_BLEND_FACTOR_ONE_MINUS_SRC_ALPHA,
    SCE_GXM_BLEND_FACTOR_DST_COLOR,
    SCE_GXM_BLEND_FACTOR_ONE_MINUS_DST_COLOR,
    SCE_GXM_BLEND_FACTOR_DST_ALPHA,
    SCE_GXM_BLEND_FACTOR_ONE_MINUS_DST_ALPHA,
    SCE_GXM_BLEND_FACTOR_SRC_ALPHA_SATURATE,
    SCE_GXM_BLEND_FACTOR_DST_ALPHA_SATURATE
};

enum SceGxmBlendFunc
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_BLEND_FUNC_NONE,
    SCE_GXM_BLEND_FUNC_ADD,
    SCE_GXM_BLEND_FUNC_SUBTRACT,
    SCE_GXM_BLEND_FUNC_REVERSE_SUBTRACT
};

struct SceGxmBlendInfo
{
    // https://psp2sdk.github.io/structSceGxmBlendInfo.html
    // TODO I don't think this is right.
    SceGxmColorMask colorMask;
    SceGxmBlendFunc colorFunc : 4;
    SceGxmBlendFunc alphaFunc : 4;
    SceGxmBlendFactor colorSrc : 4;
    SceGxmBlendFactor colorDst : 4;
    SceGxmBlendFactor alphaSrc : 4;
    SceGxmBlendFactor alphaDst : 4;
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

struct SceGxmFragmentProgram
{
    // TODO This is an opaque type.
};

struct SceGxmInitializeParams
{
    // This is guesswork based on Napier tutorial 3 PDF.
    uint32_t flags = 0;
    uint32_t displayQueueMaxPendingCount = 0;
    Ptr<SceGxmDisplayQueueCallback> displayQueueCallback;
    uint32_t displayQueueCallbackDataSize = 0;
    uint32_t parameterBufferSize = 0;
};

enum SceGxmMultisampleMode
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_MULTISAMPLE_NONE,
    SCE_GXM_MULTISAMPLE_2X,
    SCE_GXM_MULTISAMPLE_4X
};

enum SceGxmOutputRegisterFormat
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_OUTPUT_REGISTER_FORMAT_DECLARED,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_UCHAR4,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_CHAR4,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_USHORT2,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_SHORT2,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_HALF4,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_HALF2,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_FLOAT2,
    SCE_GXM_OUTPUT_REGISTER_FORMAT_FLOAT
};

enum SceGxmOutputRegisterSize
{
    // https://psp2sdk.github.io/gxm_8h.html
    SCE_GXM_OUTPUT_REGISTER_SIZE_32BIT,
    SCE_GXM_OUTPUT_REGISTER_SIZE_64BIT
};

struct SceGxmProgram
{
    // TODO This is an opaque struct.
    uint32_t unknown[256]; // For debugging/reversing.
};

struct SceGxmProgramParameter
{
    // TODO Reverse engineer SceGxmProgram.
};

struct SceGxmRegisteredProgram
{
    // TODO This is an opaque type.
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

struct SceGxmShaderPatcher
{
};

typedef Ptr<SceGxmRegisteredProgram> SceGxmShaderPatcherId;

// https://psp2sdk.github.io/gxm_8h.html
typedef Ptr<void> SceGxmShaderPatcherHostAllocCallback(Ptr<void> userData, uint32_t size);
typedef void SceGxmShaderPatcherHostFreeCallback(Ptr<void> userData, Ptr<void> mem);
typedef Ptr<void> SceGxmShaderPatcherBufferAllocCallback(Ptr<void> userData, uint32_t size);
typedef void SceGxmShaderPatcherBufferFreeCallback(Ptr<void> userData, Ptr<void> mem);
typedef Ptr<void> SceGxmShaderPatcherUsseAllocCallback(Ptr<void> userData, uint32_t size, Ptr<uint32_t> usseOffset);
typedef void SceGxmShaderPatcherUsseFreeCallback(Ptr<void> userData, Ptr<void> mem);

struct SceGxmShaderPatcherParams
{
    // https://psp2sdk.github.io/structSceGxmShaderPatcherParams.html
    Ptr<void> userData;
    Ptr<SceGxmShaderPatcherHostAllocCallback> hostAllocCallback;
    Ptr<SceGxmShaderPatcherHostFreeCallback> hostFreeCallback;
    Ptr<SceGxmShaderPatcherBufferAllocCallback> bufferAllocCallback;
    Ptr<SceGxmShaderPatcherBufferFreeCallback> bufferFreeCallback;
    Ptr<void> bufferMem;
    uint32_t bufferMemSize;
    Ptr<SceGxmShaderPatcherUsseAllocCallback> vertexUsseAllocCallback;
    Ptr<SceGxmShaderPatcherUsseFreeCallback> vertexUsseFreeCallback;
    Ptr<void> vertexUsseMem;
    uint32_t vertexUsseMemSize;
    uint32_t vertexUsseOffset;
    Ptr<SceGxmShaderPatcherUsseAllocCallback> fragmentUsseAllocCallback;
    Ptr<SceGxmShaderPatcherUsseFreeCallback> fragmentUsseFreeCallback;
    Ptr<void> fragmentUsseMem;
    uint32_t fragmentUsseMemSize;
    uint32_t fragmentUsseOffset;
};

struct SceGxmSyncObject
{    
};

struct SceGxmVertexAttribute
{
    // https://psp2sdk.github.io/structSceGxmVertexAttribute.html
    // TODO This structure might get oddly padded.
    uint16_t streamIndex;
    uint16_t offset;
    SceGxmAttributeFormat format;
    uint8_t componentCount;
    uint16_t regIndex;
};

struct SceGxmVertexProgram
{
    // TODO I think this is an opaque type.
};

struct SceGxmVertexStream
{
    // https://psp2sdk.github.io/structSceGxmVertexStream.html
    uint16_t stride;
    uint16_t indexSource;
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

IMP_SIG(sceGxmProgramCheck)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmProgram *program = Ptr<const SceGxmProgram>(r0).get(&emu->mem);
    assert(program != nullptr);
    
    return SCE_OK;
}

IMP_SIG(sceGxmProgramFindParameterByName)
{
    const SceGxmProgram *const program = Ptr<const SceGxmProgram>(r0).get(&emu->mem);
    const char *const name = Ptr<const char>(r1).get(&emu->mem);
    assert(program != nullptr);
    assert(name != nullptr);
    
    // TODO Reverse engineer SceGxmProgram!
    // TODO This is a SceGxmProgramParameter *.
    return r0;
}

IMP_SIG(sceGxmProgramParameterGetResourceIndex)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmProgramParameter *const parameter = Ptr<const SceGxmProgramParameter>(r0).get(&emu->mem);
    assert(parameter != nullptr);
    
    // TODO Reverse engineer SceGxmProgramParameter.
    return 0;
}

IMP_SIG(sceGxmShaderPatcherCreate)
{
    // https://psp2sdk.github.io/gxm_8h.html
    const SceGxmShaderPatcherParams *const params = Ptr<const SceGxmShaderPatcherParams>(r0).get(&emu->mem);
    Ptr<SceGxmShaderPatcher> *const shaderPatcher = Ptr<Ptr<SceGxmShaderPatcher>>(r1).get(&emu->mem);
    assert(params != nullptr);
    assert(shaderPatcher != nullptr);
    
    *shaderPatcher = Ptr<SceGxmShaderPatcher>(alloc(&emu->mem, sizeof(SceGxmShaderPatcher), __FUNCTION__));
    assert(*shaderPatcher);
    if (!*shaderPatcher)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmShaderPatcherCreateFragmentProgram)
{
    // https://psp2sdk.github.io/gxm_8h.html
    // sceGxmShaderPatcherCreateFragmentProgram (SceGxmShaderPatcher *shaderPatcher, SceGxmShaderPatcherId programId, SceGxmOutputRegisterFormat outputFormat, SceGxmMultisampleMode multisampleMode, const SceGxmBlendInfo *blendInfo, const SceGxmProgram *vertexProgram, SceGxmFragmentProgram **fragmentProgram)
    struct Stack
    {
        Ptr<const SceGxmBlendInfo> blendInfo;
        Ptr<const SceGxmVertexProgram> vertexProgram;
        Ptr<Ptr<SceGxmFragmentProgram>> fragmentProgram;
    };
    
    MemState *const mem = &emu->mem;
    SceGxmShaderPatcher *const shaderPatcher = Ptr<SceGxmShaderPatcher>(r0).get(mem);
    const SceGxmRegisteredProgram *const programId = SceGxmShaderPatcherId(r1).get(mem);
    const SceGxmOutputRegisterFormat outputFormat = static_cast<SceGxmOutputRegisterFormat>(r2);
    const SceGxmMultisampleMode multiesampleMode = static_cast<SceGxmMultisampleMode>(r3);
    const Stack *const stack = sp.cast<const Stack>().get(mem);
    const SceGxmBlendInfo *const blendInfo = stack->blendInfo.get(mem);
    Ptr<SceGxmFragmentProgram> *const fragmentProgram = stack->fragmentProgram.get(mem);
    assert(shaderPatcher != nullptr);
    assert(programId != 0);
    assert(outputFormat == SCE_GXM_OUTPUT_REGISTER_FORMAT_UCHAR4);
    assert(multiesampleMode == SCE_GXM_MULTISAMPLE_NONE);
    assert((blendInfo == nullptr) || (blendInfo != nullptr));
    assert(fragmentProgram != nullptr);
    
    *fragmentProgram = Ptr<SceGxmFragmentProgram>(alloc(mem, sizeof(SceGxmFragmentProgram), __FUNCTION__));
    assert(*fragmentProgram);
    if (!*fragmentProgram)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmShaderPatcherCreateVertexProgram)
{
    // https://psp2sdk.github.io/gxm_8h.html
    struct Stack
    {
        Ptr<const SceGxmVertexStream> streams;
        uint32_t streamCount;
        Ptr<Ptr<SceGxmVertexProgram>> vertexProgram;
    };
    
    MemState *const mem = &emu->mem;
    SceGxmShaderPatcher *const shaderPatcher = Ptr<SceGxmShaderPatcher>(r0).get(mem);
    const SceGxmRegisteredProgram *const programId = SceGxmShaderPatcherId(r1).get(mem);
    const SceGxmVertexAttribute *const attributes = Ptr<const SceGxmVertexAttribute>(r2).get(mem);
    const uint32_t attributeCount = r3;
    const Stack *const stack = sp.cast<const Stack>().get(mem);
    const SceGxmVertexStream *const streams = stack->streams.get(mem);
    Ptr<SceGxmVertexProgram> *const vertexProgram = stack->vertexProgram.get(mem);
    assert(shaderPatcher != nullptr);
    assert(programId != 0);
    assert(attributes != nullptr);
    assert(attributeCount > 0);
    assert(streams != nullptr);
    assert(stack->streamCount > 0);
    assert(vertexProgram != nullptr);
    
    *vertexProgram = Ptr<SceGxmVertexProgram>(alloc(mem, sizeof(SceGxmVertexProgram), __FUNCTION__));
    assert(*vertexProgram);
    if (!*vertexProgram)
    {
        return OUT_OF_MEMORY;
    }
    
    return SCE_OK;
}

IMP_SIG(sceGxmShaderPatcherRegisterProgram)
{
    // https://psp2sdk.github.io/gxm_8h.html
    SceGxmShaderPatcher *const shaderPatcher = Ptr<SceGxmShaderPatcher>(r0).get(&emu->mem);
    const SceGxmProgram *const programHeader = Ptr<const SceGxmProgram>(r1).get(&emu->mem);
    SceGxmShaderPatcherId *const programId = Ptr<SceGxmShaderPatcherId>(r2).get(&emu->mem);
    assert(shaderPatcher != nullptr);
    assert(programHeader != nullptr);
    assert(programId != nullptr);
    
    *programId = SceGxmShaderPatcherId(alloc(&emu->mem, sizeof(SceGxmRegisteredProgram), __FUNCTION__));
    assert(*programId);
    if (!*programId)
    {
        return OUT_OF_MEMORY;
    }
    
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
