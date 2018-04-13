#pragma once

#include <rpcs3/BitField.h>

#include <cstdint>

struct SceGxmProgram {
    std::uint32_t magic; // should be "GXP\0"

    std::uint8_t major_version; //min 1
    std::uint8_t minor_version; //min 4
    std::uint16_t unk6; //maybe padding

    std::uint32_t size; //size of file - ignoring padding bytes at the end after SceGxmProgramParameter table
    std::uint32_t unkC;

    std::uint16_t unk10;
    std::uint8_t unk12;
    std::uint8_t unk13;

    std::uint8_t unk14; //related to profile_type
    std::uint8_t unk15;
    std::uint8_t unk16;
    std::uint8_t unk17;

    std::uint32_t unk18;
    std::uint32_t unk1C;

    std::uint32_t unk20;
    std::uint32_t parameter_count;
    std::uint32_t parameters_offset; // Number of bytes from the start of this field to the first parameter.
    std::uint32_t unk2C;

    std::uint16_t primary_reg_count; // (PAs)
    std::uint16_t secondary_reg_count; // (SAs)
    std::uint16_t temp_reg_count1; //not sure // - verify this
    std::uint16_t unk36;
    std::uint16_t temp_reg_count2; //not sure // - verify this
    std::uint16_t unk3A; //some item count?

    std::uint32_t unk3C;

    std::uint32_t maybe_asm_offset;
    std::uint32_t unk44;

    std::uint32_t unk_offset_48;
    std::uint32_t unk_offset_4C;

    std::uint32_t unk_50; //usually zero?
    std::uint32_t unk_54; //usually zero?
    std::uint32_t unk_58; //usually zero?
    std::uint32_t unk_5C; //usually zero?

    std::uint32_t unk_60;
    std::uint32_t unk_64;
    std::uint32_t unk_68;
    std::uint32_t unk_6C;

    std::uint32_t unk_70;
    std::uint32_t maybe_literal_offset; //not sure
    std::uint32_t unk_78;
    std::uint32_t maybe_parameters_offset2; //not sure
};

struct SceGxmProgramParameter {
    int32_t name_offset; // Number of bytes from the start of this structure to the name string.
    union {
        bf_t<uint16_t, 0, 4> category;  // SceGxmParameterCategory - select constant or sampler
        bf_t<uint16_t, 4, 4> type;  // SceGxmParameterType - applicable for constants, not applicable for samplers (select type like float, half, fixed ...)
        bf_t<uint16_t, 8, 4> component_count;  // applicable for constants, not applicable for samplers (select size like float2, float3, float3 ...)
        bf_t<uint16_t, 12, 4> container_index;  // applicable for constants, not applicable for samplers (buffer, default, texture)
    };
    uint16_t unknown; // Maybe relevant to SCE_GXM_PARAMETER_CATEGORY_AUXILIARY_SURFACE or SCE_GXM_PARAMETER_CATEGORY_UNIFORM_BUFFER.
    uint32_t array_size;
    int32_t resource_index;
};

static_assert(sizeof(SceGxmProgramParameter) == 16, "Incorrect structure layout.");
