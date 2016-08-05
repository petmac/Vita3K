#include <psp2/kernel/processmgr.h>
#include <psp2/gxm.h>

#include <stdio.h>

static const uint8_t clear_v_gxp[] =
{
#include "shaders/clear_v.h"
};

static void check(int result, const char *function, FILE *fp)
{
    if (result != 0)
    {
        fprintf(fp, "%s failed (%d, 0x%x).\n", function, result, result);
        
        fclose(fp);
        fp = nullptr;
        
        sceKernelExitProcess(1);
    }
}

static void dump(FILE *fp, const SceGxmProgram *program, const char *name)
{
    fprintf(fp, "Program %s at address %p:\n", name, program);
    
    unsigned int param_count = sceGxmProgramGetParameterCount(program);
    fprintf(fp, "\t%u parameter(s)\n", param_count);
    
    for (unsigned int param_index = 0; param_index < param_count; ++param_index)
    {
        const SceGxmProgramParameter *const parameter = sceGxmProgramGetParameter(program, param_index);
        const int offset = reinterpret_cast<const char *>(parameter) - reinterpret_cast<const char *>(program);
        fprintf(fp, "\tParameter %u at address %p (offset = %d)\n", param_index, parameter, offset);
        
        const SceGxmParameterCategory category = sceGxmProgramParameterGetCategory(parameter);
        const char *const name = sceGxmProgramParameterGetName(parameter);
        const SceGxmParameterSemantic semantic = sceGxmProgramParameterGetSemantic(parameter);
        const unsigned int semantic_index = sceGxmProgramParameterGetSemanticIndex(parameter);
        const SceGxmParameterType type = sceGxmProgramParameterGetType(parameter);
        const unsigned int component_count = sceGxmProgramParameterGetComponentCount(parameter);
        const unsigned int array_size = sceGxmProgramParameterGetArraySize(parameter);
        const unsigned int resource_index = sceGxmProgramParameterGetResourceIndex(parameter);
        const unsigned int container_index = sceGxmProgramParameterGetContainerIndex(parameter);
        const SceBool is_sampler_cube = sceGxmProgramParameterIsSamplerCube(parameter);
        
        fprintf(fp, "\t\tCategory = %u\n", category);
        fprintf(fp, "\t\tName = %s\n", name);
        fprintf(fp, "\t\tSemantic = %u\n", semantic);
        fprintf(fp, "\t\tSemantic index = %u\n", semantic_index);
        fprintf(fp, "\t\tType = %u\n", type);
        fprintf(fp, "\t\tComponent count = %u\n", component_count);
        fprintf(fp, "\t\tArray size = %u\n", array_size);
        fprintf(fp, "\t\tResource index = %u\n", resource_index);
        fprintf(fp, "\t\tContainer index = %u\n", container_index);
        fprintf(fp, "\t\tIs sampler cube = %u\n", is_sampler_cube);
    }
}

static void display_callback(const void *data)
{
}

int main(int argc, char *argv[])
{
    FILE *fp = fopen("ux0:/data/hello.txt", "w");
    if (fp == nullptr)
    {
        sceKernelExitProcess(1);
        return 1;
    }
    
    fprintf(fp, "Started.\n");
    
    SceGxmInitializeParams params = {};
    params.displayQueueCallback = &display_callback;
    params.displayQueueCallbackDataSize = 4;
    params.displayQueueMaxPendingCount = 2;
    params.parameterBufferSize = SCE_GXM_DEFAULT_PARAMETER_BUFFER_SIZE;
    
    check(sceGxmInitialize(&params), "sceGxmInitialize", fp);
    dump(fp, reinterpret_cast<const SceGxmProgram *>(clear_v_gxp), "clear_v");
    
    fprintf(fp, "Exiting normally.\n");
    fclose(fp);
    fp = nullptr;
    
    sceKernelExitProcess(0);
    return 0;
}
