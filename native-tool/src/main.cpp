#include <psp2/kernel/processmgr.h>
#include <psp2/gxm.h>

#include <stdio.h>

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
    
    fprintf(fp, "Exiting normally.\n");
    fclose(fp);
    fp = nullptr;
    
    sceKernelExitProcess(0);
    return 0;
}
