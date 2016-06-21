#include "import.h"

IMP_SIG(sceKernelCreateLwMutex)
{
    Args args = read_args(uc);
    (void)args;
    
    write_result(uc, 0);
}
