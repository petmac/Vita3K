#include "import.h"

#include <unicorn/unicorn.h>

IMP_SIG(uvl_exit)
{
    // http://yifanlu.github.io/UVLoader/group__uvloader.html#gab258eeb1f2b90ef9ca0cab0f9a3f2c39
    const int status = r0;
    (void)status;
    uc_emu_stop(thread->uc);
    
    return 0;
}
