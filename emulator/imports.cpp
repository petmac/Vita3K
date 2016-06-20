#include "imports.h"

#include "import.h"

const char *import_name(uint32_t nid)
{
    switch (nid)
    {
#define NID(name, nid) case nid: return #name;
#include "nids.h"
#undef NID
        default:
            return "UNRECOGNISED";
    }
}

ImportFn *import_fn(uint32_t nid)
{
    switch (nid)
    {
#define NID(name, nid) case nid: return &import_##name;
#include "nids.h"
#undef NID
        default:
            return nullptr;
    }
}
