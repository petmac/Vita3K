#include "nid.h"

const char *nid_name(uint32_t nid)
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
