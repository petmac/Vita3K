#pragma once

#include <stdint.h>

struct uc_struct;

typedef void ImportFn(uc_struct *);

const char *import_name(uint32_t nid);
ImportFn *import_fn(uint32_t nid);
