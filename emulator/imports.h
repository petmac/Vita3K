#pragma once

#include <stdint.h>

typedef void ImportFn();

const char *import_name(uint32_t nid);
ImportFn *import_fn(uint32_t nid);
