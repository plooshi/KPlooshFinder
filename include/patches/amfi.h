#ifndef _PATCHES_AMFI_H
#define _PATCHES_AMFI_H
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

extern uint32_t *amfi_ret;
extern bool found_amfi_mac_syscall;
extern bool found_trustcache;
extern uint32_t offsetof_p_flags;

void patch_amfi_kext(void *real_buf, void *amfi_buf, size_t amfi_len, bool has_constraints, bool has_devmode);

#endif