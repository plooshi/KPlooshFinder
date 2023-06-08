// this just has the shellcode functions as C arrays
// as we can't really compile the shellcode into the bin
#include <stdint.h>
#include "plooshfinder.h"

uint32_t _sandbox_shellcode[4] = {
    0x14000008, // b sandbox_shellcode_m
    0x14000017, // b amfi_execve_hook
    0x1400001e, // b pre_execve_hook
    nop
};

uint32_t vnode_getpath[4] = {
    0xaa0003f3, // mov x19, x0
    nop,
    0xaa1303e0, // mov x0, x19
    ret
};

uint32_t sandbox_shellcode_m[14] = {
    0xaa1e03e6, // mov x6, x30
    0xaa1303e4, // mov x4, x19
    0xaa0003e5, // mov x5, x0
    0xaa0103e0, // mov x0, x1
    0xb4000140, // cbz x0, nomatch
    0x97fffff7, // bl vnode_getpath
    0xb4000100, // cbz x0, nomatch
    0xf9400007, // ldr x7, [x0]
    0x10000940, // adr x0, pattern
    0xf9400008, // ldr x8, [x0]
    0xaa1f03e0, // mov x0, xzr
    0xeb07011f, // cmp x8, x7
    0x54000041, // b.ne nomatch
    0xd2800020  // mov x0, 1
};

uint32_t nomatch[2] = {
    0xaa0403f3, // mov x19, x4
    0xd61f00c0  // br x6
};

uint32_t amfi_execve_hook[8] = {
    0xf94007e0, // ldr x0, [sp, 8]
    0xb9400001, // ldr w1, [x0]
    0x32060021, // orr w1, w1, 0x4000000
    0x32000c21, // orr w1, w1, 0xf
    0x12126421, // and w1, w1, 0xffffc0ff
    0xb9000001, // str x1, [x0]
    0xaa1f03e0, // mov x0, xzr
    ret
};

uint32_t pre_execve_hook[28] = {
    0xb40005c3, // cbz x3, pre_execve_hook$orig
    0xd11003ff, // sub sp, sp, 0x400
    0xa9007bfd, // stp x29, x30, [sp]
    0xa90107e0, // stp x0, x1, [sp, 0x10]
    0xa9020fe2, // stp x2, x3, [sp, 0x20]
    0xa90317e4, // stp x4, x5, [sp, 0x30]
    0xa9041fe6, // stp x6, x7, [sp, 0x40]
    0x580005b0, // ldr x16, vfs
    0xd63f0200, // blr x16
    0xaa0003e2, // mov x2, x0
    0xf94017e0, // ldr x0, [sp, 0x28]
    0x910203e1, // add x1, sp, 0x80
    0x52807008, // mov w8, 0x380
    0xa900203f, // stp xzr, x8, [x1]
    0xa9017c3f, // stp xzr, xzr, [x1, 0x10]
    0x58000470, // ldr x16, vnode
    0xd63f0200, // blr x16
    0xb50002e0, // cbnz x0, pre_execve_hook$orig$epilog
    0x52800002, // mov w2, 0
    0xb940cfe8, // ldr w8, [sp, 0xcc]
    0x36580108, // tbz w8, 0xb, pre_execve_hook$orig$gid
    0xb940c7e8, // ldr w8, [sp, 0xc4]
    0xf9400fe0, // ldr x0, [sp, 0x18]
    0xb9001808, // str w8, [x0, 0x18]
    0x52800022, // mov w2, 1
    nop,
    nop,
    nop
};

uint32_t pre_execve_hook$orig$gid[6] = {
    0xb940cfe8, // ldr w8, [sp, 0xcc]
    0x365000a8, // tbz w8, 0xa, pre_execve_hook$orig$p_flags
    0x52800022, // mov w2, 1
    0xb940cbe8, // ldr w8, [sp, 0xc8]
    0xf9400fe0, // ldr x0, [sp, 0x18]
    0xb9002808  // str w8, [x0, 0x28]
};

uint32_t pre_execve_hook$orig$p_flags[2] = {
    0x340000c2, // cbz w2, pre_execve_hook$orig$epilog
    0xf94013e0, // ldr x0, [sp, 0x20]
};

uint32_t _sandbox_shellcode_setuid_patch[4] = {
    0xb9400008, // ldr w8, [x0]
    0x32180108, // orr w8, w8, 0x100
    0xb9000008, // str w8, [x0]
    nop
};

uint32_t pre_execve_hook$orig$epilog[6] = {
    0xa94107e0, // ldp x0, x1, [sp, 0x10]
    0xa9420fe2, // ldp x2, x3, [sp, 0x20]
    0xa94317e4, // ldp x4, x5, [sp, 0x30]
    0xa9441fe6, // ldp x6, x7, [sp, 0x40]
    0xa9407bfd, // ldp x29, x30, [sp]
    0x911003ff  // add sp, sp, 0x400
};

uint32_t pre_execve_hook$orig[2] = {
    0x58000050, // ldr x16, _sandbox_shellcode_ptrs
    0xd61f0200, // br x16
};

uint64_t orig[1] = {
    0x4141413341414132
};

uint64_t vnode[1] = {
    0x4141413541414134
};

uint64_t vfs[1] = {
    0x4141413741414136
};

uint64_t _vnode_lookup[1] = {
    0x4141413941414138
};

uint64_t _vnode_put[1] = {
    0x4141414141414140
};

uint64_t pattern[1] = {
    0x746E65766573662E
};

uint32_t _nvram_shc[4] = {
    0x71000c1f, // cmp w0, 3
    0x1a8003e0, // csel w0, wzr, w0, eq
    ret,
    nop
};