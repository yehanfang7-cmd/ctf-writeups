/*
 * 秘密演算法的原生版本（MurmurHash 風格 finalizer）。
 * 只給建置期 gen.c 和 SELFTEST 版的 vm.c 使用；出貨版 vm.c 不會 include 它。
 */
#ifndef MINIVM_REFERENCE_H
#define MINIVM_REFERENCE_H

#include "isa.h"

static uint64_t secret_reference(uint64_t x) {
    uint64_t h = x;
    h ^= 0x5bd1e995ULL;
    h *= 0x100000001b3ULL;           /* FNV-1a 質數 */
    h ^= h >> 15;
    h += 0x9e3779b97f4a7c15ULL;      /* 黃金比例常數 */
    h  = rotl64(h, 13);
    h *= 0xff51afd7ed558ccdULL;      /* murmur3 常數 */
    h ^= h >> 33;
    return h;
}

#endif
