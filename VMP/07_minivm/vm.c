/*
 * minivm 出貨程式：只含加密後的 bytecode（blob.h，由 gen.c 產生）和直譯器。
 *
 *   gcc -O2 -I generated -o vm vm.c                 出貨版
 *   gcc -O2 -I generated -DSELFTEST -o vm_st vm.c   除錯版：多了原生對照和 VM_DISASM
 *
 * 出貨版刻意不含：原生 reference（反組譯它就是答案）、組譯器（emit 的立即值就是答案）、
 * 反組譯器與 opcode 名稱（設個環境變數就能拿到明文 bytecode）。
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isa.h"
#include "blob.h"

#ifdef SELFTEST
#include "reference.h"
static void dump(const uint8_t *code, size_t len) {
    printf("[decrypted bytecode, %zu bytes]\n", len);
    for (size_t i = 0; i < len; i++) printf("%02x%s", code[i], i % 16 == 15 || i + 1 == len ? "\n" : " ");
}
#endif

/* 只接受完整的非負整數（10 進位或 0x 開頭的 16 進位），不默默把 "abc" 當成 0 */
static int parse_u64(const char *s, uint64_t *v) {
    char *end;
    if (!*s || *s == '-' || *s == '+' || *s == ' ') return 0;
    errno = 0;
    unsigned long long r = strtoull(s, &end, 0);
    if (errno || *end) return 0;
    *v = r;
    return 1;
}

int main(int argc, char **argv) {
    uint64_t input, out;
    if (argc != 2 || !parse_u64(argv[1], &input)) {
        fprintf(stderr, "usage: %s <number>\n", argv[0]);
        return 1;
    }

    uint8_t code[BLOB_LEN];
    memcpy(code, BLOB, BLOB_LEN);
    crypt_inplace(code, BLOB_LEN, BLOB_SEED);

#ifdef SELFTEST
    if (getenv("VM_DISASM")) dump(code, BLOB_LEN);
#endif

    int err = vm_run(code, BLOB_LEN, input, &out, OPMAP);
    if (err != VM_OK) { fprintf(stderr, "vm error %d\n", err); return 2; }
    printf("%llu\n", (unsigned long long)out);

#ifdef SELFTEST
    uint64_t ref = secret_reference(input);
    if (out != ref) {
        fprintf(stderr, "MISMATCH! vm=%llu ref=%llu\n", (unsigned long long)out, (unsigned long long)ref);
        return 3;
    }
#endif
    return 0;
}
