/*
 * oracle：攻擊方的「單步執行器」。代表從出貨 binary 取出的直譯器 —— 單元 06 是用 Unicorn 模擬 ELF 裡的
 * vm_run，這裡為了可重現，直接用同一份 blob.h（含該 build 的 OPMAP）編一支小工具。它和出貨 vm.exe 是同一個
 * 直譯器、同一套 opcode 編號，差別只在：它會印出整個堆疊，讓攻擊者觀察每個未知位元組的行為。
 *
 *   oracle <hex-bytecode> <input>   ->   "<err> <sp> <v0> <v1> ..."   (堆疊由底到頂，十進位)
 *
 * 關鍵：oracle 內部用 OPMAP，但攻擊腳本 attack_div.py 從不讀 OPMAP —— 它只送 bytecode、看輸出，
 * 從行為反推每個位元組的語意。這就是單元 06 不靠 dispatcher 編號的黑箱分類法。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isa.h"
#include "blob.h"

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <hex> <input>\n", argv[0]); return 1; }

    const char *h = argv[1];
    size_t hl = strlen(h);
    if (hl % 2 || hl / 2 > 1024) { fprintf(stderr, "oracle: bad hex\n"); return 1; }
    size_t n = hl / 2;
    uint8_t code[1024];
    for (size_t i = 0; i < n; i++) {
        unsigned b;
        if (sscanf(h + 2 * i, "%2x", &b) != 1) { fprintf(stderr, "oracle: bad hex\n"); return 1; }
        code[i] = (uint8_t)b;
    }
    uint64_t input = strtoull(argv[2], NULL, 0);

    uint64_t stack[VM_STACK];
    int sp = 0, err = VM_NO_HALT;
    size_t pc = 0;
    while (pc < n) {
        uint8_t op = OPMAP[code[pc++]];
        uint64_t imm = 0;
        int wants_imm = (op == OP_PUSH || op == OP_SHR || op == OP_SHL || op == OP_ROL);
        if (op == 0) { err = VM_BAD_OP; break; }
        if (wants_imm) {
            if (n - pc < 8) { err = VM_TRUNCATED; break; }
            for (int i = 0; i < 8; i++) imm |= (uint64_t)code[pc + i] << (8 * i);
            pc += 8;
        }
        if (op == OP_INPUT || op == OP_PUSH || op == OP_DUP) { if (sp >= VM_STACK) { err = VM_OVERFLOW; break; } }
        switch (op) {
        case OP_INPUT: stack[sp++] = input; break;
        case OP_PUSH:  stack[sp++] = imm; break;
        case OP_ADD: case OP_SUB: case OP_MUL: case OP_XOR: case OP_AND: case OP_OR: {
            if (sp < 2) { err = VM_UNDERFLOW; goto done; }
            uint64_t b = stack[--sp], a = stack[--sp];
            stack[sp++] = op == OP_ADD ? a + b : op == OP_SUB ? a - b : op == OP_MUL ? a * b
                        : op == OP_XOR ? a ^ b : op == OP_AND ? a & b : a | b;
            break;
        }
        case OP_SHR: case OP_SHL: case OP_ROL: {
            if (imm >= 64) { err = VM_BAD_SHIFT; goto done; }
            if (sp < 1) { err = VM_UNDERFLOW; goto done; }
            uint64_t a = stack[--sp];
            stack[sp++] = op == OP_SHR ? a >> imm : op == OP_SHL ? a << imm : rotl64(a, (unsigned)imm);
            break;
        }
        case OP_DUP:  if (sp < 1) { err = VM_UNDERFLOW; goto done; } stack[sp] = stack[sp - 1]; sp++; break;
        case OP_HALT: if (sp < 1) { err = VM_UNDERFLOW; goto done; }
                      { uint64_t r = stack[sp - 1]; sp = 0; stack[sp++] = r; } err = VM_OK; goto done;
        default:      err = VM_BAD_OP; goto done;
        }
    }
done:
    printf("%d %d", err, sp);
    for (int i = 0; i < sp; i++) printf(" %llu", (unsigned long long)stack[i]);
    putchar('\n');
    return 0;
}
