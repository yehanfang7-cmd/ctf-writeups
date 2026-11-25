/*
 * minivm 共用核心：指令集、bytecode 加解密、直譯器。
 * gen.c（建置期）與 vm.c（出貨）都 include 這個檔；裡面沒有任何秘密演算法的常數。
 */
#ifndef MINIVM_ISA_H
#define MINIVM_ISA_H

#include <stddef.h>
#include <stdint.h>

/* ---- 第 1 層：虛擬指令集（stack-based，值皆為 uint64_t） ---- */
enum {
    OP_INPUT = 0x10,  /* push(input)                              */
    OP_PUSH  = 0x11,  /* [imm8B] push(imm)                        */
    OP_ADD   = 0x12,  /* b=pop a=pop push(a+b)                    */
    OP_SUB   = 0x13,
    OP_MUL   = 0x14,
    OP_XOR   = 0x15,
    OP_AND   = 0x16,
    OP_OR    = 0x17,
    OP_SHR   = 0x18,  /* [n8B] push(pop() >> n)，n 必須 < 64       */
    OP_SHL   = 0x19,  /* [n8B] push(pop() << n)，n 必須 < 64       */
    OP_ROL   = 0x1a,  /* [n8B] push(rotl64(pop(), n))，n 必須 < 64 */
    OP_DUP   = 0x1b,
    OP_HALT  = 0x1c,  /* 結果 = pop()                             */
};

static inline int has_operand(uint8_t op) {
    return op == OP_PUSH || op == OP_SHR || op == OP_SHL || op == OP_ROL;
}

static inline uint64_t rotl64(uint64_t x, unsigned n) {
    n &= 63;
    return n ? (x << n) | (x >> (64 - n)) : x;
}

/* ---- 第 3 層：滾動金鑰 XOR（做兩次 = 還原） ---- */
static inline void crypt_inplace(uint8_t *p, size_t n, uint8_t seed) {
    uint8_t k = seed;
    for (size_t i = 0; i < n; i++) {
        p[i] ^= k;
        k = (uint8_t)(k * 31u + 17u);
    }
}

/* ---- 第 4 層：直譯器 ----
 * 每個錯誤都回傳錯誤碼，不讀寫界外：bytecode 被竄改或截斷時不會變成未定義行為。 */
enum { VM_OK = 0, VM_BAD_OP, VM_TRUNCATED, VM_UNDERFLOW, VM_OVERFLOW, VM_BAD_SHIFT, VM_NO_HALT };
#define VM_STACK 256

static inline int vm_fetch64(const uint8_t *code, size_t len, size_t *pc, uint64_t *v) {
    if (len - *pc < 8) return VM_TRUNCATED;          /* *pc <= len 恆成立 */
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) r |= (uint64_t)code[*pc + i] << (8 * i);
    *pc += 8;
    *v = r;
    return VM_OK;
}

static int vm_run(const uint8_t *code, size_t len, uint64_t input, uint64_t *out) {
    uint64_t stack[VM_STACK], a, b, n;
    int sp = 0, err;
    size_t pc = 0;

#define NEED(k)  do { if (sp < (k)) return VM_UNDERFLOW; } while (0)
#define ROOM()   do { if (sp >= VM_STACK) return VM_OVERFLOW; } while (0)
#define IMM(v)   do { if ((err = vm_fetch64(code, len, &pc, &(v))) != VM_OK) return err; } while (0)
#define BIN(expr) do { NEED(2); b = stack[--sp]; a = stack[--sp]; stack[sp++] = (expr); } while (0)
#define SHIFT(expr) do { IMM(n); if (n >= 64) return VM_BAD_SHIFT; NEED(1); a = stack[--sp]; stack[sp++] = (expr); } while (0)

    while (pc < len) {
        uint8_t op = code[pc++];
        switch (op) {                                  /* ← dispatcher */
        case OP_INPUT: ROOM(); stack[sp++] = input; break;
        case OP_PUSH:  IMM(a); ROOM(); stack[sp++] = a; break;
        case OP_ADD:   BIN(a + b); break;
        case OP_SUB:   BIN(a - b); break;
        case OP_MUL:   BIN(a * b); break;
        case OP_XOR:   BIN(a ^ b); break;
        case OP_AND:   BIN(a & b); break;
        case OP_OR:    BIN(a | b); break;
        case OP_SHR:   SHIFT(a >> n); break;
        case OP_SHL:   SHIFT(a << n); break;
        case OP_ROL:   SHIFT(rotl64(a, (unsigned)n)); break;
        case OP_DUP:   NEED(1); ROOM(); a = stack[sp - 1]; stack[sp++] = a; break;
        case OP_HALT:  NEED(1); *out = stack[--sp]; return VM_OK;
        default:       return VM_BAD_OP;
        }
    }
    return VM_NO_HALT;
#undef NEED
#undef ROOM
#undef IMM
#undef BIN
#undef SHIFT
}

#endif
