/*
 * minivm —— 一個教學用的小型 VM 保護器
 * ---------------------------------------------------------
 * 展示「虛擬化混淆」的完整流程：
 *   1. 設計一套虛擬指令集 (opcode + operand)
 *   2. 把要保護的 secret 函式「組譯」成 bytecode
 *   3. 用滾動金鑰把 bytecode 加密 (只是提高逆向成本，非真加密)
 *   4. interpreter 在執行期解密 bytecode 並用 dispatcher 執行
 *   5. 跟原生 reference 函式對照，確認行為等價
 *
 * 編譯:  gcc -O2 -o vm vm.c
 * 執行:  ./vm 1234
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================
 * 第 1 層：虛擬指令集
 * ========================================================
 * stack-based，每個值都是 uint64_t。
 * 有些指令後面跟著一個 8-byte 的 operand (little-endian)。
 */
enum {
    OP_INPUT = 0x10,  /* 把輸入值推上堆疊                  */
    OP_PUSH  = 0x11,  /* [imm] 推一個立即值               */
    OP_ADD   = 0x12,  /* b=pop a=pop  push a+b            */
    OP_SUB   = 0x13,  /* b=pop a=pop  push a-b            */
    OP_MUL   = 0x14,  /* b=pop a=pop  push a*b            */
    OP_XOR   = 0x15,
    OP_AND   = 0x16,
    OP_OR    = 0x17,
    OP_SHR   = 0x18,  /* [imm] a=pop  push a >> imm       */
    OP_SHL   = 0x19,  /* [imm] a=pop  push a << imm       */
    OP_ROL   = 0x1a,  /* [imm] a=pop  push rotl64(a,imm)  */
    OP_DUP   = 0x1b,  /* 複製堆疊頂端                     */
    OP_HALT  = 0x1c,  /* 停止，堆疊頂端即為結果           */
};

/* operand ops：這些 opcode 後面會跟 8 bytes */
static int has_operand(uint8_t op) {
    return op == OP_PUSH || op == OP_SHR || op == OP_SHL || op == OP_ROL;
}

/* ========================================================
 * 第 2 層：一個極簡的「組譯器」
 * ========================================================
 * 在程式啟動時，把 secret 演算法寫成一串 bytecode。
 * 真實的保護器會有獨立的 compiler，把 C/IR 翻成 bytecode；
 * 這裡為了單檔示範，直接手工 emit。
 */
typedef struct {
    uint8_t buf[1024];
    size_t  len;
} Asm;

static void emit8(Asm *a, uint8_t b) { a->buf[a->len++] = b; }

static void emit64(Asm *a, uint64_t v) {
    for (int i = 0; i < 8; i++) emit8(a, (uint8_t)(v >> (8 * i)));
}

/* 高階 helper，讓 secret 看起來像一段程式 */
static void a_input(Asm *a)            { emit8(a, OP_INPUT); }
static void a_push (Asm *a, uint64_t v){ emit8(a, OP_PUSH); emit64(a, v); }
static void a_xor  (Asm *a)            { emit8(a, OP_XOR); }
static void a_add  (Asm *a)            { emit8(a, OP_ADD); }
static void a_mul  (Asm *a)            { emit8(a, OP_MUL); }
static void a_shr  (Asm *a, uint64_t n){ emit8(a, OP_SHR); emit64(a, n); }
static void a_rol  (Asm *a, uint64_t n){ emit8(a, OP_ROL); emit64(a, n); }
static void a_dup  (Asm *a)            { emit8(a, OP_DUP); }
static void a_halt (Asm *a)            { emit8(a, OP_HALT); }

/* 把 secret 演算法組譯出來 (見下方 reference 對照) */
static void assemble_secret(Asm *a) {
    a->len = 0;
    a_input(a);                               /* h = x                       */
    a_push(a, 0x5bd1e995ULL);  a_xor(a);      /* h ^= 0x5bd1e995             */
    a_push(a, 0x100000001b3ULL); a_mul(a);    /* h *= FNV prime             */
    a_dup(a);  a_shr(a, 15);   a_xor(a);      /* h ^= h >> 15               */
    a_push(a, 0x9e3779b97f4a7c15ULL); a_add(a);/* h += golden ratio          */
    a_rol(a, 13);                             /* h = rotl(h, 13)            */
    a_push(a, 0xff51afd7ed558ccdULL); a_mul(a);/* h *= murmur3 constant       */
    a_dup(a);  a_shr(a, 33);   a_xor(a);      /* h ^= h >> 33               */
    a_halt(a);                                /* return h                   */
}

/* ========================================================
 * 第 3 層：bytecode 加密 (滾動金鑰 XOR)
 * ========================================================
 * 出貨的程式裡只會有加密後的 blob；靜態分析者看不到明文 opcode。
 * 這只是提高成本：金鑰就在程式裡，動態追還是追得到。
 */
#define KEY_SEED 0xA5u

static void crypt_inplace(uint8_t *p, size_t n) {
    uint8_t k = KEY_SEED;
    for (size_t i = 0; i < n; i++) {
        p[i] ^= k;
        k = (uint8_t)(k * 31u + 17u);   /* 每個 byte 換一次金鑰 */
    }
}

/* ========================================================
 * 第 4 層：interpreter (dispatcher + handlers)
 * ========================================================
 */
static uint64_t rotl64(uint64_t x, unsigned n) {
    n &= 63;
    return n ? (x << n) | (x >> (64 - n)) : x;
}

static uint64_t fetch64(const uint8_t *code, size_t *pc) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= (uint64_t)code[(*pc)++] << (8 * i);
    return v;
}

static uint64_t vm_run(const uint8_t *code, size_t len, uint64_t input) {
    uint64_t stack[256];
    int sp = 0;
    size_t pc = 0;

    #define PUSH(v) (stack[sp++] = (v))
    #define POP()   (stack[--sp])

    while (pc < len) {
        uint8_t op = code[pc++];
        switch (op) {              /* ← dispatcher */
        case OP_INPUT: PUSH(input); break;
        case OP_PUSH:  PUSH(fetch64(code, &pc)); break;
        case OP_ADD: { uint64_t b = POP(), a = POP(); PUSH(a + b); } break;
        case OP_SUB: { uint64_t b = POP(), a = POP(); PUSH(a - b); } break;
        case OP_MUL: { uint64_t b = POP(), a = POP(); PUSH(a * b); } break;
        case OP_XOR: { uint64_t b = POP(), a = POP(); PUSH(a ^ b); } break;
        case OP_AND: { uint64_t b = POP(), a = POP(); PUSH(a & b); } break;
        case OP_OR:  { uint64_t b = POP(), a = POP(); PUSH(a | b); } break;
        case OP_SHR: { uint64_t n = fetch64(code, &pc); uint64_t a = POP(); PUSH(a >> n); } break;
        case OP_SHL: { uint64_t n = fetch64(code, &pc); uint64_t a = POP(); PUSH(a << n); } break;
        case OP_ROL: { uint64_t n = fetch64(code, &pc); uint64_t a = POP(); PUSH(rotl64(a, (unsigned)n)); } break;
        case OP_DUP: { uint64_t t = stack[sp - 1]; PUSH(t); } break;
        case OP_HALT: return POP();
        default:
            fprintf(stderr, "bad opcode 0x%02x @ %zu\n", op, pc - 1);
            exit(2);
        }
    }
    #undef PUSH
    #undef POP
    return 0;   /* 沒遇到 HALT */
}

/* ========================================================
 * 反組譯器：逆向者把 bytecode 解密後，看到的就是這個
 * ========================================================
 * 示範 has_operand 的用途：知道哪些 opcode 後面跟著 8-byte operand，
 * 才能正確切出指令邊界。這正是手動逆向 VM 的第一步。
 */
static const char *op_name(uint8_t op) {
    switch (op) {
    case OP_INPUT: return "INPUT"; case OP_PUSH: return "PUSH";
    case OP_ADD: return "ADD";     case OP_SUB:  return "SUB";
    case OP_MUL: return "MUL";     case OP_XOR:  return "XOR";
    case OP_AND: return "AND";     case OP_OR:   return "OR";
    case OP_SHR: return "SHR";     case OP_SHL:  return "SHL";
    case OP_ROL: return "ROL";     case OP_DUP:  return "DUP";
    case OP_HALT: return "HALT";   default:      return "???";
    }
}

static void vm_disasm(const uint8_t *code, size_t len) {
    size_t pc = 0;
    while (pc < len) {
        uint8_t op = code[pc];
        printf("  %04zu: %-6s", pc, op_name(op));
        pc++;
        if (has_operand(op)) printf(" 0x%llx", (unsigned long long)fetch64(code, &pc));
        putchar('\n');
    }
}

/* ========================================================
 * 原生 reference：用來驗證 VM 行為等價 (出貨時會拿掉)
 * ========================================================
 */
static uint64_t secret_reference(uint64_t x) {
    uint64_t h = x;
    h ^= 0x5bd1e995ULL;
    h *= 0x100000001b3ULL;
    h ^= h >> 15;
    h += 0x9e3779b97f4a7c15ULL;
    h  = rotl64(h, 13);
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 33;
    return h;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <number>\n", argv[0]);
        return 1;
    }
    uint64_t input = strtoull(argv[1], NULL, 0);

    /* === 建置期：組譯 + 加密 (真實情境會離線先做好) === */
    Asm prog;
    assemble_secret(&prog);
    crypt_inplace(prog.buf, prog.len);   /* 現在 prog.buf 是加密的 blob */

    /* === 執行期：解密到暫存區再跑 === */
    uint8_t code[1024];
    memcpy(code, prog.buf, prog.len);
    crypt_inplace(code, prog.len);       /* XOR 兩次 = 還原 */

    if (getenv("VM_DISASM")) {           /* VM_DISASM=1 時傾印解密後的 bytecode */
        printf("[disasm of decrypted bytecode, %zu bytes]\n", prog.len);
        vm_disasm(code, prog.len);
    }

    uint64_t out = vm_run(code, prog.len, input);

    printf("%llu\n", (unsigned long long)out);

    /* 自我驗證 (debug 用) */
    uint64_t ref = secret_reference(input);
    if (out != ref)
        fprintf(stderr, "MISMATCH! vm=%llu ref=%llu\n",
                (unsigned long long)out, (unsigned long long)ref);

    return 0;
}
