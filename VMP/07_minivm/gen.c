/*
 * 建置期工具：把秘密演算法組譯成 bytecode，和原生 reference 對照後加密，輸出 blob.h。
 * 這支程式不出貨；出貨的 vm.c 只拿到加密後的位元組與一張 opcode 對照表。
 *
 *   gen <blob.h> [crypt_seed] [opcode_seed]
 *       crypt_seed  滾動金鑰種子（1 byte），預設 0xA5
 *       opcode_seed 非 0 時，依此種子隨機重排 opcode 編號（diversity）；0 或省略 = 不重排
 *
 * 不論有無重排，bytecode 的結構都一樣，只是每條指令的位元組值不同。
 */
#include <stdio.h>
#include <stdlib.h>

#include "isa.h"
#include "reference.h"

/* 所有 opcode 的 canonical id，順序固定 */
static const uint8_t OPS[] = { OP_INPUT, OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_XOR, OP_AND,
                               OP_OR, OP_SHR, OP_SHL, OP_ROL, OP_DUP, OP_HALT };
#define NOPS ((int)(sizeof OPS / sizeof OPS[0]))

static const char *op_name(uint8_t id) {
    static const char *names[] = { "INPUT", "PUSH", "ADD", "SUB", "MUL", "XOR", "AND",
                                   "OR", "SHR", "SHL", "ROL", "DUP", "HALT" };
    return id >= OP_INPUT && id <= OP_HALT ? names[id - OP_INPUT] : "???";
}

/* OBYTE[id] = 這個 opcode 在 bytecode 裡實際用的位元組；OPMAP[byte] = 還原回 canonical id（0 = 無效） */
static uint8_t OBYTE[256], OPMAP[256];

static uint64_t splitmix(uint64_t *s) {
    uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

/* opcode_seed == 0：identity。否則從 1..255 隨機取 NOPS 個相異位元組指派給各 opcode。 */
static void build_opcode_map(unsigned opcode_seed) {
    for (int i = 0; i < NOPS; i++) OBYTE[OPS[i]] = OPS[i];        /* 預設 identity */
    if (opcode_seed) {
        uint8_t pool[255];
        for (int i = 0; i < 255; i++) pool[i] = (uint8_t)(i + 1);
        uint64_t s = opcode_seed;
        for (int i = 254; i > 0; i--) {                          /* Fisher-Yates */
            int j = (int)(splitmix(&s) % (uint64_t)(i + 1));
            uint8_t t = pool[i]; pool[i] = pool[j]; pool[j] = t;
        }
        for (int i = 0; i < NOPS; i++) OBYTE[OPS[i]] = pool[i];
    }
    for (int i = 0; i < NOPS; i++) OPMAP[OBYTE[OPS[i]]] = OPS[i];
}

/* ---- 第 2 層：極簡組譯器（emit 時把 canonical id 換成該 build 的位元組） ---- */
typedef struct { uint8_t buf[1024]; size_t len; } Asm;

static void emit8(Asm *a, uint8_t b) {
    if (a->len >= sizeof a->buf) { fprintf(stderr, "gen: program too long\n"); exit(1); }
    a->buf[a->len++] = b;
}
static void emit_op(Asm *a, uint8_t id) { emit8(a, OBYTE[id]); }
static void emit64(Asm *a, uint64_t v) { for (int i = 0; i < 8; i++) emit8(a, (uint8_t)(v >> (8 * i))); }
static void shift_op(Asm *a, uint8_t id, uint64_t n) {
    if (n >= 64) { fprintf(stderr, "gen: shift %llu out of range\n", (unsigned long long)n); exit(1); }
    emit_op(a, id); emit64(a, n);
}

static void a_input(Asm *a)             { emit_op(a, OP_INPUT); }
static void a_push (Asm *a, uint64_t v) { emit_op(a, OP_PUSH); emit64(a, v); }
static void a_xor  (Asm *a)             { emit_op(a, OP_XOR); }
static void a_add  (Asm *a)             { emit_op(a, OP_ADD); }
static void a_mul  (Asm *a)             { emit_op(a, OP_MUL); }
static void a_shr  (Asm *a, uint64_t n) { shift_op(a, OP_SHR, n); }
static void a_rol  (Asm *a, uint64_t n) { shift_op(a, OP_ROL, n); }
static void a_dup  (Asm *a)             { emit_op(a, OP_DUP); }
static void a_halt (Asm *a)             { emit_op(a, OP_HALT); }

static void assemble_secret(Asm *a) {
    a->len = 0;
    a_input(a);                                  /* h = x               */
    a_push(a, 0x5bd1e995ULL);         a_xor(a);  /* h ^= 0x5bd1e995     */
    a_push(a, 0x100000001b3ULL);      a_mul(a);  /* h *= FNV prime      */
    a_dup(a); a_shr(a, 15);           a_xor(a);  /* h ^= h >> 15        */
    a_push(a, 0x9e3779b97f4a7c15ULL); a_add(a);  /* h += golden ratio   */
    a_rol(a, 13);                                /* h = rotl(h, 13)     */
    a_push(a, 0xff51afd7ed558ccdULL); a_mul(a);  /* h *= murmur3 const  */
    a_dup(a); a_shr(a, 33);           a_xor(a);  /* h ^= h >> 33        */
    a_halt(a);                                   /* return h            */
}

static void disasm(const uint8_t *code, size_t len) {
    size_t pc = 0;
    uint64_t v;
    while (pc < len) {
        uint8_t id = OPMAP[code[pc]];
        printf("  %04zx: %-6s", pc, op_name(id));              /* 位址用 16 進位 */
        pc++;
        if (has_operand(id)) {
            if (vm_fetch64(code, len, &pc, &v) != VM_OK) { printf(" <truncated>\n"); return; }
            printf(" 0x%llx", (unsigned long long)v);
        }
        putchar('\n');
    }
}

int main(int argc, char **argv) {
    if (argc < 2 || argc > 4) { fprintf(stderr, "usage: %s <blob.h> [crypt_seed] [opcode_seed]\n", argv[0]); return 1; }
    unsigned long crypt_seed = argc >= 3 ? strtoul(argv[2], NULL, 0) : 0xA5ul;
    unsigned long opcode_seed = argc >= 4 ? strtoul(argv[3], NULL, 0) : 0ul;
    if (crypt_seed > 0xff) { fprintf(stderr, "gen: crypt seed must fit in one byte\n"); return 1; }

    build_opcode_map((unsigned)opcode_seed);

    Asm prog;
    assemble_secret(&prog);
    printf("[bytecode, %zu bytes, opcode_seed 0x%lx]\n", prog.len, opcode_seed);
    disasm(prog.buf, prog.len);
    for (int i = 0; i < NOPS; i++)                              /* 機器可解析的對照，供測試驗證分類結果 */
        printf("OPCODE %-6s 0x%02x\n", op_name(OPS[i]), OBYTE[OPS[i]]);

    /* 建置期自我驗證：bytecode 必須和原生版本完全一致 */
    uint64_t s = 1, xs[2000 + 6] = { 0, 1, 1234, 0xdeadbeef, 0x7fffffffffffffffULL, ~0ULL };
    for (int i = 6; i < 2006; i++) xs[i] = splitmix(&s);
    for (int i = 0; i < 2006; i++) {
        uint64_t out;
        int err = vm_run(prog.buf, prog.len, xs[i], &out, OPMAP);
        if (err != VM_OK || out != secret_reference(xs[i])) {
            fprintf(stderr, "gen: bytecode disagrees with reference at x=%llu (err %d)\n",
                    (unsigned long long)xs[i], err);
            return 1;
        }
    }
    printf("[self-check] 2006 inputs agree with the native reference\n");

    crypt_inplace(prog.buf, prog.len, (uint8_t)crypt_seed);
    FILE *f = fopen(argv[1], "w");
    if (!f) { perror(argv[1]); return 1; }
    fprintf(f, "/* generated by gen.c: encrypted bytecode + opcode table; do not edit */\n");
    fprintf(f, "#define BLOB_SEED 0x%02lxu\n#define BLOB_LEN %zu\n", crypt_seed, prog.len);
    fprintf(f, "static const uint8_t OPMAP[256] = {");
    for (int i = 0; i < 256; i++) fprintf(f, "%s0x%02x,", i % 12 ? " " : "\n    ", OPMAP[i]);
    fprintf(f, "\n};\n");
    fprintf(f, "static const uint8_t BLOB[BLOB_LEN] = {");
    for (size_t i = 0; i < prog.len; i++) fprintf(f, "%s0x%02x,", i % 12 ? " " : "\n    ", prog.buf[i]);
    fprintf(f, "\n};\n");
    return fclose(f) == 0 ? 0 : 1;
}
