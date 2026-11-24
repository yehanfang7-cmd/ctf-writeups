/* Fast Subleq runner for unit 05 (the Python versions in devirt.py are the readable reference).

   vm run      <resident.bin> <out.bin> <mem0> <words> <pc0> <pwdst> <maxlen> <password-hex> [max_steps]
   vm lockstep <resident.bin> <mem0> <words> <pc0> <pwdst> <maxlen> <password-hex> <head> <base> <ip0>

   "run" follows the x86 interpreter at 0x5dd9 byte for byte: a 64 KiB segment, word index i lives at
   (mem0 + 2*i) & 0xffff, output is mem[2] when mem[4] != 0.  It prints steps, the result word and the
   output, and writes the final segment to out.bin.

   "lockstep" also runs an independent RSSB model that starts from the pristine image (not from Subleq
   state).  Every time Subleq reaches <head> the model executes one RSSB instruction and the whole RSSB
   region [base, words) must match the Subleq memory word for word. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t seg[65536];
static unsigned mem0;

static uint16_t rd(uint16_t i) { uint16_t o = mem0 + 2u * i; return seg[o] | seg[(uint16_t)(o + 1)] << 8; }
static void wr(uint16_t i, uint16_t v) { uint16_t o = mem0 + 2u * i; seg[o] = v; seg[(uint16_t)(o + 1)] = v >> 8; }

static int load(const char *path, const char *pwhex, unsigned pwdst, unsigned maxlen) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(seg, 1, sizeof seg, f);
    fclose(f);
    if (n == 0) return 0;
    /* routine 0x1da: copy at most maxlen bytes, one byte per word, the NUL included */
    size_t len = strlen(pwhex) / 2;
    for (unsigned i = 0; i < maxlen; i++) {
        unsigned ch = 0;
        if (i < len) sscanf(pwhex + 2 * i, "%2x", &ch);
        seg[(uint16_t)(pwdst + 2 * i)] = ch;
        seg[(uint16_t)(pwdst + 2 * i + 1)] = 0;
        if (ch == 0) break;
    }
    return 1;
}

/* one Subleq instruction; returns 0 on halt */
static int sub_step(uint16_t *pc, unsigned words, char *out, size_t *outlen) {
    if ((unsigned)*pc + 3 > words) return 0;
    uint16_t a = rd(*pc), b = rd(*pc + 1), c = rd(*pc + 2);
    uint16_t r = rd(b) - rd(a);
    wr(b, r);
    if (c != 0 && (int16_t)r <= 0) {
        if (c == 0xffff) return 0;
        *pc = c;
    } else {
        *pc += 3;
    }
    if (rd(4)) {
        if (*outlen < 4096) out[(*outlen)++] = (char)rd(2);
        wr(4, 0); wr(2, 0);
    }
    return 1;
}

static void print_out(const char *out, size_t n) {
    printf("out ");
    for (size_t i = 0; i < n; i++) printf("%02x", (unsigned char)out[i]);
    printf("\n");
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    static char out[4096];
    size_t outlen = 0;
    if (!strcmp(argv[1], "run") && argc >= 10) {
        mem0 = strtoul(argv[4], 0, 16);
        unsigned words = strtoul(argv[5], 0, 16), pwdst = strtoul(argv[7], 0, 16), maxlen = strtoul(argv[8], 0, 16);
        uint16_t pc = strtoul(argv[6], 0, 16);
        unsigned long long limit = argc > 10 ? strtoull(argv[10], 0, 10) : ~0ull, steps = 0;
        if (!load(argv[2], argv[9], pwdst, maxlen)) return 3;
        while (steps < limit && sub_step(&pc, words, out, &outlen)) steps++;
        printf("steps %llu\npc %x\n", steps, pc);
        print_out(out, outlen);
        FILE *f = fopen(argv[3], "wb");
        if (!f) return 3;
        fwrite(seg, 1, sizeof seg, f);
        fclose(f);
        return 0;
    }
    if (!strcmp(argv[1], "lockstep") && argc == 12) {
        mem0 = strtoul(argv[3], 0, 16);
        unsigned words = strtoul(argv[4], 0, 16), pwdst = strtoul(argv[6], 0, 16), maxlen = strtoul(argv[7], 0, 16);
        uint16_t pc = strtoul(argv[5], 0, 16);
        unsigned head = strtoul(argv[9], 0, 16), base = strtoul(argv[10], 0, 16), ip0 = strtoul(argv[11], 0, 16);
        if (!load(argv[2], argv[8], pwdst, maxlen)) return 3;
        unsigned n = words - base;
        uint16_t *M = calloc(65536, 2);          /* RSSB memory, indexed mod 2^16 like the machine */
        for (unsigned i = 0; i < n; i++) M[i] = rd(base + i);
        M[0] = ip0;
        unsigned long long rsteps = 0, ssteps = 0;
        int started = 0;
        for (;;) {
            if (pc == head) {
                if (started) {                   /* model executes one instruction */
                    uint16_t ip = M[0], x = M[ip];
                    if (ip >= n || (x >= n && x < 0xfffe)) { printf("access outside the RSSB region at %llu\n", rsteps); return 1; }
                    if (x == 0xfffe) { printf("model halted early at %llu\n", rsteps); return 1; }
                    if (x == 0xffff) M[0] = ip + 1;
                    else {
                        uint16_t v = M[x] - M[1];
                        if (x != 2) M[x] = v;
                        M[1] = v;
                        M[0] = M[0] + 1 + (v >> 15);
                        if (M[6]) M[4] = M[6] = 0;
                    }
                    rsteps++;
                }
                started = 1;
                for (unsigned i = 0; i < n; i++)
                    if (M[i] != rd(base + i)) {
                        printf("mismatch after %llu RSSB steps: cell %x model %x subleq %x\n", rsteps, i, M[i], rd(base + i));
                        return 1;
                    }
            }
            if (!sub_step(&pc, words, out, &outlen)) break;
            ssteps++;
        }
        int model_halts = M[M[0]] == 0xfffe;
        printf("subleq %llu\nrssb %llu\nmodel_halts %d\n", ssteps, rsteps, model_halts);
        print_out(out, outlen);
        return model_halts ? 0 : 1;
    }
    return 2;
}
