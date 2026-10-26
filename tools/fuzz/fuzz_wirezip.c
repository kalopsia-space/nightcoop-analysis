/* Faithful transcription of NightCoop.dll FUN_180066cc0 (wire_zip / NCZQ LZ4-style
 * block decompressor, 0.1.1-beta.2) for libFuzzer + AddressSanitizer.
 *
 * Purpose: empirically check the decompressor for out-of-bounds read/write. The
 * window buffer is allocated to EXACTLY base+outsize bytes so ASan redzones catch
 * any OOB the manual bounds reasoning in docs/F_rce_fuzzing_0.1.1-beta.2.md missed.
 *
 * This fuzzes a TRANSCRIPTION of the decompiled logic, not the shipped bytes. It is
 * faithful (same arithmetic, same bounds checks), but a transcription error could in
 * principle hide or invent a bug; a real crash should be replayed against the DLL.
 *
 * Build & run:
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined -o fuzz_wirezip fuzz_wirezip.c
 *   ./fuzz_wirezip -max_total_time=90 -max_len=70000 corpus/
 *
 * Model: the game's sliding-window object is param_1 = {base_ptr, _, _, write_off}.
 * The decoder writes decompressed bytes into win[write_off .. write_off+outsize) and
 * may back-reference earlier window content win[0 .. write_off).
 * Replacements, semantics-preserving for bounds:
 *   FUN_1800663b0(win, outsize) -> ensure capacity: we pre-allocate base+outsize.
 *   FUN_180a7cd90(dst,src,n)    -> memmove (the CRT copy).
 * The post-loop "commit to output vector" is modeled by a bounded copy into outvec.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int decode(uint8_t *win, uint64_t base, uint64_t winsz,
                  const uint8_t *in, uint64_t inlen, uint64_t outsize,
                  uint8_t *outvec, uint64_t outcap)
{
    if (!(outsize < 0x10001 && inlen != 0)) return 0;

    uint8_t *buf   = win;          /* lVar5  = *param_1          */
    uint64_t wr    = base;         /* uVar7  = param_1[3]        */
    uint64_t end   = wr + outsize; /* uVar14 = out end           */
    uint64_t cur   = wr;           /* uVar15 = current out pos   */
    uint64_t start = wr;           /* local_48                   */
    uint64_t ip    = 0;            /* uVar8  = input cursor      */
    (void)winsz;

    do {
        uint8_t tok = in[ip++];                 /* bVar4 */
        uint64_t litlen = (uint64_t)(tok >> 4);
        if (litlen == 0xf) {
            uint8_t b;
            do {
                if (inlen <= ip) return 0;
                b = in[ip++];
                litlen += b;
            } while (b == 0xff);
        }
        if ((inlen - ip < litlen) || (end - cur < litlen)) return 0;
        memmove(buf + cur, in + ip, litlen);
        ip  += litlen;
        cur += litlen;
        if (ip >= inlen) break;

        if (inlen - ip < 2) return 0;
        uint64_t off = (uint64_t)in[ip] | ((uint64_t)in[ip + 1] << 8); /* u16 LE */
        if (off == 0 || cur < off) return 0;    /* offset can't precede buffer start */
        ip += 2;

        uint64_t mlen = (uint64_t)(tok & 0xf);
        if (mlen == 0xf) {
            uint8_t b;
            do {
                if (inlen <= ip) return 0;
                b = in[ip++];
                mlen += b;
            } while (b == 0xff);
        }
        uint64_t copy = mlen + 4;                /* min-match 4 */
        if (end - cur < copy) return 0;

        uint64_t srcpos = cur - off;             /* within buf, >= 0 since off <= cur */
        uint8_t *src = buf + srcpos;
        uint8_t *dst = buf + cur;
        if (copy < 0x10 ||
            ((uint64_t)dst <= (uint64_t)src + mlen + 3 &&
             (uint64_t)src <= (uint64_t)dst + mlen + 3)) {
            for (uint64_t k = 0; k < copy; k++) dst[k] = src[k];   /* overlap-safe */
        } else {
            memmove(dst, src, copy);
        }
        cur += copy;
    } while (ip < inlen);

    if (cur != end) return 0;                    /* must produce exactly outsize */

    uint64_t produced = end - start;
    if (produced <= outcap) memmove(outvec, buf + start, produced);
    return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 4) return 0;
    uint64_t outsize = (uint64_t)data[0] | ((uint64_t)data[1] << 8);   /* 0..65535 */
    uint64_t base    = (uint64_t)data[2] | ((uint64_t)data[3] << 8);   /* 0..65535 */
    const uint8_t *in = data + 4;
    uint64_t inlen = size - 4;

    uint64_t winsz = base + outsize;
    uint8_t *win = (uint8_t *)malloc(winsz ? winsz : 1);
    if (!win) return 0;
    /* prior window content [0,base): defined bytes from the input tail */
    if (inlen) { for (uint64_t i = 0; i < base; i++) win[i] = in[i % inlen]; }
    else       { memset(win, 0, base); }

    uint8_t *outvec = (uint8_t *)malloc(outsize ? outsize : 1);
    if (!outvec) { free(win); return 0; }

    decode(win, base, winsz, in, inlen, outsize, outvec, outsize);

    free(win);
    free(outvec);
    return 0;
}
