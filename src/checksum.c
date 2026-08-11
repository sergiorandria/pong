/* Copyright (c) 2025 Sergio Randriamihoatra.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "checksum.h"

#include <string.h>

/* ────────────────────────────────────────────────────────────────────────────
 * Checksum (RFC 1071).
 *
 * The buffer is summed as 8-byte words into a 64-bit accumulator.  A plain
 * 64-bit addition would lose the carry out of bit 63, so every carry is folded
 * back into the accumulator (the classic `sum += w; if (sum < w) sum++`), which
 * keeps the accumulator congruent to the true one's-complement sum modulo
 * 2^64-1.  Four fixed folds then reduce it to 16 bits.
 *
 * On x86-64 the inner loop is inline assembly using the ADC instruction, which
 * chains the carry flag directly across additions; the loop is unrolled four
 * 8-byte words per iteration and the final carry out is folded with `adc $0`.
 * A portable unrolled-by-four fallback is used elsewhere.
 * ──────────────────────────────────────────────────────────────────────────*/

uint16_t checksum(const void *data, size_t len)
{
    const uint8_t *p  = (const uint8_t *)data;
    uint64_t       sum = 0;
    size_t         g4  = len >> 5;        /* groups of 32 bytes */
    size_t         rqw = (len >> 3) & 3;  /* leftover 8-byte words */
    size_t         rem = len & 7;         /* leftover bytes */

#if defined(__x86_64__) && defined(__GNUC__)
    __asm__ volatile(
        "clc\n\t"
        "testq %[n], %[n]\n\t"
        "jz 2f\n\t"
        "1:\n\t"
        "adcq 0(%[p]), %[s]\n\t"
        "adcq 8(%[p]), %[s]\n\t"
        "adcq 16(%[p]), %[s]\n\t"
        "adcq 24(%[p]), %[s]\n\t"
        "leaq 32(%[p]), %[p]\n\t"  /* lea preserves CF (addq would clobber it) */
        "decq %[n]\n\t"
        "jnz 1b\n\t"
        "adcq $0, %[s]\n\t"          /* fold the final carry out of bit 63 */
        "2:\n\t"
        : [s] "+r"(sum), [p] "+r"(p), [n] "+r"(g4)
        : : "cc", "memory");
#else
    while (g4--) {
        uint64_t w0, w1, w2, w3;
        memcpy(&w0, p + 0, 8);
        memcpy(&w1, p + 8, 8);
        memcpy(&w2, p + 16, 8);
        memcpy(&w3, p + 24, 8);
        sum += w0; if (sum < w0) sum++;   /* fold carry out of bit 63 */
        sum += w1; if (sum < w1) sum++;
        sum += w2; if (sum < w2) sum++;
        sum += w3; if (sum < w3) sum++;
        p += 32;
    }
#endif

    while (rqw--) {
        uint64_t w;
        memcpy(&w, p, 8);
        sum += w;
        if (sum < w) sum++;               /* fold carry out of bit 63 */
        p += 8;
    }
    if (rem & 4) { uint32_t w; memcpy(&w, p, 4); sum += w; p += 4; }
    if (rem & 2) { uint16_t w; memcpy(&w, p, 2); sum += w; p += 2; }
    /* Odd tail byte: it sits at an even index, i.e. the high byte of its
     * on-wire word (RFC 1071 pads it with a zero on the right).  Read as a
     * native word the pair is {byte, 0}, so add the raw byte value. */
    if (rem & 1) sum += *p;

    /* Four fixed folds always reduce the accumulator below 2^16:
     * after fold k the value is < 2^(64-16k) + 2^16, so fold 3 leaves
     * a value <= 0x1fffe and fold 4 therefore <= 0xffff. */
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}
