/* Minimal BLAKE2b with outlen=16 — matches Python hashlib.blake2b(digest_size=16).
 * Based on RFC 7693 reference (public domain / CC0). */
#ifndef BOGI_BLAKE2B16_H
#define BOGI_BLAKE2B16_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint64_t B2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};

static const uint8_t B2B_SIGMA[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

static uint64_t b2b_rotr64(uint64_t x, unsigned n) {
  return (x >> n) | (x << (64 - n));
}

static void b2b_g(uint64_t v[16], int a, int b, int c, int d, uint64_t x, uint64_t y) {
  v[a] = v[a] + v[b] + x;
  v[d] = b2b_rotr64(v[d] ^ v[a], 32);
  v[c] = v[c] + v[d];
  v[b] = b2b_rotr64(v[b] ^ v[c], 24);
  v[a] = v[a] + v[b] + y;
  v[d] = b2b_rotr64(v[d] ^ v[a], 16);
  v[c] = v[c] + v[d];
  v[b] = b2b_rotr64(v[b] ^ v[c], 63);
}

static void b2b_compress(uint64_t h[8], const uint8_t block[128], uint64_t t0,
                         uint64_t t1, int last) {
  uint64_t m[16], v[16];
  for (int i = 0; i < 16; i++) {
    m[i] = (uint64_t)block[i * 8 + 0] | ((uint64_t)block[i * 8 + 1] << 8) |
           ((uint64_t)block[i * 8 + 2] << 16) | ((uint64_t)block[i * 8 + 3] << 24) |
           ((uint64_t)block[i * 8 + 4] << 32) | ((uint64_t)block[i * 8 + 5] << 40) |
           ((uint64_t)block[i * 8 + 6] << 48) | ((uint64_t)block[i * 8 + 7] << 56);
  }
  for (int i = 0; i < 8; i++) v[i] = h[i];
  for (int i = 0; i < 8; i++) v[i + 8] = B2B_IV[i];
  v[12] ^= t0;
  v[13] ^= t1;
  if (last) v[14] = ~v[14];
  for (int r = 0; r < 12; r++) {
    const uint8_t *s = B2B_SIGMA[r];
    b2b_g(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    b2b_g(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    b2b_g(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    b2b_g(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    b2b_g(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    b2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    b2b_g(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    b2b_g(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
  }
  for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

static void blake2b16(const uint8_t *data, size_t n, uint8_t out[16]) {
  uint64_t h[8];
  for (int i = 0; i < 8; i++) h[i] = B2B_IV[i];
  /* param block: digest_length=16, key_length=0, fanout=1, depth=1, ... */
  h[0] ^= 0x01010000ull | 16ull;

  uint8_t block[128];
  uint64_t t0 = 0, t1 = 0;
  size_t off = 0;
  while (n - off > 128) {
    memcpy(block, data + off, 128);
    t0 += 128;
    if (t0 < 128) t1++;
    b2b_compress(h, block, t0, t1, 0);
    off += 128;
  }
  size_t left = n - off;
  memset(block, 0, 128);
  if (left) memcpy(block, data + off, left);
  t0 += (uint64_t)left;
  if (t0 < left) t1++;
  b2b_compress(h, block, t0, t1, 1);
  for (int i = 0; i < 16; i++)
    out[i] = (uint8_t)((h[i / 8] >> (8 * (i % 8))) & 0xff);
}

#endif
