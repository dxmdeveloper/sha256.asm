#include "sha256.asm/csha256.h"
#include <memory.h>

#define bswap32(x) ((uint32_t)(x << 24 | (x << 8 & 0x00ff0000) | (x >> 8 & 0x0000ff00) | x >> 24))
#define bswap64(x) (((uint64_t)bswap32((x))) << 32 | bswap32((x) >> 32))
#define rotr32(x, n) (uint32_t)(x >> n | x << (32 - n))

void csha256_calc(uint32_t *hash, const uint8_t *data, size_t len)
{
    memcpy(hash, init_hash256, 8 * sizeof(uint32_t));

    for (size_t i = 0; i < len / 64; i++) {
        csha256_calc_chunk(hash, data+i*8);
    }

    //  --- last chunk with padding ---
    uint8_t chunk[64] = { 0 }; // null initialized chunk
    size_t last_chunk_size = len % 64;

    memcpy(chunk, data + len - last_chunk_size, last_chunk_size);
    chunk[last_chunk_size] = 0x80; // 0b10000000

    if (last_chunk_size > 56) {
        // last chunk is too small to hold L (bit_len), so we need another chunk
        csha256_calc_chunk(hash, chunk);
        memset(chunk, 0, 56); // initialize new chunk
    }

    uint64_t bit_len = len * 8;
    bit_len = bswap64(bit_len);
    memcpy(chunk + 56, &bit_len, 8);

    csha256_calc_chunk(hash, chunk);
}

void csha256_calc_chunk(uint32_t hash[8], const uint8_t chunk[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;

    for (int i = 0; i < 16; i++)
        w[i] = bswap32(((uint32_t *) chunk)[i]); // Little endian to big endian

    for (int i = 16; i < 64; i++) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ w[i - 15] >> 3;
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ w[i - 2] >> 10;
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    e = hash[4];
    f = hash[5];
    g = hash[6];
    h = hash[7];

    for (int i = 0; i < 64; i++) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t temp1 = h + S1 + ch + k256[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

const uint32_t k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t init_hash256[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

