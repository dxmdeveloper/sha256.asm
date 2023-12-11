#pragma once
#include <stdlib.h>
#include <stdint.h>

#define SHA256_CHUNK_SIZE 64

void csha256_push_chunk(uint32_t hash[8], const uint8_t chunk[64]);

void csha256_calc(uint32_t hash[8], const uint8_t *data, size_t len);

extern const uint32_t k256[64];
extern const uint32_t init_hash256[8];