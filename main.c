#include <stdio.h>
#include <stdint.h>
#include "csha256.h"

extern uint64_t asm_sha256_calc(uint32_t *hash, uint8_t *data, size_t len);

int main(){
    char message64[] = "sha message of length 64 bytes. 12345678901234567834534534512113";
    uint32_t hash[8] = { 0 };

    asm_sha256_calc(hash, (uint8_t*)message64, sizeof(message64) - 1);

    printf("asm: %08x%08x%08x%08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);

    csha256_calc(hash, (uint8_t*)message64, sizeof(message64) - 1);

    printf("  C: %08x%08x%08x%08x%08x%08x%08x%08x\n", hash[0], hash[1], hash[2], hash[3], hash[4], hash[5], hash[6], hash[7]);
    return 0;
}