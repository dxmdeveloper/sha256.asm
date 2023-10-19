; nasm intel style x64 Linux ABI
;
; based on: https://en.wikipedia.org/wiki/SHA-2#Pseudocode

section .text

global _sha256_chunk
sha256_calc_chunk: ;void sha256_calc_chunk(uint32_t hash[8], const uint8_t chunk[64])
    push rbp
    mov rbp, rsp

    ;u32 w[64] ; [rbp-256]
    ;assign to first 16 elements of w values from chunk (func arg). Sha256 is big endian, so we have to do bswap.
    %assign i 0
    %rep 16
        mov eax, [esi+4*i]
        bswap eax
        mov dword [ebp-256+4*i], eax
        %assign i i+1
    %endrep

    mov dword [ebp-288], 0x6a09e667 ; u32 a
    mov dword [ebp-284], 0xbb67ae85 ; u32 b
    mov dword [ebp-280], 0x3c6ef372 ; u32 c
    mov dword [ebp-276], 0xa54ff53a ; u32 d
    mov dword [ebp-272], 0x510e527f ; u32 e
    mov dword [ebp-268], 0x9b05688c ; u32 f
    mov dword [ebp-264], 0x1f83d9ab ; u32 g
    mov dword [ebp-260], 0x5be0cd19 ; u32 h

    ; move 1st and 2nd arg to temporary registers
    mov r10, rdi
    mov r11, rsi
    

    ; Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    ; for i from 16 to 63
    ;    s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
    ;    s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    ;    w[i] := w[i-16] + s0 + w[i-7] + s1
    %assign i 16
    %rep 48
        %assign wm15 i-15
        %assign wm2 i-2
        %assign wm7 i-7
        %assign wm16 i-16
        
        mov eax, [ebp-256+4*wm15]
        mov ecx, eax
        mov edx, eax
        ror eax, 7
        ror ecx, 18
        shr edx, 3
        xor eax, ecx
        xor eax, edx

        mov edx, [ebp-256+4*wm2]
        mov ecx, edx
        mov edi, edx
        ror edx, 17
        ror ecx, 19
        shr edi, 10
        xor edx, ecx
        xor edx, edi

        add eax, edx
        add eax, [ebp-256+4*wm7]
        add eax, [ebp-256+4*wm16]
        mov [ebp-256+4*i], eax
        %assign i i+1
    %endrep





global sha256
sha256: ; struct{uint64_t[4]} sha256(uint8_t data[n], size_t n)
    push rbp
    mov rbp, rsp
    ; don't forget to sub rsp

    ; u32 hash[8]
    mov dword [ebp-32], 0x6a09e667 ; hash[0] 
    mov dword [ebp-28], 0xbb67ae85 ; hash[1]
    mov dword [ebp-24], 0x3c6ef372 ; hash[2]
    mov dword [ebp-20], 0xa54ff53a ; hash[3]
    mov dword [ebp-16], 0x510e527f ; hash[4]
    mov dword [ebp-12], 0x9b05688c ; hash[5]
    mov dword [ebp-8],  0x1f83d9ab ; hash[6]
    mov dword [ebp-4],  0x5be0cd19 ; hash[7]

    leave
    ret

section .data

    k256 dd 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
         dd 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
         dd 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
         dd 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
         dd 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
         dd 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
         dd 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
         dd 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
         dd 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
         dd 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
         dd 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2