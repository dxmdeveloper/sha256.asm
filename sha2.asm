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

    ;Initialize working variables to current hash value:
    mov eax, [edi] ; a = hash[0]
    mov [ebp-288], eax ; u32 a [ebp-288]
    mov eax, [edi+4] 
    mov [ebp-284], eax ; u32 b [ebp-284]
    mov eax, [edi+8]
    mov [ebp-280], eax ; u32 c [ebp-280]
    mov eax, [edi+12]
    mov [ebp-276], eax ; u32 d [ebp-276]
    mov eax, [edi+16]
    mov [ebp-272], eax ; u32 e [ebp-272]
    mov eax, [edi+20]
    mov [ebp-268], eax ; u32 f [ebp-268]
    mov eax, [edi+24]
    mov [ebp-264], eax ; u32 g [ebp-264]
    mov eax, [edi+28]
    mov [ebp-260], eax ; u32 h [ebp-260]

    ; Move 1st arg to temporary register. Second argument will not be used again.
    mov r10, rdi
    
    ; Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    ; for i from 16 to 63
    ;    s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
    ;    s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    ;    w[i] := w[i-16] + s0 + w[i-7] + s1
    %assign i 16
    %rep 48    
        ; eax as S0
        mov eax, [ebp-256+4*(i-15)]
        mov ecx, eax
        mov edx, eax
        ror eax, 7
        ror ecx, 18
        shr edx, 3
        xor eax, ecx
        xor eax, edx

        ; edx as S1
        mov edx, [ebp-256+4*(i-2)]
        mov ecx, edx
        mov edi, edx
        ror edx, 17
        ror ecx, 19
        shr edi, 10
        xor edx, ecx
        xor edx, edi

        add eax, edx
        add eax, [ebp-256+4*(i-7)]
        add eax, [ebp-256+4*(i-16)]
        mov [ebp-256+4*i], eax
        %assign i i+1
    %endrep

    ; Compression function main loop:
    ; for i from 0 to 63
    ;     S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
    ;     ch := (e and f) xor ((not e) and g)
    ;     temp1 := h + S1 + ch + k[i] + w[i]
    ;     S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
    ;     maj := (a and b) xor (a and c) xor (b and c)
    ;     temp2 := S0 + maj

    %assign i 0
    %rep 64
        ; eax as S1
        mov eax, [ebp-272]
        mov ecx, eax
        mov edx, eax
        ror eax, 6
        ror ecx, 11
        ror edx, 25
        xor eax, ecx
        xor eax, edx

        ; ecx as ch
        mov ecx, [ebp-272]
        mov edx, ecx
        and ecx, [ebp-268]
        not edx
        and edx, [ebp-264]
        xor ecx, edx

        ; eax as temp1
        add eax, [ebp-260]
        add eax, [k256+4*i]
        add eax, [ebp-256+4*i]

        ; edi as S0
        mov edi, [ebp-288]
        mov ecx, edi
        mov edx, edi
        ror edi, 2
        ror ecx, 13
        ror edx, 22
        xor edi, ecx
        xor edi, edx

        ; ecx as maj
        mov ecx, [ebp-288]
        mov edx, ecx
        and ecx, [ebp-284] ; a and b
        and edx, [ebp-280] ; a and c
        xor ecx, edx
        mov edx, [ebp-284]
        and edx, [ebp-280] ; b and c
        xor ecx, edx
        
        ; edi as temp2
        add edi, ecx


        mov ecx, [ebp-264]
        mov [ebp-260], ecx ; h := g
        mov ecx, [ebp-268]
        mov [ebp-264], ecx ; g := f
        mov ecx, [ebp-272]
        mov [ebp-268], ecx ; f := e
        mov ecx, eax
        add ecx, [ebp-276]
        mov [ebp-272], eax ; e := d + temp1
        mov ecx, [ebp-280]
        mov [ebp-272], ecx ; d := c
        mov ecx, [ebp-284]
        mov [ebp-280], ecx ; c := b
        mov ecx, [ebp-288]
        mov [ebp-284], ecx ; b := a
        add eax, edi
        mov [ebp-288], eax ; a := temp1 + temp2

        %assign i i+1
    %endrep

    ; Add the compressed chunk to the current hash value:
    ; h0 := h0 + a
    ; h1 := h1 + b
    ; ...
    ; h7 := h7 + h
    %assign i 0
    %rep 8
        mov eax, [r10+i*4]
        add eax, [ebp-288+i*4]
        mov [r10+i*4], eax
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
