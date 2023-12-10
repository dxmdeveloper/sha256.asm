; nasm intel style x64 Linux ABI
;
; based on: https://en.wikipedia.org/wiki/SHA-2#Pseudocode

section .text

%ifdef __win64__
%macro linux_abi_args_conv 0
    sub rsp, 16
    push rdi
    push rsi
    mov rdi, rcx ; must be preserved in windows
    mov rsi, rdx ; must be preserved in windows
    mov rdx, r8
    mov rcx, r9
%endmacro
%macro linux_abi_args_conv_pre_ret 0
    pop rsi
    pop rdi
%endmacro
%else
%macro linux_abi_args_conv 0
%endmacro
%macro linux_abi_args_conv_pre_ret 0
%endmacro
%endif

global _sha256_calc_chunk
_sha256_calc_chunk: ;void _sha256_calc_chunk(uint32_t hash[8], const uint8_t chunk[64])
    push rbp
    mov rbp, rsp

    mov rcx, 15
    endianess_ch_loop:
        mov eax, [rsi+rcx*4]
        bswap eax
        mov [rbp-256+rcx*4], eax
        sub rcx, 1
        jnc endianess_ch_loop

    ;Initialize working variables to current hash value:
    mov eax, [rdi] ; a = hash[0]
    mov [rbp-288], eax ; u32 a [rbp-288]
    mov eax, [rdi+4]
    mov [rbp-284], eax ; u32 b [rbp-284]
    mov eax, [rdi+8]
    mov [rbp-280], eax ; u32 c [rbp-280]
    mov eax, [rdi+12]
    mov [rbp-276], eax ; u32 d [rbp-276]
    mov eax, [rdi+16]
    mov [rbp-272], eax ; u32 e [rbp-272]
    mov eax, [rdi+20]
    mov [rbp-268], eax ; u32 f [rbp-268]
    mov eax, [rdi+24]
    mov [rbp-264], eax ; u32 g [rbp-264]
    mov eax, [rdi+28]
    mov [rbp-260], eax ; u32 h [rbp-260]

    ; Move 1st arg to temporary register. Second argument will not be used again.
    mov r9, rdi

    ; Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
    ; for i from 16 to 63
    ;    s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
    ;    s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)
    ;    w[i] := w[i-16] + s0 + w[i-7] + s1
    %assign i 16
    %rep 48    
        ; eax as S0
        mov eax, [rbp-256+4*(i-15)]
        mov ecx, eax
        mov edx, eax
        ror eax, 7
        ror ecx, 18
        shr edx, 3
        xor eax, ecx
        xor eax, edx

        ; edx as S1
        mov edx, [rbp-256+4*(i-2)]
        mov ecx, edx
        mov edi, edx
        ror edx, 17
        ror ecx, 19
        shr edi, 10
        xor edx, ecx
        xor edx, edi

        add eax, edx
        add eax, [rbp-256+4*(i-7)]
        add eax, [rbp-256+4*(i-16)]
        mov [rbp-256+4*i], eax
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

    compression:
    %assign i 0
    %rep 64
        ; eax as S1
        mov eax, [rbp-272] ; e
        mov ecx, eax
        mov edx, eax
        ror eax, 6
        ror ecx, 11
        ror edx, 25
        xor eax, ecx
        xor eax, edx

        ; ecx as ch
        mov ecx, [rbp-272]
        mov edx, ecx
        and ecx, [rbp-268]
        not edx
        and edx, [rbp-264]
        xor ecx, edx

        ; eax as temp1
        add eax, [rbp-260]      ; h
        add eax, [k256+i*4]     ; k[i]
        add eax, [rbp-256+i*4]  ; w[i]
        add eax, ecx            ; ch

        ; edi as S0
        mov edi, [rbp-288]
        mov ecx, edi
        mov edx, edi
        ror edi, 2
        ror ecx, 13
        ror edx, 22
        xor edi, ecx
        xor edi, edx

        ; ecx as maj
        mov ecx, [rbp-288]
        mov edx, ecx
        and ecx, [rbp-284] ; a and b
        and edx, [rbp-280] ; a and c
        xor ecx, edx
        mov edx, [rbp-284]
        and edx, [rbp-280] ; b and c
        xor ecx, edx
        
        ; edi as temp2
        add edi, ecx

        ; eax == temp1
        ; edi == temp2

        mov ecx, [rbp-264]
        mov [rbp-260], ecx ; h := g
        mov ecx, [rbp-268]
        mov [rbp-264], ecx ; g := f
        mov ecx, [rbp-272]
        mov [rbp-268], ecx ; f := e
        mov ecx, eax
        add ecx, [rbp-276]
        mov [rbp-272], ecx ; e := d + temp1
        mov ecx, [rbp-280]
        mov [rbp-276], ecx ; d := c
        mov ecx, [rbp-284]
        mov [rbp-280], ecx ; c := b
        mov ecx, [rbp-288]
        mov [rbp-284], ecx ; b := a
        add eax, edi
        mov [rbp-288], eax ; a := temp1 + temp2

        %assign i i+1
    %endrep

    ; Add the compressed chunk to the current hash value:
    ; h0 := h0 + a
    ; h1 := h1 + b
    ; ...
    ; h7 := h7 + h
    %assign i 0
    %rep 8
        mov eax, [r9+i*4]
        add eax, [rbp-288+i*4]
        mov [r9+i*4], eax
        %assign i i+1
    %endrep

    mov rdi, r9

    leave
    ret

global asm_sha256_calc
asm_sha256_calc: ; void asm_sha256_calc(uint8_t hash[8], uint8_t data[n], size_t len)
    push rbp
    mov rbp, rsp
    sub rsp, 96

    push rbx
    push r12

    linux_abi_args_conv

    ; u32 hash[8]
    mov dword [rdi],    0x6a09e667 ; hash[0]
    mov dword [rdi+4],  0xbb67ae85 ; hash[1]
    mov dword [rdi+8],  0x3c6ef372 ; hash[2]
    mov dword [rdi+12], 0xa54ff53a ; hash[3]
    mov dword [rdi+16], 0x510e527f ; hash[4]
    mov dword [rdi+20], 0x9b05688c ; hash[5]
    mov dword [rdi+24], 0x1f83d9ab ; hash[6]
    mov dword [rdi+28], 0x5be0cd19 ; hash[7]

    mov r10, rsi ; r10 == data
    mov r11, rdx ; r11 == len (arg)
    mov r12, rdx ; r12 == const len (for later)
    cmp r11, 64
    jc sha_padding
    foreach_full_chunk:
        mov rsi, r10
        call _sha256_calc_chunk

        add r10, 64
        sub r11, 64
        jl sha_padding

    sha_padding:
        mov r11, r12
        and r11, 63 ; r11 %= 64 last_chunk_len

        mov rcx, 7
        zero_init_chunk1:
            mov qword [rbp-64+rcx*8], 0
            sub rcx, 1
            jnc zero_init_chunk1

        xor rcx, rcx
        pad_memcpy:
            cmp rcx, r11 ; r11 is last_chunk_len
            jz pad_memcpy_end
            mov al, [r10+rcx]
            mov [rbp-64+rcx], al
            inc rcx
            jmp pad_memcpy

        pad_memcpy_end:

        ; append a bit 1
        mov byte [rbp-64+r11], 0x80
        cmp r11, 56
        jc append_bit_len
        ; if last_chunk_len > 56
        lea rsi, [rbp-64]
        call _sha256_calc_chunk
        mov rcx, 6
        zero_init_chunk2:
            mov qword [rbp-64+rcx*8], 0
            sub rcx, 1
            jnc zero_init_chunk2

        append_bit_len:
            shl r12, 3 ; len * 8
            bswap r12
            mov [rbp-8], r12

        lea rsi, [rbp-64]
        call _sha256_calc_chunk

    xor rax, rax

    pop r12
    pop rbx
    linux_abi_args_conv_pre_ret
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