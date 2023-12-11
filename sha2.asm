; nasm intel style. x64 Linux ABI compatibile
;
; based on: https://en.wikipedia.org/wiki/SHA-2#Pseudocode

section .text

%ifdef __win64__
%macro COMPATIBILITY_ENTER_ARGS_XCHG 0
    sub rsp, 16
    push rdi
    push rsi
    mov rdi, rcx ; must be preserved in windows
    mov rsi, rdx ; must be preserved in windows
    mov rdx, r8
    mov rcx, r9
%endmacro
%macro COMPATIBILITY_LEAVE_ARGS_XCHG_FIXUP 0
    pop rsi
    pop rdi
%endmacro
%else
%macro COMPATIBILITY_ENTER_ARGS_XCHG 0
%endmacro
%macro COMPATIBILITY_LEAVE_ARGS_XCHG_FIXUP 0
%endmacro
%endif

; Windows ABI incompatible function.
; Unaffected general-purpose registers: rbx, rdi, r10-r15
_asm_sha256_push_chunk: ;void _asm_sha256_push_chunk(uint32_t hash[8], const uint8_t chunk[64])
    push rbp
    mov rbp, rsp
    sub rsp, 296
    push rbx

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
    mov rcx, 16
    extension_loop:
        ; eax as S0
        mov eax, [rbp-256+4*(rcx-15)]
        mov ebx, eax
        mov edx, eax
        ror eax, 7
        ror ebx, 18
        shr edx, 3
        xor eax, ebx
        xor eax, edx

        ; edx as S1
        mov edx, [rbp-256+(rcx-2)*4]
        mov ebx, edx
        mov edi, edx
        ror edx, 17
        ror ebx, 19
        shr edi, 10
        xor edx, ebx
        xor edx, edi

        add eax, edx
        add eax, [rbp-256+(rcx-7)*4]
        add eax, [rbp-256+(rcx-16)*4]
        mov [rbp-256+rcx*4], eax

        inc rcx
        cmp rcx, 64
        jnz extension_loop

    ; Compression function main loop:
    ; for i from 0 to 63
    ;     S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
    ;     ch := (e and f) xor ((not e) and g)
    ;     temp1 := h + S1 + ch + k[i] + w[i]
    ;     S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
    ;     maj := (a and b) xor (a and c) xor (b and c)
    ;     temp2 := S0 + maj

    xor rcx, rcx
    compression_loop:
        ; eax as S1
        mov eax, [rbp-272] ; e
        mov ebx, eax
        mov edx, eax
        ror eax, 6
        ror ebx, 11
        ror edx, 25
        xor eax, ebx
        xor eax, edx

        ; ebx as ch
        mov ebx, [rbp-272] ; e
        mov edx, ebx
        and ebx, [rbp-268] ; e and f
        not edx
        and edx, [rbp-264] ; ~e and g
        xor ebx, edx

        ; eax as temp1
        add eax, [rbp-260]        ; h
        add eax, [k256+rcx*4]     ; k[i]
        add eax, [rbp-256+rcx*4]  ; w[i]
        add eax, ebx              ; ch

        ; edi as S0
        mov edi, [rbp-288] ; a
        mov ebx, edi
        mov edx, edi
        ror edi, 2
        ror ebx, 13
        ror edx, 22
        xor edi, ebx
        xor edi, edx

        ; ebx as maj
        mov ebx, [rbp-288] ; a
        mov edx, ebx
        and ebx, [rbp-284] ; a and b
        and edx, [rbp-280] ; a and c
        xor ebx, edx
        mov edx, [rbp-284] ; b
        and edx, [rbp-280] ; b and c
        xor ebx, edx
        
        ; edi as temp2
        add edi, ebx

        ; eax == temp1
        ; edi == temp2
        mov ebx, [rbp-264]
        mov [rbp-260], ebx ; h := g
        mov ebx, [rbp-268]
        mov [rbp-264], ebx ; g := f
        mov ebx, [rbp-272]
        mov [rbp-268], ebx ; f := e
        mov ebx, eax
        add ebx, [rbp-276]
        mov [rbp-272], ebx ; e := d + temp1
        mov ebx, [rbp-280]
        mov [rbp-276], ebx ; d := c
        mov ebx, [rbp-284]
        mov [rbp-280], ebx ; c := b
        mov ebx, [rbp-288]
        mov [rbp-284], ebx ; b := a
        add eax, edi
        mov [rbp-288], eax ; a := temp1 + temp2

        inc rcx
        cmp rcx, 64
        jnz compression_loop

    ; Add the compressed chunk to the current hash value:
    ; h0 := h0 + a
    ; h1 := h1 + b
    ; ...
    ; h7 := h7 + h
    mov rcx, 7
    hash_add_loop:
        mov eax, [r9+rcx*4]
        add eax, [rbp-288+rcx*4]
        mov [r9+rcx*4], eax
        sub rcx, 1
        jnc hash_add_loop

    ; function ending
    mov rdi, r9
    pop rbx

    mov rsp, rbp
    pop rbp
    ret
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

global asm_sha256_calc
asm_sha256_calc: ; void asm_sha256_calc(uint8_t hash[8], uint8_t data[n], size_t len)
    push rbp
    mov rbp, rsp
    sub rsp, 88

    COMPATIBILITY_ENTER_ARGS_XCHG
    push r12

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

    foreach_full_chunk:
        cmp r11, 64
        jc sha_padding

        mov rsi, r10
        call _asm_sha256_push_chunk

        add r10, 64
        sub r11, 64
        jmp foreach_full_chunk

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
        ; if (last_chunk_len >= 56) {
        lea rsi, [rbp-64]
        call _asm_sha256_push_chunk
        mov rcx, 6
        zero_init_chunk2:
            mov qword [rbp-64+rcx*8], 0
            sub rcx, 1
            jnc zero_init_chunk2
        ; }
        append_bit_len:
            shl r12, 3 ; len * 8
            bswap r12
            mov [rbp-8], r12

        lea rsi, [rbp-64]
        call _asm_sha256_push_chunk


    ; function ending
    xor rax, rax ; return 0 (return value was used for debugging only)

    pop r12
    COMPATIBILITY_LEAVE_ARGS_XCHG_FIXUP

    mov rsp, rbp
    pop rbp
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