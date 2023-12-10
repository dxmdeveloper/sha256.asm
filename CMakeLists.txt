cmake_minimum_required(VERSION 3.26)
project(sha256asm C ASM_NASM)

set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)
set(CMAKE_C_STANDARD 99)

include_directories(..)
set_source_files_properties(sha2.asm PROPERTIES COMPILE_FLAGS "-f elf64")

add_executable(sha256asm
        csha256.h
        main.c
        csha256.c
        sha2.asm)

set_target_properties(sha256asm PROPERTIES LINK_FLAGS "-no-pie")