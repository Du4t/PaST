cmake_minimum_required(VERSION 3.10)
project(ftfuzz_runtime C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(fuzz_rt STATIC
    src/fuzz_rt.c
    src/distance_rt.c
    src/cmp_rt.c
    src/state_rt.c
    src/dgf_rt.c
)

target_include_directories(fuzz_rt PUBLIC include)
target_compile_options(fuzz_rt PRIVATE -O2 -g -Wall -Wextra -fPIC)
