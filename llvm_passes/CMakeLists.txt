cmake_minimum_required(VERSION 3.16)
project(ftfuzz_llvm_passes C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(LLVM REQUIRED CONFIG)

include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

add_library(TargetDistancePass MODULE
    target_distance_pass/TargetDistancePass.cpp
)
target_include_directories(TargetDistancePass PRIVATE common)
target_compile_options(TargetDistancePass PRIVATE -fno-rtti -fPIC -O2)

add_library(CmpBarrierPass MODULE
    cmp_barrier_pass/CmpBarrierPass.cpp
)
target_include_directories(CmpBarrierPass PRIVATE common)
target_compile_options(CmpBarrierPass PRIVATE -fno-rtti -fPIC -O2)

add_library(StateHitPass MODULE
    state_hit_pass/StateHitPass.cpp
)
target_include_directories(StateHitPass PRIVATE common)
target_compile_options(StateHitPass PRIVATE -fno-rtti -fPIC -O2)
