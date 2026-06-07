cmake_minimum_required(VERSION 3.20)
project(TaprootVanity LANGUAGES CXX)

option(ENABLE_CUDA "Build CUDA vanity generator" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_library(taproot_vanity_core
    src/taproot_vanity.cpp
)
target_include_directories(taproot_vanity_core PUBLIC include)
target_link_libraries(taproot_vanity_core PUBLIC OpenSSL::Crypto)
target_compile_options(taproot_vanity_core PRIVATE -Wall -Wextra -Wpedantic -O3)
target_compile_definitions(taproot_vanity_core PRIVATE OPENSSL_SUPPRESS_DEPRECATED)

add_executable(taproot-vanity src/main.cpp)
target_link_libraries(taproot-vanity PRIVATE taproot_vanity_core)

if(ENABLE_CUDA)
  enable_language(CUDA)
  add_executable(taproot-vanity-cuda src/cuda/taproot_vanity_cuda.cu src/cuda/main_cuda.cpp)
  target_include_directories(taproot-vanity-cuda PRIVATE include)
  target_link_libraries(taproot-vanity-cuda PRIVATE taproot_vanity_core OpenSSL::Crypto)
  set_target_properties(taproot-vanity-cuda PROPERTIES CUDA_STANDARD 20 CUDA_STANDARD_REQUIRED ON CUDA_ARCHITECTURES "75;80;86;89;90")
  target_compile_options(taproot-vanity-cuda PRIVATE $<$<COMPILE_LANGUAGE:CUDA>:--use_fast_math;-O3;-Xptxas=-O3,-v;-lineinfo>)
endif()
