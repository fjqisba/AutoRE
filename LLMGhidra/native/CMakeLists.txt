cmake_minimum_required(VERSION 3.24)
project(LLMGhidraNative LANGUAGES C CXX)

# 原生算法参考及兼容性工具独立构建，不进入 Cargo 默认构建链。
option(LLMGHIDRA_BUILD_SLEIGH_COMPILER "Build the native SLEIGH compiler" OFF)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
include(cmake/NativeSources.cmake)

add_library(llmghidra_native_abi INTERFACE)
if(MSVC)
    # 跨静态库传递 STL 对象时，调用方必须使用同一迭代器 ABI。
    target_compile_definitions(llmghidra_native_abi INTERFACE
        _ITERATOR_DEBUG_LEVEL=0 _SECURE_SCL=0 _HAS_ITERATOR_DEBUGGING=0 NOMINMAX)
endif()

function(llmghidra_configure_native_target target)
    target_link_libraries(${target} PUBLIC llmghidra_native_abi)
    target_include_directories(${target} PUBLIC "${GHIDRA_DECOMPILER_CPP_DIR}")
    if(MSVC)
        target_compile_definitions(${target} PRIVATE
            WINDOWS _WINDOWS WIN32 _WIN32 _CRT_SECURE_NO_WARNINGS)
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            target_compile_definitions(${target} PRIVATE WIN64 _WIN64)
        endif()
        target_compile_options(${target} PRIVATE /EHsc /W3 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wno-sign-compare -Wno-unused-parameter)
        if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
            target_compile_definitions(${target} PRIVATE LINUX _LINUX)
        endif()
    endif()
endfunction()

file(GLOB GHIDRA_LOCAL_ZLIB_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/decompiler/zlib/*.c")
add_library(ghidra_local_zlib STATIC ${GHIDRA_LOCAL_ZLIB_SOURCES})
target_include_directories(ghidra_local_zlib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/decompiler/zlib")
target_compile_definitions(ghidra_local_zlib PRIVATE NO_GZIP)
if(MSVC)
    target_compile_definitions(ghidra_local_zlib PRIVATE
        _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_DEPRECATE ZLIB_WINAPI)
endif()

# 公共源只编译一次，避免 decompiler 与 SLEIGH 同时链接时出现重复定义。
add_library(ghidra_native_common STATIC ${GHIDRA_NATIVE_SHARED_SOURCES})
llmghidra_configure_native_target(ghidra_native_common)
add_library(ghidra_decompiler_core STATIC ${GHIDRA_DECOMPILER_CORE_SOURCES})
llmghidra_configure_native_target(ghidra_decompiler_core)
target_link_libraries(ghidra_decompiler_core PUBLIC ghidra_native_common)
add_library(ghidra_sleigh STATIC ${GHIDRA_SLEIGH_RUNTIME_SOURCES})
llmghidra_configure_native_target(ghidra_sleigh)
target_compile_definitions(ghidra_sleigh PRIVATE LOCAL_ZLIB NO_GZIP)
target_link_libraries(ghidra_sleigh PUBLIC ghidra_native_common ghidra_local_zlib)

if(LLMGHIDRA_BUILD_SLEIGH_COMPILER)
    add_executable(llmghidra-sleigh-compiler ${GHIDRA_SLEIGH_COMPILER_SOURCES})
    llmghidra_configure_native_target(llmghidra-sleigh-compiler)
    target_compile_definitions(llmghidra-sleigh-compiler PRIVATE LOCAL_ZLIB NO_GZIP)
    target_link_libraries(llmghidra-sleigh-compiler PRIVATE ghidra_local_zlib)
    if(MSVC)
        target_compile_definitions(llmghidra-sleigh-compiler PRIVATE _CRT_NONSTDC_NO_DEPRECATE)
    endif()
endif()
