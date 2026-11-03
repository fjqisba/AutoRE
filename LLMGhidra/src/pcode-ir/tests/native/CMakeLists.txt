cmake_minimum_required(VERSION 3.24)
project(pcode_ir_oracle LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
get_filename_component(LLMGHIDRA_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../../.." ABSOLUTE)
# 直接从当前项目源码构建 oracle 依赖，不再依赖旧工作树里的 .lib。
add_subdirectory("${LLMGHIDRA_ROOT}/native" "${CMAKE_CURRENT_BINARY_DIR}/ghidra-native")
add_executable(pcode_ir_oracle oracle.cc)
target_link_libraries(pcode_ir_oracle PRIVATE
    ghidra_decompiler_core ghidra_sleigh)
