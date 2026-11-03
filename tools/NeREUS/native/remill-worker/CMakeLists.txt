cmake_minimum_required(VERSION 3.21)
project(nereus_remill_worker LANGUAGES C CXX)

find_package(remill CONFIG REQUIRED)
add_executable(nereus-remill-worker main.cpp)
target_compile_features(nereus-remill-worker PRIVATE cxx_std_17)
target_link_libraries(nereus-remill-worker PRIVATE remill)
target_include_directories(nereus-remill-worker SYSTEM PRIVATE ${LLVM_INCLUDE_DIRS})
file(READ "${CMAKE_CURRENT_LIST_DIR}/../../toolchains/versions.lock.json" nereus_versions)
string(JSON nereus_remill_revision GET "${nereus_versions}" remill revision)
target_compile_definitions(nereus-remill-worker PRIVATE
  NEREUS_REMILL_REVISION="${nereus_remill_revision}")
install(TARGETS nereus-remill-worker RUNTIME DESTINATION bin)
