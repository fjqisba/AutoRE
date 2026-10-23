#pragma once

#include <memory>

namespace ghidra {
class ConstantPool;
}

namespace llmghidra::headless {

class ProgramSleighArchitecture;

// Selects the processor-specific, fully native constant-pool provider declared
// by the selected pspec. Languages without deferred constants receive the
// standard empty in-memory pool.
[[nodiscard]] std::unique_ptr<ghidra::ConstantPool>
build_program_constant_pool(ProgramSleighArchitecture &architecture);

} // namespace llmghidra::headless
