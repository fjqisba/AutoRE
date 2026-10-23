#pragma once

#include "llmghidra/program/program_architecture.hpp"

#include "globalcontext.hh"

#include <cstdint>
#include <vector>

namespace llmghidra::program {

// ContextDatabase used during the first SLEIGH initialization pass.  SLEIGH
// registers every processor-context field through registerVariable(); this
// collector keeps the exact absolute bit ranges while retaining the complete
// ContextInternal behavior needed by the decoder during that pass.
class SleighContextMetadataCollector final : public ghidra::ContextInternal {
public:
    void registerVariable(const std::string &name,
                          ghidra::int4 start_bit,
                          ghidra::int4 end_bit) override;

    [[nodiscard]] const std::vector<ProcessorContextFieldDescription> &
    fields() const noexcept;
    [[nodiscard]] std::uint32_t context_blob_size() const noexcept;

private:
    std::vector<ProcessorContextFieldDescription> fields_;
    std::uint32_t context_blob_size_{};
};

} // namespace llmghidra::program
