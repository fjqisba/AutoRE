#include "llmghidra/program/sleigh_context_metadata.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace llmghidra::program {

void SleighContextMetadataCollector::registerVariable(
    const std::string &name,
    ghidra::int4 start_bit,
    ghidra::int4 end_bit) {
    if (name.empty() || start_bit < 0 || end_bit < start_bit) {
        throw std::invalid_argument(
            "SLEIGH registered an invalid processor-context field");
    }
    if (static_cast<std::uint64_t>(end_bit) >=
        std::numeric_limits<std::uint32_t>::max()) {
        throw std::overflow_error(
            "SLEIGH processor-context field exceeds native metadata limits");
    }

    ghidra::ContextInternal::registerVariable(name, start_bit, end_bit);

    const ProcessorContextFieldDescription description{
        name,
        static_cast<std::uint32_t>(start_bit),
        static_cast<std::uint32_t>(end_bit)};
    const auto existing = std::ranges::find_if(
        fields_, [&](const auto &candidate) {
            return candidate.name == description.name;
        });
    if (existing == fields_.end()) {
        fields_.push_back(description);
    }
    else if (existing->start_bit != description.start_bit ||
             existing->end_bit != description.end_bit) {
        throw std::runtime_error(
            "SLEIGH re-registered a processor-context field with a different bit range");
    }

    context_blob_size_ = std::max(
        context_blob_size_,
        static_cast<std::uint32_t>(end_bit) / 8U + 1U);
}

const std::vector<ProcessorContextFieldDescription> &
SleighContextMetadataCollector::fields() const noexcept {
    return fields_;
}

std::uint32_t
SleighContextMetadataCollector::context_blob_size() const noexcept {
    return context_blob_size_;
}

} // namespace llmghidra::program
