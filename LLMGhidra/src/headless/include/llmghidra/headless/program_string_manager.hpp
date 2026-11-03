#pragma once

#include "stringmanage.hh"

namespace llmghidra::program {
class Program;
}

namespace llmghidra::headless {

class ProgramStringRecord;

// Native replacement for DecompileCallback.getStringData(). Queries are
// resolved against ProgramDB Listing, data-types, instance settings, property
// maps and memory without a Java callback process.
class ProgramStringManager final : public ghidra::StringManager {
public:
    ProgramStringManager(program::Program &program,
                         ghidra::int4 maximum_characters);

    const std::vector<ghidra::uint1> &getStringData(
        const ghidra::Address &address,
        ghidra::Datatype *character_type,
        bool &is_truncated) override;

private:
    void populate_defined_string(
        StringData &destination,
        const ghidra::Address &decompiler_address,
        const ghidra::Datatype &query_type,
        const ProgramStringRecord &record);
    void populate_probed_string(
        StringData &destination,
        const ghidra::Address &decompiler_address,
        const ghidra::Datatype &character_type);

    program::Program *program_{};
};

} // namespace llmghidra::headless
