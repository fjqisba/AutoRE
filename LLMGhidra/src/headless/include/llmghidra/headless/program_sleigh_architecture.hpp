#pragma once

#include "llmghidra/program/language.hpp"
#include "llmghidra/program/persistent_address_map.hpp"

#include "sleigh_arch.hh"

#include <filesystem>
#include <memory>
#include <ostream>

namespace llmghidra::db {
class DatabaseHandle;
}

namespace llmghidra::program {
class Program;
class SleighContextMetadataCollector;
}

namespace llmghidra::headless {

class ProgramLoadImage;
class ProgramTypeFactory;

// Fully native decompiler Architecture bound to one ProgramDB.  It loads the
// exact processor/compiler/SLEIGH resources selected by the database and
// replaces the bootstrap context collector with the persistent ProgramDB
// context provider before any instruction is decoded.
class ProgramSleighArchitecture final : public ghidra::SleighArchitecture {
public:
    ProgramSleighArchitecture(
        program::Program &program,
        program::LanguageDescription language,
        program::ProcessorSpec processor_spec,
        program::CompilerSpec compiler_spec,
        std::ostream &errors);
    ~ProgramSleighArchitecture() override;

    [[nodiscard]] program::Program &program() noexcept;
    [[nodiscard]] const program::Program &program() const noexcept;
    [[nodiscard]] const program::LanguageDescription &language() const noexcept;
    [[nodiscard]] const program::ProcessorSpec &processor_spec() const noexcept;
    [[nodiscard]] const program::CompilerSpec &compiler_spec() const noexcept;
    [[nodiscard]] ghidra::Datatype *resolve_program_data_type(
        std::int64_t id, ghidra::int4 size_hint = 0);

protected:
    void buildLoader(ghidra::DocumentStorage &store) override;
    ghidra::Scope *buildDatabase(ghidra::DocumentStorage &store) override;
    ghidra::Translate *buildTranslator(
        ghidra::DocumentStorage &store) override;
    void buildContext(ghidra::DocumentStorage &store) override;
    void buildTypegrp(ghidra::DocumentStorage &store) override;
    void buildCommentDB(ghidra::DocumentStorage &store) override;
    void buildStringManager(ghidra::DocumentStorage &store) override;
    void buildConstantPool(ghidra::DocumentStorage &store) override;
    void buildSymbols(ghidra::DocumentStorage &store) override;
    void buildSpecFile(ghidra::DocumentStorage &store) override;
    void modifySpaces(ghidra::Translate *translate) override;
    void resolveArchitecture() override;
    void postSpecFile() override;

private:
    void install_program_overlays();
    void populate_program_symbols();

    program::Program *program_{};
    program::LanguageDescription language_;
    program::ProcessorSpec processor_spec_;
    program::CompilerSpec compiler_spec_;
    ProgramLoadImage *program_loader_{};
    ProgramTypeFactory *program_types_{};
    program::SleighContextMetadataCollector *metadata_context_{};
    bool program_symbols_populated_{};
};

// Ownership shell that guarantees ProgramDB outlives all decompiler providers
// owned by Architecture.  Opening performs both the metadata SLEIGH pass and
// the complete Architecture::init lifecycle in-process with no Java bridge.
class HeadlessRuntime final {
public:
    [[nodiscard]] static std::unique_ptr<HeadlessRuntime> open(
        std::shared_ptr<db::DatabaseHandle> database,
        program::ProgramOpenMode mode,
        const std::filesystem::path &processor_pack_root,
        std::ostream &errors);

    ~HeadlessRuntime();
    HeadlessRuntime(const HeadlessRuntime &) = delete;
    HeadlessRuntime &operator=(const HeadlessRuntime &) = delete;

    [[nodiscard]] program::Program &program() noexcept;
    [[nodiscard]] const program::Program &program() const noexcept;
    [[nodiscard]] ProgramSleighArchitecture &architecture() noexcept;
    [[nodiscard]] const ProgramSleighArchitecture &architecture() const noexcept;

private:
    HeadlessRuntime(
        std::unique_ptr<program::Program> program,
        std::unique_ptr<ProgramSleighArchitecture> architecture);

    // Declaration order is intentional: destruction is reversed, so all
    // Architecture-owned providers are released before ProgramDB.
    std::unique_ptr<program::Program> program_;
    std::unique_ptr<ProgramSleighArchitecture> architecture_;
};

} // namespace llmghidra::headless
