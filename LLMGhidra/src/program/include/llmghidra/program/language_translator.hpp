#pragma once

#include "llmghidra/program/language.hpp"
#include "llmghidra/program/register_context_manager.hpp"

#include <memory>
#include <optional>
#include <string>
#include <functional>
#include <vector>

namespace llmghidra::program {

class ProgramArchitecture;
class AddressFactory;

// Native counterpart of ghidra.program.util.LanguageTranslator.  The virtual
// contract is intentionally general enough for processor-specific translators;
// SimpleLanguageTranslator implements the shipped .trans format.
class LanguageTranslator {
public:
    virtual ~LanguageTranslator() = default;

    [[nodiscard]] virtual const std::string &old_language_id() const = 0;
    [[nodiscard]] virtual std::int32_t old_language_version() const = 0;
    [[nodiscard]] virtual const std::string &new_language_id() const = 0;
    [[nodiscard]] virtual std::int32_t new_language_version() const = 0;
    [[nodiscard]] virtual const ProgramArchitecture &old_architecture() const = 0;
    [[nodiscard]] virtual const ProgramArchitecture &new_architecture() const = 0;
    [[nodiscard]] virtual const AddressFactory &old_address_factory() const = 0;
    [[nodiscard]] virtual const AddressFactory &new_address_factory() const = 0;
    [[nodiscard]] virtual std::optional<std::string> new_address_space(
        const std::string &old_name) const = 0;
    [[nodiscard]] virtual std::optional<Address> new_address(
        const Address &old_address) const = 0;
    [[nodiscard]] virtual std::optional<Address> new_register_address(
        const Address &old_address,
        std::int32_t size) const = 0;
    [[nodiscard]] virtual std::optional<std::string> new_register(
        const std::string &old_name) const = 0;
    [[nodiscard]] virtual std::optional<RegisterValue> new_register_value(
        const RegisterValue &old_value) const = 0;
    [[nodiscard]] virtual bool value_translation_required(
        const std::string &old_register) const = 0;
    [[nodiscard]] virtual std::string new_compiler_spec_id(
        const std::string &old_id) const = 0;
    [[nodiscard]] virtual std::optional<RegisterValue>
    context_gap_value() const = 0;
    [[nodiscard]] virtual std::vector<std::string>
    post_upgrade_handlers() const = 0;
};

class SimpleLanguageTranslator final : public LanguageTranslator {
public:
    SimpleLanguageTranslator(
        LanguageTranslationDescription description,
        std::shared_ptr<const ProgramArchitecture> old_architecture,
        std::shared_ptr<const ProgramArchitecture> new_architecture,
        std::shared_ptr<const AddressFactory> old_address_factory,
        std::shared_ptr<const AddressFactory> new_address_factory);

    [[nodiscard]] const ProgramArchitecture &old_architecture() const override;
    [[nodiscard]] const ProgramArchitecture &new_architecture() const override;
    [[nodiscard]] const std::string &old_language_id() const override;
    [[nodiscard]] std::int32_t old_language_version() const override;
    [[nodiscard]] const std::string &new_language_id() const override;
    [[nodiscard]] std::int32_t new_language_version() const override;
    [[nodiscard]] const AddressFactory &old_address_factory() const override;
    [[nodiscard]] const AddressFactory &new_address_factory() const override;
    [[nodiscard]] std::optional<std::string> new_address_space(
        const std::string &old_name) const override;
    [[nodiscard]] std::optional<Address> new_address(
        const Address &old_address) const override;
    [[nodiscard]] std::optional<Address> new_register_address(
        const Address &old_address,
        std::int32_t size) const override;
    [[nodiscard]] std::optional<std::string> new_register(
        const std::string &old_name) const override;
    [[nodiscard]] std::optional<RegisterValue> new_register_value(
        const RegisterValue &old_value) const override;
    [[nodiscard]] bool value_translation_required(
        const std::string &old_register) const override;
    [[nodiscard]] std::string new_compiler_spec_id(
        const std::string &old_id) const override;
    [[nodiscard]] std::optional<RegisterValue>
    context_gap_value() const override;
    [[nodiscard]] std::vector<std::string>
    post_upgrade_handlers() const override;
    [[nodiscard]] const LanguageTranslationDescription &description() const noexcept;

private:
    [[nodiscard]] std::optional<RegisterValue> translate_normal_value(
        const RegisterValue &old_value,
        const std::string &target_name) const;
    [[nodiscard]] std::optional<RegisterValue> translate_context_value(
        const RegisterValue &old_value,
        bool carry_old_values) const;
    [[nodiscard]] std::optional<std::string> canonical_register(
        const ProgramArchitecture &architecture,
        const std::string &name) const;
    [[nodiscard]] std::optional<std::string> canonical_context_field(
        const ProgramArchitecture &architecture,
        const std::string &name) const;
    void validate_address_spaces() const;

    LanguageTranslationDescription description_;
    std::shared_ptr<const ProgramArchitecture> old_architecture_;
    std::shared_ptr<const ProgramArchitecture> new_architecture_;
    std::shared_ptr<const AddressFactory> old_address_factory_;
    std::shared_ptr<const AddressFactory> new_address_factory_;
};

struct LanguageTranslationEndpoint {
    std::string language_id;
    std::int32_t version{};
    std::int32_t minor_version{};
    std::shared_ptr<const ProgramArchitecture> architecture;
    std::shared_ptr<const AddressFactory> address_factory;
};

// Native counterpart of LanguageTranslatorFactory.  Historical *.lang
// endpoints are seeded from LanguageRegistry; current SLEIGH architectures are
// registered by the headless language loader after it has built its
// ProgramArchitecture and AddressFactory.
class LanguageTranslatorFactory final {
public:
    using NativeTranslatorBuilder = std::function<
        std::unique_ptr<LanguageTranslator>(
            const LanguageTranslationEndpoint &,
            const LanguageTranslationEndpoint &)>;

    explicit LanguageTranslatorFactory(const LanguageRegistry &registry);
    ~LanguageTranslatorFactory();
    LanguageTranslatorFactory(LanguageTranslatorFactory &&) noexcept;
    LanguageTranslatorFactory &operator=(LanguageTranslatorFactory &&) noexcept;
    LanguageTranslatorFactory(const LanguageTranslatorFactory &) = delete;
    LanguageTranslatorFactory &operator=(const LanguageTranslatorFactory &) = delete;

    void register_endpoint(LanguageTranslationEndpoint endpoint);
    void register_native_translator(
        std::string from_language_id,
        std::int32_t from_version,
        std::string to_language_id,
        std::int32_t to_version,
        NativeTranslatorBuilder builder);
    [[nodiscard]] std::unique_ptr<LanguageTranslator> create(
        const std::string &from_language_id,
        std::int32_t from_version,
        const std::string &to_language_id,
        std::int32_t to_version) const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace llmghidra::program
