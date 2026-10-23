#include "llmghidra/program/language_translator.hpp"

#include "llmghidra/program/address_factory.hpp"
#include "llmghidra/program/program_architecture.hpp"

#include <algorithm>
#include <compare>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace llmghidra::program {
namespace {

struct EndpointKey {
    std::string id;
    std::int32_t version{};

    friend auto operator<=>(const EndpointKey &, const EndpointKey &) = default;
};

struct EdgeKey {
    EndpointKey from;
    EndpointKey to;

    friend auto operator<=>(const EdgeKey &, const EdgeKey &) = default;
};

[[nodiscard]] std::string endpoint_text(const EndpointKey &key) {
    return key.id + " version " + std::to_string(key.version);
}

[[nodiscard]] std::string base_register_name(
    const ProgramArchitecture &architecture,
    std::string name) {
    std::set<std::string> visited;
    while (true) {
        if (!visited.insert(name).second) {
            throw std::runtime_error(
                "language translator register hierarchy contains a cycle");
        }
        const auto description = architecture.register_named(name);
        if (!description) {
            throw std::runtime_error(
                "language translator references an unknown register: " + name);
        }
        if (!description->base_register) return name;
        name = *description->base_register;
    }
}

[[nodiscard]] RegisterValue empty_value(
    const ProgramArchitecture &architecture,
    const std::string &register_name) {
    const auto base_name = base_register_name(architecture, register_name);
    const auto base = architecture.register_named(base_name);
    if (!base || base->size <= 0 || base->base_register) {
        throw std::runtime_error(
            "language translator produced an invalid target register");
    }
    const auto width = static_cast<std::size_t>(base->size);
    return {base_name, std::vector<std::uint8_t>(width, 0),
            std::vector<std::uint8_t>(width, 0)};
}

class CompositeLanguageTranslator final : public LanguageTranslator {
public:
    explicit CompositeLanguageTranslator(
        std::vector<std::unique_ptr<LanguageTranslator>> stages)
        : stages_(std::move(stages)) {
        if (stages_.size() < 2) {
            throw std::invalid_argument(
                "composite language translator requires at least two stages");
        }
        for (std::size_t index = 1; index < stages_.size(); ++index) {
            if (&stages_[index - 1]->new_architecture() !=
                    &stages_[index]->old_architecture() ||
                &stages_[index - 1]->new_address_factory() !=
                    &stages_[index]->old_address_factory()) {
                throw std::invalid_argument(
                    "language translator chain has incompatible adjacent endpoints");
            }
        }
    }

    [[nodiscard]] const ProgramArchitecture &old_architecture() const override {
        return stages_.front()->old_architecture();
    }
    [[nodiscard]] const std::string &old_language_id() const override {
        return stages_.front()->old_language_id();
    }
    [[nodiscard]] std::int32_t old_language_version() const override {
        return stages_.front()->old_language_version();
    }
    [[nodiscard]] const std::string &new_language_id() const override {
        return stages_.back()->new_language_id();
    }
    [[nodiscard]] std::int32_t new_language_version() const override {
        return stages_.back()->new_language_version();
    }
    [[nodiscard]] const ProgramArchitecture &new_architecture() const override {
        return stages_.back()->new_architecture();
    }
    [[nodiscard]] const AddressFactory &old_address_factory() const override {
        return stages_.front()->old_address_factory();
    }
    [[nodiscard]] const AddressFactory &new_address_factory() const override {
        return stages_.back()->new_address_factory();
    }

    [[nodiscard]] std::optional<std::string> new_address_space(
        const std::string &old_name) const override {
        std::optional<std::string> current = old_name;
        for (const auto &stage : stages_) {
            if (!current) return std::nullopt;
            current = stage->new_address_space(*current);
        }
        return current;
    }

    [[nodiscard]] std::optional<Address> new_address(
        const Address &old_address) const override {
        std::optional<Address> current = old_address;
        for (const auto &stage : stages_) {
            if (!current) return std::nullopt;
            current = stage->new_address(*current);
        }
        return current;
    }

    [[nodiscard]] std::optional<Address> new_register_address(
        const Address &old_address,
        std::int32_t size) const override {
        std::optional<Address> current = old_address;
        for (const auto &stage : stages_) {
            if (!current) return std::nullopt;
            current = stage->new_register_address(*current, size);
        }
        return current;
    }

    [[nodiscard]] std::optional<std::string> new_register(
        const std::string &old_name) const override {
        std::optional<std::string> current = old_name;
        for (const auto &stage : stages_) {
            if (!current) return std::nullopt;
            current = stage->new_register(*current);
        }
        return current;
    }

    [[nodiscard]] std::optional<RegisterValue> new_register_value(
        const RegisterValue &old_value) const override {
        std::optional<RegisterValue> current = old_value;
        for (const auto &stage : stages_) {
            if (!current) return std::nullopt;
            const std::string input_name = current->register_name;
            auto translated = stage->new_register_value(*current);
            if (!translated) {
                const auto mapped = stage->new_register(input_name);
                if (!mapped) return std::nullopt;
                translated = empty_value(stage->new_architecture(), *mapped);
            }
            current = std::move(translated);
        }
        return current;
    }

    [[nodiscard]] bool value_translation_required(
        const std::string &old_register) const override {
        std::optional<std::string> current = old_register;
        bool required = false;
        for (const auto &stage : stages_) {
            if (!current) return required;
            required = required || stage->value_translation_required(*current);
            current = stage->new_register(*current);
        }
        return required;
    }

    [[nodiscard]] std::string new_compiler_spec_id(
        const std::string &old_id) const override {
        std::string current = old_id;
        for (const auto &stage : stages_) {
            current = stage->new_compiler_spec_id(current);
        }
        return current;
    }

    [[nodiscard]] std::optional<RegisterValue>
    context_gap_value() const override {
        std::optional<RegisterValue> current;
        for (const auto &stage : stages_) {
            if (!current) {
                current = stage->context_gap_value();
                if (!current) {
                    const auto &architecture = stage->new_architecture();
                    if (!architecture.processor_context_register) continue;
                    current = empty_value(
                        architecture,
                        *architecture.processor_context_register);
                }
                continue;
            }
            const std::string input_name = current->register_name;
            auto translated = stage->new_register_value(*current);
            if (!translated) {
                const auto mapped = stage->new_register(input_name);
                if (mapped) {
                    translated = empty_value(stage->new_architecture(), *mapped);
                }
                else {
                    translated = stage->context_gap_value();
                }
                if (!translated) {
                    const auto &architecture = stage->new_architecture();
                    if (!architecture.processor_context_register) {
                        current.reset();
                        continue;
                    }
                    translated = empty_value(
                        architecture,
                        *architecture.processor_context_register);
                }
            }
            current = std::move(translated);
        }
        return current && current->has_any_value()
            ? current : std::nullopt;
    }

    [[nodiscard]] std::vector<std::string>
    post_upgrade_handlers() const override {
        std::vector<std::string> result;
        for (const auto &stage : stages_) {
            auto handlers = stage->post_upgrade_handlers();
            result.insert(result.end(),
                          std::make_move_iterator(handlers.begin()),
                          std::make_move_iterator(handlers.end()));
        }
        return result;
    }

private:
    std::vector<std::unique_ptr<LanguageTranslator>> stages_;
};

struct PathCost {
    std::size_t default_edges{};
    std::size_t total_edges{};

    friend auto operator<=>(const PathCost &, const PathCost &) = default;
};

struct SelectedEdge {
    EdgeKey key;
    const LanguageTranslationDescription *description{};
    bool default_mapping{};

    friend bool operator==(const SelectedEdge &, const SelectedEdge &) = default;
};

} // namespace

class LanguageTranslatorFactory::Impl {
public:
    explicit Impl(const LanguageRegistry &registry)
        : descriptions_(registry.translations()) {
        for (const auto &legacy : registry.legacy_languages()) {
            for (const auto &alias : legacy.aliases) {
                add_endpoint({alias, legacy.version, 0, legacy.architecture,
                              legacy.address_factory});
            }
        }
    }

    void add_endpoint(LanguageTranslationEndpoint endpoint) {
        if (endpoint.language_id.empty() || endpoint.version < 0 ||
            !endpoint.architecture || !endpoint.address_factory) {
            throw std::invalid_argument(
                "language translation endpoint is incomplete");
        }
        EndpointKey key{endpoint.language_id, endpoint.version};
        if (!endpoints_.emplace(key, std::move(endpoint)).second) {
            throw std::runtime_error(
                "duplicate language translation endpoint: " +
                endpoint_text(key));
        }
    }

    void add_native(EdgeKey key, NativeTranslatorBuilder builder) {
        if (!builder) {
            throw std::invalid_argument(
                "native language translator builder is empty");
        }
        if (!native_builders_.emplace(std::move(key), std::move(builder)).second) {
            throw std::runtime_error(
                "duplicate native language translator registration");
        }
    }

    [[nodiscard]] std::unique_ptr<LanguageTranslator> create(
        const EndpointKey &from,
        const EndpointKey &to) const {
        if (from == to) {
            throw std::invalid_argument(
                "language translation endpoints are identical");
        }
        if (from.id == to.id && from.version >= to.version) {
            throw std::invalid_argument(
                "same-language translation must increase the major version");
        }
        require_endpoint(from);
        require_endpoint(to);

        const auto edges = build_edges(from, to);
        std::vector<SelectedEdge> active_path;
        std::set<EndpointKey> active_nodes{from};
        std::vector<SelectedEdge> best_path;
        std::optional<PathCost> best_cost;
        bool ambiguous = false;
        search(from, to, edges, active_nodes, active_path, {}, best_cost,
               best_path, ambiguous);

        if (!best_cost) {
            // Ghidra permits a direct default translator only when structural
            // address-space validation succeeds.  Construction performs that
            // validation and throws for an incompatible language pair.
            return make_default(from, to);
        }
        if (ambiguous) {
            throw std::runtime_error(
                "ambiguous language translator chain from " +
                endpoint_text(from) + " to " + endpoint_text(to));
        }

        std::vector<std::unique_ptr<LanguageTranslator>> stages;
        stages.reserve(best_path.size());
        for (const auto &edge : best_path) {
            stages.push_back(make_stage(edge));
        }
        if (stages.empty()) {
            throw std::runtime_error("language translator chain is empty");
        }
        if (stages.size() == 1) return std::move(stages.front());
        return std::make_unique<CompositeLanguageTranslator>(std::move(stages));
    }

private:
    [[nodiscard]] const LanguageTranslationEndpoint &require_endpoint(
        const EndpointKey &key) const {
        const auto found = endpoints_.find(key);
        if (found == endpoints_.end()) {
            throw std::out_of_range(
                "missing language translation endpoint: " + endpoint_text(key));
        }
        return found->second;
    }

    [[nodiscard]] std::vector<SelectedEdge> build_edges(
        const EndpointKey &from,
        const EndpointKey &to) const {
        std::map<EdgeKey, const LanguageTranslationDescription *> explicit_edges;
        for (const auto &description : descriptions_) {
            EdgeKey key{{description.from_language_id, description.from_version},
                        {description.to_language_id, description.to_version}};
            if (!endpoints_.contains(key.from) || !endpoints_.contains(key.to)) {
                continue;
            }
            const auto [position, inserted] =
                explicit_edges.emplace(key, &description);
            if (!inserted && position->second->source != description.source) {
                throw std::runtime_error(
                    "conflicting language translation specifications for " +
                    endpoint_text(key.from) + " -> " + endpoint_text(key.to));
            }
        }

        std::vector<SelectedEdge> result;
        for (const auto &[key, description] : explicit_edges) {
            if (!native_builders_.contains(key)) {
                result.push_back({key, description, false});
            }
        }
        for (const auto &[key, builder] : native_builders_) {
            (void)builder;
            if (endpoints_.contains(key.from) && endpoints_.contains(key.to)) {
                result.push_back({key, nullptr, false});
            }
        }

        std::map<std::string, std::vector<std::int32_t>> versions;
        for (const auto &[key, endpoint] : endpoints_) {
            (void)endpoint;
            versions[key.id].push_back(key.version);
        }
        for (auto &[id, values] : versions) {
            std::ranges::sort(values);
            values.erase(std::unique(values.begin(), values.end()), values.end());
            for (std::size_t index = 1; index < values.size(); ++index) {
                EdgeKey key{{id, values[index - 1]}, {id, values[index]}};
                if (!explicit_edges.contains(key) &&
                    !native_builders_.contains(key)) {
                    result.push_back({std::move(key), nullptr, true});
                }
            }
        }
        std::ranges::sort(result, [](const auto &left, const auto &right) {
            return left.key < right.key;
        });
        (void)from;
        (void)to;
        return result;
    }

    static void search(
        const EndpointKey &current,
        const EndpointKey &target,
        const std::vector<SelectedEdge> &edges,
        std::set<EndpointKey> &active_nodes,
        std::vector<SelectedEdge> &active_path,
        PathCost cost,
        std::optional<PathCost> &best_cost,
        std::vector<SelectedEdge> &best_path,
        bool &ambiguous) {
        if (best_cost && cost > *best_cost) return;
        if (current == target) {
            if (!best_cost || cost < *best_cost) {
                best_cost = cost;
                best_path = active_path;
                ambiguous = false;
            }
            else if (cost == *best_cost && active_path != best_path) {
                ambiguous = true;
            }
            return;
        }
        for (const auto &edge : edges) {
            if (edge.key.from != current || active_nodes.contains(edge.key.to)) {
                continue;
            }
            PathCost next = cost;
            next.default_edges += edge.default_mapping ? 1U : 0U;
            ++next.total_edges;
            active_nodes.insert(edge.key.to);
            active_path.push_back(edge);
            search(edge.key.to, target, edges, active_nodes, active_path,
                   next, best_cost, best_path, ambiguous);
            active_path.pop_back();
            active_nodes.erase(edge.key.to);
        }
    }

    [[nodiscard]] std::unique_ptr<LanguageTranslator> make_default(
        const EndpointKey &from,
        const EndpointKey &to) const {
        LanguageTranslationDescription description;
        description.from_language_id = from.id;
        description.from_version = from.version;
        description.to_language_id = to.id;
        description.to_version = to.version;
        const auto &old_endpoint = require_endpoint(from);
        const auto &new_endpoint = require_endpoint(to);
        return std::make_unique<SimpleLanguageTranslator>(
            std::move(description), old_endpoint.architecture,
            new_endpoint.architecture, old_endpoint.address_factory,
            new_endpoint.address_factory);
    }

    [[nodiscard]] std::unique_ptr<LanguageTranslator> make_stage(
        const SelectedEdge &edge) const {
        if (edge.default_mapping) {
            return make_default(edge.key.from, edge.key.to);
        }
        const auto &old_endpoint = require_endpoint(edge.key.from);
        const auto &new_endpoint = require_endpoint(edge.key.to);
        if (const auto native = native_builders_.find(edge.key);
            native != native_builders_.end()) {
            auto result = native->second(old_endpoint, new_endpoint);
            if (!result ||
                &result->old_architecture() != old_endpoint.architecture.get() ||
                &result->new_architecture() != new_endpoint.architecture.get() ||
                &result->old_address_factory() !=
                    old_endpoint.address_factory.get() ||
                &result->new_address_factory() !=
                    new_endpoint.address_factory.get()) {
                throw std::runtime_error(
                    "native language translator returned incompatible endpoints");
            }
            return result;
        }
        if (!edge.description) {
            throw std::logic_error(
                "explicit language translator edge has no implementation");
        }
        return std::make_unique<SimpleLanguageTranslator>(
            *edge.description, old_endpoint.architecture,
            new_endpoint.architecture, old_endpoint.address_factory,
            new_endpoint.address_factory);
    }

    std::vector<LanguageTranslationDescription> descriptions_;
    std::map<EndpointKey, LanguageTranslationEndpoint> endpoints_;
    std::map<EdgeKey, NativeTranslatorBuilder> native_builders_;
};

LanguageTranslatorFactory::LanguageTranslatorFactory(
    const LanguageRegistry &registry)
    : impl_(std::make_unique<Impl>(registry)) {}

LanguageTranslatorFactory::~LanguageTranslatorFactory() = default;
LanguageTranslatorFactory::LanguageTranslatorFactory(
    LanguageTranslatorFactory &&) noexcept = default;
LanguageTranslatorFactory &LanguageTranslatorFactory::operator=(
    LanguageTranslatorFactory &&) noexcept = default;

void LanguageTranslatorFactory::register_endpoint(
    LanguageTranslationEndpoint endpoint) {
    impl_->add_endpoint(std::move(endpoint));
}

void LanguageTranslatorFactory::register_native_translator(
    std::string from_language_id,
    std::int32_t from_version,
    std::string to_language_id,
    std::int32_t to_version,
    NativeTranslatorBuilder builder) {
    impl_->add_native(
        {{std::move(from_language_id), from_version},
         {std::move(to_language_id), to_version}},
        std::move(builder));
}

std::unique_ptr<LanguageTranslator> LanguageTranslatorFactory::create(
    const std::string &from_language_id,
    std::int32_t from_version,
    const std::string &to_language_id,
    std::int32_t to_version) const {
    return impl_->create({from_language_id, from_version},
                         {to_language_id, to_version});
}

} // namespace llmghidra::program
