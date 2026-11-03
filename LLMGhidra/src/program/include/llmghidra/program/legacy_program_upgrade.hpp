#pragma once

#include <memory>

namespace llmghidra::db {
class DatabaseHandle;
}

namespace llmghidra::program {

class CommentManager;
class DataTypeManager;
class FunctionManager;
class LegacyFunctionUpgrade;
class NamespaceManager;
class PersistentAddressMap;
class ProgramArchitecture;
class ReferenceManager;
class SymbolManager;
class VariableStorageManager;

// Orders cross-manager migrations that cannot be implemented safely inside a
// single table adapter.  Every operation runs inside Program::open(UPGRADE)'s
// transaction; legacy source tables are removed only after all dependent
// current-schema records have been written.
class LegacyProgramUpgradeCoordinator final {
public:
    LegacyProgramUpgradeCoordinator(
        std::shared_ptr<db::DatabaseHandle> database,
        PersistentAddressMap &address_map,
        SymbolManager &symbols,
        NamespaceManager &namespaces,
        FunctionManager &functions,
        DataTypeManager &data_types,
        CommentManager &comments,
        VariableStorageManager &variable_storage,
        ReferenceManager &references,
        const ProgramArchitecture *architecture);

    void upgrade();

private:
    void upgrade_functions(LegacyFunctionUpgrade &legacy);
    void upgrade_variable_symbols();

    std::shared_ptr<db::DatabaseHandle> database_;
    PersistentAddressMap *address_map_{};
    SymbolManager *symbols_{};
    NamespaceManager *namespaces_{};
    FunctionManager *functions_{};
    DataTypeManager *data_types_{};
    CommentManager *comments_{};
    VariableStorageManager *variable_storage_{};
    ReferenceManager *references_{};
    const ProgramArchitecture *architecture_{};
};

} // namespace llmghidra::program
