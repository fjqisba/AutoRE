set(GHIDRA_DECOMPILER_CPP_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../decompiler/cpp")

set(GHIDRA_DECOMPILER_COMMON_SOURCES
    marshal.cc
    space.cc
    float.cc
    address.cc
    pcoderaw.cc
    translate.cc
    opcodes.cc
    globalcontext.cc
    capability.cc
    architecture.cc
    options.cc
    graph.cc
    cover.cc
    block.cc
    cast.cc
    typeop.cc
    database.cc
    cpool.cc
    comment.cc
    stringmanage.cc
    modelrules.cc
    fspec.cc
    action.cc
    loadimage.cc
    varnode.cc
    op.cc
    type.cc
    variable.cc
    varmap.cc
    jumptable.cc
    emulate.cc
    emulateutil.cc
    flow.cc
    userop.cc
    expression.cc
    multiprecision.cc
    funcdata.cc
    funcdata_block.cc
    funcdata_varnode.cc
    unionresolve.cc
    funcdata_op.cc
    pcodeinject.cc
    heritage.cc
    prefersplit.cc
    rangeutil.cc
    ruleaction.cc
    subflow.cc
    transform.cc
    blockaction.cc
    merge.cc
    double.cc
    constseq.cc
    bitfield.cc
    coreaction.cc
    condexe.cc
    override.cc
    dynamic.cc
    crc32.cc
    prettyprint.cc
    printlanguage.cc
    printc.cc
    memstate.cc
    opbehavior.cc
    paramid.cc
    signature.cc
    xml.cc)

# Sources used by both the decompiler framework and the native SLEIGH engine.
# Product targets must compile these exactly once; keeping two copies in
# static archives creates ODR/link-order failures when the headless runtime
# links both subsystems into one process.
set(GHIDRA_NATIVE_SHARED_SOURCES
    marshal.cc
    space.cc
    float.cc
    address.cc
    pcoderaw.cc
    translate.cc
    opcodes.cc
    globalcontext.cc
    xml.cc)

set(GHIDRA_SLEIGH_COMMON_SOURCES
    marshal.cc
    space.cc
    float.cc
    address.cc
    pcoderaw.cc
    translate.cc
    opcodes.cc
    globalcontext.cc
    sleigh.cc
    pcodecompile.cc
    sleighbase.cc
    slghsymbol.cc
    slghpatexpress.cc
    slghpattern.cc
    semantics.cc
    context.cc
    slaformat.cc
    compression.cc
    filemanage.cc
    xml.cc
    pcodeparse.cc)

set(GHIDRA_SLEIGH_COMPILER_SOURCES
    ${GHIDRA_SLEIGH_COMMON_SOURCES}
    slgh_compile.cc
    slghparse.cc
    slghscan.cc)

list(TRANSFORM GHIDRA_DECOMPILER_COMMON_SOURCES
     PREPEND "${GHIDRA_DECOMPILER_CPP_DIR}/")
list(TRANSFORM GHIDRA_NATIVE_SHARED_SOURCES
     PREPEND "${GHIDRA_DECOMPILER_CPP_DIR}/")
list(TRANSFORM GHIDRA_SLEIGH_COMMON_SOURCES
     PREPEND "${GHIDRA_DECOMPILER_CPP_DIR}/")
list(TRANSFORM GHIDRA_SLEIGH_COMPILER_SOURCES
     PREPEND "${GHIDRA_DECOMPILER_CPP_DIR}/")

set(GHIDRA_DECOMPILER_CORE_SOURCES ${GHIDRA_DECOMPILER_COMMON_SOURCES})
list(REMOVE_ITEM GHIDRA_DECOMPILER_CORE_SOURCES
     ${GHIDRA_NATIVE_SHARED_SOURCES})

set(GHIDRA_SLEIGH_RUNTIME_SOURCES ${GHIDRA_SLEIGH_COMMON_SOURCES})
list(REMOVE_ITEM GHIDRA_SLEIGH_RUNTIME_SOURCES
     ${GHIDRA_NATIVE_SHARED_SOURCES})
