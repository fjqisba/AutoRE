// SPDX-License-Identifier: Apache-2.0
// 直接调用本地 Ghidra C++ 编解码器生成证据；不是 Rust 编码器自生成期望值。
#include "translate.hh"
#include "op.hh"
#include "database.hh"
#include <filesystem>
#include <fstream>
#include <limits>
using namespace ghidra;

struct Spaces : AddrSpaceManager {
  Spaces() {
    insertSpace(new ConstantSpace(this, nullptr));
    insertSpace(new AddrSpace(this, nullptr, IPTR_PROCESSOR, "ram", false, 8, 1, 1, 0, 0, 0));
    insertSpace(new AddrSpace(this, nullptr, IPTR_PROCESSOR, "register", false, 8, 1, 2, 0, 0, 0));
    setDefaultCodeSpace(1);
  }
};
void emitLoad(Encoder &e, Spaces &s) {
  e.openElement(ELEM_OP);
  e.writeSignedInteger(ATTRIB_CODE, CPUI_LOAD);
  e.writeSignedInteger(ATTRIB_SIZE, 2);
  e.openElement(ELEM_ADDR);
  s.getSpace(2)->encodeAttributes(e, 0x4000, 8);
  e.closeElement(ELEM_ADDR);
  e.openElement(ELEM_SPACEID);
  e.writeSpace(ATTRIB_NAME, s.getSpace(1));
  e.closeElement(ELEM_SPACEID);
  e.openElement(ELEM_ADDR);
  s.getSpace(2)->encodeAttributes(e, 0x4008, 8);
  e.closeElement(ELEM_ADDR);
  e.closeElement(ELEM_OP);
}
int main(int argc, char **argv) {
  if (argc != 2) return 2;
  AttributeId::initialize(); ElementId::initialize();
  Spaces spaces;
  std::filesystem::path dir(argv[1]);
  std::filesystem::create_directories(dir);
  {
    std::ofstream stream(dir / "native_load.packed", std::ios::binary);
    PackedEncode encoder(stream); emitLoad(encoder, spaces);
  }
  {
    std::ofstream stream(dir / "native_load.xml", std::ios::binary);
    XmlEncode encoder(stream, false); emitLoad(encoder, spaces);
  }
  {
    std::ofstream stream(dir / "native_scalars.packed", std::ios::binary);
    PackedEncode encoder(stream);
    encoder.openElement(ELEM_OP);
    encoder.writeSignedInteger(ATTRIB_SIZE, std::numeric_limits<intb>::min());
    encoder.writeUnsignedInteger(ATTRIB_OFFSET, std::numeric_limits<uintb>::max());
    encoder.writeBool(ATTRIB_VOLATILE, true);
    encoder.writeString(ATTRIB_NAME, "a<&\"b");
    encoder.closeElement(ELEM_OP);
  }
  {
    std::ofstream stream(dir / "native_seqnum.packed", std::ios::binary);
    PackedEncode encoder(stream);
    SeqNum(Address(spaces.getSpace(1), 0xfffffffffffffff0ULL), 0x89abcdef).encode(encoder);
  }
  // 同一原生解码器再读取 fixture，确认它符合 raw P-code 接口。
  std::ifstream stream(dir / "native_load.packed", std::ios::binary);
  PackedDecode decoder(&spaces); decoder.ingestStream(stream);
  uint4 elem = decoder.openElement(ELEM_OP);
  int4 count = decoder.readSignedInteger(ATTRIB_SIZE);
  VarnodeData inputs[2], output, *out = &output;
  auto code = PcodeOpRaw::decode(decoder, count, inputs, &out);
  decoder.closeElement(elem);
  return code == CPUI_LOAD && count == 2 && out->offset == 0x4000 && inputs[1].offset == 0x4008 ? 0 : 1;
}
