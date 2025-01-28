#include <sstream>
#include <iomanip>
#include <vector>
#include "hexUtil.h"

std::string BinaryArrayToHex(const CryptoPP::byte* binary, size_t length) {
  std::ostringstream oss;
  for (size_t i = 0; i < length; ++i) {
    oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(binary[i]);
  }
  return oss.str();
}

int HexToBinaryArray(const std::string& hex, CryptoPP::byte* binary, size_t maxLength) {
  if (hex.size() % 2 != 0) {
    throw std::invalid_argument("Hex string must have an even number of characters");
  }
  if (hex.size() / 2 > maxLength) {
    throw std::overflow_error("Output array too small");
  }

  for (size_t i = 0; i < hex.size(); i += 2) {
    std::string byteString = hex.substr(i, 2);
    binary[i / 2] = static_cast<CryptoPP::byte>(std::stoi(byteString, nullptr, 16));
  }
  return hex.size() / 2;
}


