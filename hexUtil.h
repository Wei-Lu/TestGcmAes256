#pragma once

#include <string>
#include <cryptlib.h>

std::string BinaryArrayToHex(const CryptoPP::byte* binary, size_t length);

int HexToBinaryArray(const std::string& hex, CryptoPP::byte* binary, size_t maxLength);
