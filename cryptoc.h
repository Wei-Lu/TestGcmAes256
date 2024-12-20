#pragma once

#include <iostream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>

void AES256_Encrypt(const std::string& plainText, std::string& cipherText, const CryptoPP::byte key[32], const CryptoPP::byte iv[16]);
void AES256_Decrypt(const std::string& cipherText, std::string& recoveredText, const CryptoPP::byte key[32], const CryptoPP::byte iv[16]);
