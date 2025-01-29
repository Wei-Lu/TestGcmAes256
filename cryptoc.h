#pragma once

#include <iostream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
const int KEY_BYTE_SIZE = 32;
const int IV_BYTE_SIZE = 16;
void aES256EncryptString(const std::string& plainText, std::string& cipherText, const CryptoPP::byte key[KEY_BYTE_SIZE], const CryptoPP::byte iv[IV_BYTE_SIZE]);
void aES256DecryptString(const std::string& cipherText, std::string& recoveredText, const CryptoPP::byte key[KEY_BYTE_SIZE], const CryptoPP::byte iv[IV_BYTE_SIZE]);
void aES256Encrypt(const CryptoPP::byte* buffer, int lenIn, CryptoPP::byte* cipherText, int& lenInOut, const CryptoPP::byte key[KEY_BYTE_SIZE], const CryptoPP::byte iv[IV_BYTE_SIZE]);
void aES256Decrypt(const CryptoPP::byte* cipherText, int lenIn, CryptoPP::byte* resultText, int& lenInOut, const CryptoPP::byte key[KEY_BYTE_SIZE], const CryptoPP::byte iv[IV_BYTE_SIZE]);