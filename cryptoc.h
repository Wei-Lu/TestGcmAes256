#pragma once

#include <iostream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>

void AES256_Encrypt(const CryptoPP::byte *plainText, int lengthIn, CryptoPP::byte *cipherText,  int lengthOut, const CryptoPP::byte key[32], const CryptoPP::byte iv[16]);
void AES256_Decrypt(const CryptoPP::byte *cipherText, int lengthIn, CryptoPP::byte *recoveredText, int lengthOut, const CryptoPP::byte key[32], const CryptoPP::byte iv[16]);
