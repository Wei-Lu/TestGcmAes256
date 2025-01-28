#pragma once

#include <iostream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>

using namespace CryptoPP;

void AES256_Encrypt(const byte *plainText, int lengthIn, byte *cipherText,  int lengthOut, const byte key[32], const byte iv[16], SecByteBlock& tag);
void AES256_Decrypt(const byte *cipherText, int lengthIn, byte *recoveredText, int lengthOut, const byte key[32], const byte iv[16], const SecByteBlock& tag);
