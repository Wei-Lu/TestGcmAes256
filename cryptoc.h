#pragma once

#include <iostream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>

using namespace CryptoPP;
int aes256Encrypt(const byte* plainText, int lenIn, byte* encriptBuffer, int& lenInOut, const byte key[32], const byte iv[16]);
int aes256Decrypt(const byte* encryptBuffer, int lenIn, byte* decryptedBuff, int& lenInOut, const byte key[32], const byte iv[16]);
