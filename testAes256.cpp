// testAes256.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cryptlib.h>
#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <hex.h>
#include <files.h>
#include "cryptoc.h"

using namespace CryptoPP;
using namespace std;

int main() {
    byte iv[16] = { 0x39, 0xb1, 0x41, 0x99, 0x57, 0xdf, 0x49, 0xbc, 0x11, 0x3f, 0x83, 0x44 };  // Replace with a 128-bit IV
    byte key[32] = { 0x32, 0x35, 0x20, 0x8d, 0x6e, 0x9e, 0x48, 0x4e, 0x02, 0x07, 0x09, 0x2d, 0x48, 0xea, 0x34, 0x7d, 0x64, 0xe0, 0x3a, 0xf0, 0xc7, 0x20, 0xf3, 0x38, 0x38, 0x0e, 0x94, 0x05, 0x8a, 0x2d, 0xe8, 0xe9 }; // Replace with a 256-bit key

  std::string plaintext = "Hello, AES-GCM!";
  byte cipherText[100], decryptedText[100];
  int lenInOut = 100;
  aes256Encrypt((byte *)plaintext.data(), plaintext.size(), cipherText, lenInOut, key, iv);
  int lenOut = 100;
  aes256Decrypt(cipherText, lenInOut, decryptedText, lenOut, key, iv);

  byte abc[] = { 1, 5, 0, 8 };
  lenInOut = 100;
  aes256Encrypt(abc, sizeof(abc), cipherText, lenInOut, key, iv);
  lenOut = 100;
  aes256Decrypt(cipherText, lenInOut, decryptedText, lenOut, key, iv);
}
