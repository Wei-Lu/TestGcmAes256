// testAes256.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <string>
#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include "cryptoc.h"

using namespace CryptoPP;
int main() {
  // Sample key and IV (replace with secure values)
  //byte key[32] = { 0x32, 0x35, 0x20, 0x8d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }; // Replace with a 256-bit key
  byte iv[16] = { 0x39, 0xb1, 0x41, 0x99, 0x57, 0xdf, 0x49, 0xbc, 0x11, 0x3f, 0x83, 0x44, 0xa8, 0xd2, 0xfd, 0xfa };  // Replace with a 128-bit IV
  byte key[32] = { 0x32, 0x35, 0x20, 0x8d, 0x6e, 0x9e, 0x48, 0x4e, 0x02, 0x07, 0x09, 0x2d, 0x48, 0xea, 0x34, 0x7d, 0x64, 0xe0, 0x3a, 0xf0, 0xc7, 0x20, 0xf3, 0x38, 0x38, 0x0e, 0x94, 0x05, 0x8a, 0x2d, 0xe8, 0xe9 }; // Replace with a 256-bit key
  std::string plainText = "dbprofile1password";
  std::string cipherText, recoveredText;
  AES256_Encrypt(plainText, cipherText, key, iv);
  // Encrypt
  std::cout << "Encrypted: " << cipherText << std::endl;
  AES256_Decrypt(cipherText, recoveredText, key, iv);

  std::cout << "Decrypted: " << recoveredText << std::endl;

  return 0;
}