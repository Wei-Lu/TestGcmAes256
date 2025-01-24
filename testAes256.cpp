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
#include <cryptlib.h>
#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <string>
#include <vector>
#include <iostream>

using namespace CryptoPP;

int main() {
  try {
    // Input: plaintext data (can be binary or text)
    std::string plaintext = "This is the data to encrypt!";
    std::vector<byte> plaintextBytes(plaintext.begin(), plaintext.end());

    // Key and IV
    byte iv[16] = { 0x39, 0xb1, 0x41, 0x99, 0x57, 0xdf, 0x49, 0xbc, 0x11, 0x3f, 0x83, 0x44, 0xa8, 0xd2, 0xfd, 0xfa };  // Replace with a 128-bit IV
    byte key[32] = { 0x32, 0x35, 0x20, 0x8d, 0x6e, 0x9e, 0x48, 0x4e, 0x02, 0x07, 0x09, 0x2d, 0x48, 0xea, 0x34, 0x7d, 0x64, 0xe0, 0x3a, 0xf0, 0xc7, 0x20, 0xf3, 0x38, 0x38, 0x0e, 0x94, 0x05, 0x8a, 0x2d, 0xe8, 0xe9 }; // Replace with a 256-bit key


    // AAD (Additional Authenticated Data)
    std::string aad = "Additional Authenticated Data";

    // Buffers for ciphertext and tag
    std::vector<byte> ciphertext(plaintextBytes.size());
    std::vector<byte> tag(16); // Typical GCM tag size is 16 bytes

    // Encryption setup
    GCM<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Encrypt
    ArraySink ciphertextSink(ciphertext.data(), ciphertext.size());
    AuthenticatedEncryptionFilter ef(
      encryptor, new Redirector(ciphertextSink), false, tag.size());

    // Add AAD (cast std::string to byte*)
    ef.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(aad.data()), aad.size());

    // Encrypt plaintext
    ef.ChannelPut(DEFAULT_CHANNEL, plaintextBytes.data(), plaintextBytes.size());

    // Finalize encryption
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    // Extract the tag
    ef.Get(tag.data(), tag.size());

    // Resize ciphertext to remove unused space
    ciphertext.resize(ciphertextSink.TotalPutLength());

    // Display results
    std::cout << "Ciphertext: ";
    for (byte c : ciphertext) {
      std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::endl;

    std::cout << "Tag: ";
    for (byte t : tag) {
      std::cout << std::hex << (int)t << " ";
    }
    std::cout << std::endl;

  }
  catch (const CryptoPP::Exception& ex) {
    std::cerr << "Encryption error: " << ex.what() << std::endl;
  }
  catch (const std::exception& ex) {
    std::cerr << "Standard exception: " << ex.what() << std::endl;
  }







  return 0;
}

#if 0

//buidable decryption
int main() {
  try {
    // Example input: binary or text data
    std::vector<byte> buffer = { 0x41, 0x42, 0x43, 0x44, 0xE2, 0x98, 0x83 }; // "ABCD"

    // Key and IV
    byte key[32] = { /* 256-bit key */ }; // Example: {0x00, 0x01, ...}
    byte iv[12] = { /* 96-bit IV */ };   // Example: {0xAA, 0xBB, ...}

    // AAD
    std::string aad = "Additional Authenticated Data";

    // Output buffers
    std::vector<byte> ciphertext(buffer.size() + 16); // Ciphertext + GCM tag
    std::vector<byte> tag(16); // GCM tag is typically 16 bytes

    // Encryption setup
    GCM<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Encrypt
    ArraySink ciphertextSink(ciphertext.data(), ciphertext.size());
    AuthenticatedEncryptionFilter ef(
      encryptor, new Redirector(ciphertextSink), false, tag.size());

    // Add AAD
    ef.ChannelPut(DEFAULT_CHANNEL, (const byte* )aad.data(), aad.size());

    // Encrypt buffer
    ef.ChannelPut(DEFAULT_CHANNEL, buffer.data(), buffer.size());

    // Finalize
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);
    ef.Get(tag.data(), tag.size()); // Extract the tag

    // Resize the ciphertext to exclude unused space
    ciphertext.resize(ciphertextSink.TotalPutLength());

    // Display ciphertext
    std::cout << "Ciphertext: ";
    for (auto c : ciphertext) {
      std::cout << std::hex << (int)c << " ";
    }
    std::cout << std::endl;

    // Display tag
    std::cout << "Tag: ";
    for (auto t : tag) {
      std::cout << std::hex << (int)t << " ";
    }
    std::cout << std::endl;

  }
  catch (const CryptoPP::Exception& ex) {
    std::cerr << "Encryption error: " << ex.what() << std::endl;
  }

  return 0;
}

#endif
#if 0
int main() {
  try {
    // Key and IV
    byte iv[16] = { 0x39, 0xb1, 0x41, 0x99, 0x57, 0xdf, 0x49, 0xbc, 0x11, 0x3f, 0x83, 0x44, 0xa8, 0xd2, 0xfd, 0xfa };  // Replace with a 128-bit IV
    byte key[32] = { 0x32, 0x35, 0x20, 0x8d, 0x6e, 0x9e, 0x48, 0x4e, 0x02, 0x07, 0x09, 0x2d, 0x48, 0xea, 0x34, 0x7d, 0x64, 0xe0, 0x3a, 0xf0, 0xc7, 0x20, 0xf3, 0x38, 0x38, 0x0e, 0x94, 0x05, 0x8a, 0x2d, 0xe8, 0xe9 }; // Replace with a 256-bit key
    // Input data
    std::string plaintext = "This is a test message.";
    std::string aad = "Additional Authenticated Data";

    // Output buffers
    std::string ciphertext;
    byte tag[16]; // 16-byte tag for GCM

    // Encryption setup
    GCM<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv, sizeof(iv));

    // Encrypt with AuthenticatedEncryptionFilter
    AuthenticatedEncryptionFilter ef(
      encryptor, new StringSink(ciphertext), false, sizeof(tag));

    // Process AAD
    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)aad.data(), aad.size());

    // Encrypt plaintext
    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)plaintext.data(), plaintext.size());

    // Finalize encryption
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    // Extract the tag
    ef.Get(tag, sizeof(tag));

    // Display results
    std::cout << "Ciphertext: ";
    for (auto c : ciphertext) {
      std::cout << std::hex << (unsigned int)(unsigned char)c << " ";
    }
    std::cout << std::endl;

    std::cout << "Tag: ";
    for (size_t i = 0; i < sizeof(tag); ++i) {
      std::cout << std::hex << (unsigned int)tag[i] << " ";
    }
    std::cout << std::endl;

  }
  catch (const CryptoPP::Exception& ex) {
    std::cerr << "Encryption error: " << ex.what() << std::endl;
  }

  return 0;
}



int main() {
  // Sample key and IV (replace with secure values)
  byte iv[16] = { 0x39, 0xb1, 0x41, 0x99, 0x57, 0xdf, 0x49, 0xbc, 0x11, 0x3f, 0x83, 0x44, 0xa8, 0xd2, 0xfd, 0xfa };  // Replace with a 128-bit IV
  byte key[32] = { 0x32, 0x35, 0x20, 0x8d, 0x6e, 0x9e, 0x48, 0x4e, 0x02, 0x07, 0x09, 0x2d, 0x48, 0xea, 0x34, 0x7d, 0x64, 0xe0, 0x3a, 0xf0, 0xc7, 0x20, 0xf3, 0x38, 0x38, 0x0e, 0x94, 0x05, 0x8a, 0x2d, 0xe8, 0xe9 }; // Replace with a 256-bit key
  std::string plainText = "dbprofile1password";
  byte cipherText[100], recoveredText[100];
  int outLen = 100;
  AES256_Encrypt((const byte *)plainText.c_str(), plainText.size(), cipherText, outLen, key, iv);
  // Encrypt
  std::cout << "Encrypted: " << cipherText << std::endl;
  int decryLen = 100;
  AES256_Decrypt(cipherText, outLen, recoveredText, decryLen, key, iv);
 // std::memcpy(charArray, byteBuffer.data(), bufferSize);
  std::cout << "Decrypted: " << recoveredText << std::endl;

  return 0;
}

#endif