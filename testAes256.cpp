// testAes256.cpp : This file contains the 'main' function. Program execution begins and ends there.
//


#include <iostream>
#include <string>
#include <vector>
#include <cryptlib.h>
#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <osrng.h>

using namespace CryptoPP;

void printHex(const std::string& label, const std::vector<byte>& data) {
  std::cout << label << ": ";
  for (byte b : data) {
    std::cout << std::hex << (int)b << " ";
  }
  std::cout << std::dec << std::endl;
}

int main() {
  AutoSeededRandomPool prng;

  // Key and IV
  std::vector<byte> key(32); // 32 bytes for 256-bit key
  std::vector<byte> iv(12);  // 12 bytes for 96-bit IV
  prng.GenerateBlock(key.data(), key.size());
  prng.GenerateBlock(iv.data(), iv.size());
//  std::vector<byte> iv = { 0x39, 0xb1, 0x41, 0x99, 0x57, 0xdf, 0x49, 0xbc, 0x11, 0x3f, 0x83, 0x44 };  // Replace with a 128-bit IV
//  std::vector<byte> key = { 0x32, 0x35, 0x20, 0x8d, 0x6e, 0x9e, 0x48, 0x4e, 0x02, 0x07, 0x09, 0x2d, 0x48, 0xea, 0x34, 0x7d, 0x64, 0xe0, 0x3a, 0xf0, 0xc7, 0x20, 0xf3, 0x38, 0x38, 0x0e, 0x94, 0x05, 0x8a, 0x2d, 0xe8, 0xe9 }; // Replace with a 256-bit key

  // Print key and IV
  printHex("Key", key);
  printHex("IV", iv);

  // Plaintext and AAD
 //td::string plaintextStr = "This is the data to encrypt!";
  std::string plaintextStr = "abcdefghijklmnopqrstuvwxyzt!";
  std::vector<byte> plaintext(plaintextStr.begin(), plaintextStr.end());
  std::string aadStr = "AdditionalData";
  std::vector<byte> aad(aadStr.begin(), aadStr.end());

  // Buffers for ciphertext and tag
  std::vector<byte> ciphertext(plaintext.size());
  std::vector<byte> tag(16); // Typical GCM tag size is 16 bytes

  try {
    // Encryption setup
    GCM<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    AuthenticatedEncryptionFilter ef(encryptor, new VectorSink(ciphertext), false, tag.size());

    // Add AAD
    ef.ChannelPut(DEFAULT_CHANNEL, aad.data(), aad.size());

    // Encrypt plaintext
    ef.ChannelPut(DEFAULT_CHANNEL, plaintext.data(), plaintext.size());

    // Finalize encryption
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);

    if (ef.MaxRetrievable() == 0) {
      std::cerr << "Error: No data in filter!" << std::endl;
      return -1;
    }


    // Get the tag
    int tagLen = ef.Get(tag.data(), tag.size());


    // Print ciphertext and tag
    printHex("Ciphertext", ciphertext);
    printHex("Tag", tag);

    // Decryption setup
    GCM<AES>::Decryption decryptor;
    decryptor.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());

    std::vector<byte> decryptedtext(plaintext.size());
    AuthenticatedDecryptionFilter df(decryptor, new VectorSink(decryptedtext), AuthenticatedDecryptionFilter::DEFAULT_FLAGS, tag.size());

    // Add AAD
    df.ChannelPut(DEFAULT_CHANNEL, aad.data(), aad.size());

    // Decrypt ciphertext
    df.ChannelPut(DEFAULT_CHANNEL, ciphertext.data(), ciphertext.size());

    // Add the tag
    df.ChannelPut(DEFAULT_CHANNEL, tag.data(), tag.size());

    // Finalize decryption
    df.ChannelMessageEnd(DEFAULT_CHANNEL);
    if (df.MaxRetrievable() == 0) {
      std::cerr << "Error: No data in filter 2!" << std::endl;
      return -1;
    }


    // Convert decrypted text to string
    std::string decryptedStr(decryptedtext.begin(), decryptedtext.end());

    std::cout << "Decrypted text: " << decryptedStr << std::endl;
  }
  catch (const Exception& e) {
    std::cerr << "Error: " << e.what() << std::endl;
  }

  return 0;
}

