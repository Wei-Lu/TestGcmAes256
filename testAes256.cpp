// testAes256.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <cryptlib.h>
#include <aes.h>
#include <gcm.h>
#include <filters.h>
#include <hex.h>
#include <files.h>

using namespace CryptoPP;
using namespace std;

#if 0
void EncryptAES_GCM(const std::string& keyHex, const std::string& ivHex,
  const std::string& plaintext, std::string& cipherText) {
  // Convert hex strings to binary
  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));

  SecByteBlock iv(AES::BLOCKSIZE);
  StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

  GCM<AES>::Encryption encryption;
  encryption.SetKeyWithIV(key, key.size(), iv, iv.size());

  std::string cipherWithTag;
  AuthenticatedEncryptionFilter encryptionFilter(encryption,
    new StringSink(cipherWithTag),
    false,  // No AAD
    16      // Tag size (default: 16 bytes)
  );

  encryptionFilter.Put((const byte*)plaintext.data(), plaintext.size());
  encryptionFilter.MessageEnd();

  cipherText = cipherWithTag;  // Includes both ciphertext and tag

  std::cout << "Ciphertext (Hex): ";
  StringSource(cipherText, true, new HexEncoder(new FileSink(std::cout)));
  std::cout << std::endl;
}

void DecryptAES_GCM(const std::string& keyHex, const std::string& ivHex,
  const std::string& cipherText, std::string& decryptedText) {
  SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));

  SecByteBlock iv(AES::BLOCKSIZE);
  StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

  GCM<AES>::Decryption decryption;
  decryption.SetKeyWithIV(key, key.size(), iv, iv.size());

  try {
    AuthenticatedDecryptionFilter decryptionFilter(decryption,
      new StringSink(decryptedText),
      AuthenticatedDecryptionFilter::MAC_AT_END,  // Expect tag at end
      16  // Tag size
    );

    decryptionFilter.Put((const byte*)cipherText.data(), cipherText.size());
    decryptionFilter.MessageEnd();

    std::cout << "Decrypted Text: " << decryptedText << std::endl;
  }
  catch (const Exception& ex) {
    std::cerr << "Decryption failed: " << ex.what() << std::endl;
  }
}
#endif


int EncryptAES_GCM(const std::string& keyHex, const std::string& ivHex,
  const byte * plaintext, int lenIn,  byte * cipherText, int &lenInOut) {
  // Convert hex strings to binary
  //SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  SecByteBlock key(32);
  StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));

  SecByteBlock iv(AES::BLOCKSIZE);
  StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

  GCM<AES>::Encryption encryption;
  encryption.SetKeyWithIV(key, key.size(), iv, iv.size());

  std::string cipherWithTag;
  AuthenticatedEncryptionFilter encryptionFilter(encryption,
    new StringSink(cipherWithTag),
    false,  // No AAD
    16      // Tag size (default: 16 bytes)
  );

  encryptionFilter.Put(plaintext, lenIn);
  encryptionFilter.MessageEnd();

  memcpy(cipherText, cipherWithTag.data(), cipherWithTag.size());  // Includes both ciphertext and tag

  std::cout << "Ciphertext (Hex): ";
  StringSource(cipherWithTag, true, new HexEncoder(new FileSink(std::cout)));
  std::cout << std::endl;
  lenInOut = cipherWithTag.size();
  return 0;
}

void DecryptAES_GCM(const std::string& keyHex, const std::string& ivHex,
  const byte *cipherText, int lenIn,   byte * decryptedBuff, int &lenInOut) {
  SecByteBlock key(32);
  //SecByteBlock key(AES::DEFAULT_KEYLENGTH);
  StringSource(keyHex, true, new HexDecoder(new ArraySink(key, key.size())));

  SecByteBlock iv(AES::BLOCKSIZE);
  StringSource(ivHex, true, new HexDecoder(new ArraySink(iv, iv.size())));

  GCM<AES>::Decryption decryption;
  decryption.SetKeyWithIV(key, key.size(), iv, iv.size());
  string decryptedText;
  try {
    AuthenticatedDecryptionFilter decryptionFilter(decryption,
      new StringSink(decryptedText),
      AuthenticatedDecryptionFilter::MAC_AT_END,  // Expect tag at end
      16  // Tag size
    );

    decryptionFilter.Put(cipherText, lenIn);
    decryptionFilter.MessageEnd();

    memcpy(decryptedBuff, decryptedText.data(), decryptedText.size());
    lenInOut = decryptedText.size();
    std::cout << "Decrypted Text: " << decryptedText << std::endl;
  }
  catch (const Exception& ex) {
    std::cerr << "Decryption failed: " << ex.what() << std::endl;
  }
}
int main() {
  std::string keyHex = "603deb1015ca71be2b73aef0857d7781603deb1015ca71be2b73aef0857d7781";  // 16-byte key
  std::string ivHex = "000102030405060708090A0B0C0D0E0F";   // 16-byte IV
  std::string plaintext = "Hello, AES-GCM!";
 // std::string cipherText, decryptedText;
  byte cipherText[100], decryptedText[100];
  int lenInOut = 100;
  EncryptAES_GCM(keyHex, ivHex, (byte *)plaintext.data(), plaintext.size(), cipherText, lenInOut);
  int lenOut = 100;
  DecryptAES_GCM(keyHex, ivHex, cipherText, lenInOut, decryptedText, lenOut);

  byte abc[] = { 1, 5, 0, 8 };
  lenInOut = 100;
  EncryptAES_GCM(keyHex, ivHex, abc, sizeof(abc), cipherText, lenInOut);
  lenOut = 100;
  DecryptAES_GCM(keyHex, ivHex, cipherText, lenInOut, decryptedText, lenOut);
  return 0;
}


#if 0

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

#endif