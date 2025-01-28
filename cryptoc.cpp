#include "cryptoc.h"
#include "files.h"
#include "hex.h"
#include "gcm.h"
#include "hexUtil.h"

using namespace CryptoPP;
const int KEY_BYTE_SIZE = 32;
const int IV_SIZE = 16;
void AES256_Encrypt(const std::string& plainText, std::string& cipherText, const byte key[32], const byte iv[16]) {

  std::string encodedKey, encodedIV, encodedTag;

  // Encryption
  try {
    GCM<AES>::Encryption enCRYPTOR256;
    enCRYPTOR256.SetKeyWithIV(key, KEY_BYTE_SIZE, iv, IV_SIZE);

    AuthenticatedEncryptionFilter encryptionFilter(
      enCRYPTOR256,
      new StringSink(cipherText), false, 16 // 16-byte (128-bit) authentication tag
    );

    encryptionFilter.ChannelPut(DEFAULT_CHANNEL, (byte *)plainText.c_str(), plainText.size());
    encryptionFilter.ChannelMessageEnd(DEFAULT_CHANNEL);

    // Authentication tag
    const int TAG_SIZE = 16;
    SecByteBlock tag(TAG_SIZE); // Replace TAG_SIZE with the tag size used (e.g., 16 bytes for AES-GCM)

// Retrieve the tag
    encryptionFilter.Get(tag, tag.size());
    // Convert to a string if needed
    std::string tagStr((const char *)tag.data(), tag.size());


    // Encode key, IV, and tag for display
    StringSource(key, KEY_BYTE_SIZE, true, new HexEncoder(new StringSink(encodedKey)));
    StringSource(iv, IV_SIZE, true, new HexEncoder(new StringSink(encodedIV)));
    StringSource(tagStr, true, new HexEncoder(new StringSink(encodedTag)));

    std::cout << "Key (Hex): " << encodedKey << std::endl;
    std::cout << "IV (Hex): " << encodedIV << std::endl;
    std::cout << "Tag (Hex): " << encodedTag << std::endl;
    std::cout << "Ciphertext (Hex): ";
    StringSource(cipherText, true, new HexEncoder(new FileSink(std::cout)));
    std::cout << std::endl;
  }
  catch (const Exception& e) {
    std::cerr << "Encryption error: " << e.what() << std::endl;
    return;
  }
}

void AES256_Decrypt(const std::string& cipherText, std::string& decryptedText, const byte key[32], const byte iv[16]) {

 // std::string decryptedText;

  try {
    GCM<AES>::Decryption deCRYPTOR256;
    deCRYPTOR256.SetKeyWithIV(key, KEY_BYTE_SIZE, iv, IV_SIZE);

    AuthenticatedDecryptionFilter decryptionFilter(
      deCRYPTOR256,
      new StringSink(decryptedText), AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16
    );

    decryptionFilter.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(cipherText.c_str()), cipherText.size());
    decryptionFilter.ChannelMessageEnd(DEFAULT_CHANNEL);

    std::cout << "Decrypted text: " << decryptedText << std::endl;


  }
  catch (const Exception& e) {
    std::cerr << "Decryption error: " << e.what() << std::endl;

  }
}


void aES256Encrypt(const byte* buffer, int lenIn, byte*cipherOut, int& lenInOut, const byte key[32], const byte iv[16])
{
  std::string hexTemp = BinaryArrayToHex(buffer, lenIn);
  std::string cipherText;
  AES256_Encrypt(hexTemp, cipherText, key, iv);
  lenInOut = std::min((int)cipherText.length(), lenInOut);
  std::memcpy(cipherOut, cipherText.data(), lenInOut);
}

void aES256Decrypt(const byte* cipherBuff, int lenIn, byte* resultBuff, int& lenInOut, const byte key[32], const byte iv[16])
{
  std::string cipherText(reinterpret_cast<const char*>(cipherBuff), lenIn);
  std::string decryptedText;
  AES256_Decrypt(cipherText, decryptedText, key, iv);
  HexToBinaryArray(decryptedText, resultBuff, lenInOut);
}
