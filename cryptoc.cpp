#include "cryptoc.h"
#include "files.h"
#include "hex.h"
#include "gcm.h"
#include "hexUtil.h"

using namespace CryptoPP;


void aES256EncryptString(const std::string& plainText, std::string& cipherText, const byte key[KEY_BYTE_SIZE], const byte iv[IV_BYTE_SIZE])
{
  try {
    GCM<AES>::Encryption enCRYPTOR256;
    enCRYPTOR256.SetKeyWithIV(key, KEY_BYTE_SIZE, iv, IV_BYTE_SIZE);
    const int TAG_SIZE = 16;

    AuthenticatedEncryptionFilter encryptionFilter(
      enCRYPTOR256,
      new StringSink(cipherText), false, TAG_SIZE);

    encryptionFilter.ChannelPut(DEFAULT_CHANNEL, (byte *)plainText.c_str(), plainText.size());
    encryptionFilter.ChannelMessageEnd(DEFAULT_CHANNEL);
    SecByteBlock tag(TAG_SIZE);

    encryptionFilter.Get(tag, tag.size());
  }
  catch (const Exception& e) {
    std::cerr << "Encryption error: " << e.what() << std::endl;
    return;
  }
}

void aES256DecryptString(const std::string& cipherText, std::string& decryptedText, const byte key[KEY_BYTE_SIZE], const byte iv[IV_BYTE_SIZE])
{
  try {
    GCM<AES>::Decryption deCRYPTOR256;
    deCRYPTOR256.SetKeyWithIV(key, KEY_BYTE_SIZE, iv, IV_BYTE_SIZE);

    AuthenticatedDecryptionFilter decryptionFilter(
      deCRYPTOR256,
      new StringSink(decryptedText), AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16
    );

    decryptionFilter.ChannelPut(DEFAULT_CHANNEL, reinterpret_cast<const byte*>(cipherText.c_str()), cipherText.size());
    decryptionFilter.ChannelMessageEnd(DEFAULT_CHANNEL);
  }
  catch (const Exception& e) {
    std::cerr << "Decryption error: " << e.what() << std::endl;

  }
}


void aES256Encrypt(const byte* buffer, int lenIn, byte*cipherOut, int& lenInOut, const byte key[KEY_BYTE_SIZE], const byte iv[IV_BYTE_SIZE])
{
  std::string hexTemp = BinaryArrayToHex(buffer, lenIn);
  std::string cipherText;
  aES256EncryptString(hexTemp, cipherText, key, iv);
  lenInOut = std::min((int)cipherText.length(), lenInOut);
  std::memcpy(cipherOut, cipherText.data(), lenInOut);
}

void aES256Decrypt(const byte* cipherBuff, int lenIn, byte* resultBuff, int& lenInOut, const byte key[KEY_BYTE_SIZE], const byte iv[IV_BYTE_SIZE])
{
  std::string cipherText(reinterpret_cast<const char*>(cipherBuff), lenIn);
  std::string decryptedText;
  aES256DecryptString(cipherText, decryptedText, key, iv);
  lenInOut = HexToBinaryArray(decryptedText, resultBuff, lenInOut);
}
