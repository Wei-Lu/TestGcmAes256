#include "cryptoc.h"
#include "files.h"
#include "hex.h"
#include "gcm.h"

using namespace CryptoPP;
const int KEY_BYTE_SIZE = 32;
const int IV_SIZE = 16;
void AES256_Encrypt(const CryptoPP::byte* plainText, CryptoPP::byte* cipherText, int lengthIn, int lengthOut, const CryptoPP::byte key[32], const CryptoPP::byte iv[16])
{
  std::string encodedKey, encodedIV, encodedTag;

  // Encryption
  try {
    GCM<AES>::Encryption enCRYPTOR256;
    enCRYPTOR256.SetKeyWithIV(key, KEY_BYTE_SIZE, iv, IV_SIZE);
    ArraySink encryptedTextSink(cipherText, lengthOut);

    AuthenticatedEncryptionFilter encryptionFilter(
      enCRYPTOR256,
      &encryptedTextSink, false, 16 // 16-byte (128-bit) authentication tag
    );

    encryptionFilter.ChannelPut(DEFAULT_CHANNEL, plainText, lengthIn);
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

void AES256_Decrypt(const CryptoPP::byte* cipherText, CryptoPP::byte* recoveredText, int lengthIn, int lengthOut, const CryptoPP::byte key[32], const CryptoPP::byte iv[16])
{
 // std::string decryptedText;

  try {
    std::vector<byte> decrypted;
    decrypted.resize(lengthIn);
    GCM<AES>::Decryption deCRYPTOR256;
    deCRYPTOR256.SetKeyWithIV(key, KEY_BYTE_SIZE, iv, IV_SIZE);
    ArraySink plaintextSink(decrypted.data(), decrypted.size());
    AuthenticatedDecryptionFilter decryptionFilter(
      deCRYPTOR256, &plaintextSink,  AuthenticatedDecryptionFilter::THROW_EXCEPTION, 16
    );

    decryptionFilter.ChannelPut(DEFAULT_CHANNEL, cipherText, lengthIn);
    decryptionFilter.ChannelMessageEnd(DEFAULT_CHANNEL);

    std::cout << "Decrypted text: " << decrypted.data() << std::endl;


  }
  catch (const Exception& e) {
    std::cerr << "Decryption error: " << e.what() << std::endl;

  }

}

