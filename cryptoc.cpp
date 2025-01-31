#include "cryptoc.h"
#include "files.h"
#include "hex.h"
#include "gcm.h"
#include <vector>

using namespace std;
using namespace CryptoPP;
const int KEY_BYTE_SIZE = 32;
const int IV_SIZE = 16;

int aes256Encrypt(const byte* plainText, int lenIn, byte* encriptBuffer, int& lenInOut, const byte key[32], const byte iv[16])
{
  vector<byte> cipherWithTag;
  try
  {
    GCM<AES>::Encryption encryption;
    encryption.SetKeyWithIV(key, 32, iv, 16);

    AuthenticatedEncryptionFilter encryptionFilter(encryption,
      new VectorSink(cipherWithTag),
      false,  // No AAD
      16      // Tag size (default: 16 bytes)
    );

    encryptionFilter.Put(plainText, lenIn);
    encryptionFilter.MessageEnd();
  }
  catch (const Exception& ex) {
    std::cerr << "Encryption failed: " << ex.what() << std::endl;
    return -1;
  }
  memset(encriptBuffer, 0, lenInOut);
  memcpy(encriptBuffer, cipherWithTag.data(), cipherWithTag.size());  // Includes both ciphertext and tag

  lenInOut = cipherWithTag.size();
  return 0;
}

int aes256Decrypt(const byte* encryptBuffer, int lenIn, byte* decryptedBuff, int& lenInOut, const byte key[32], const byte iv[16])
{
  GCM<AES>::Decryption decryption;
  decryption.SetKeyWithIV(key, 32, iv, 16);
  vector<byte> decryptedText;
  try {
    AuthenticatedDecryptionFilter decryptionFilter(decryption,
      new VectorSink(decryptedText),
      AuthenticatedDecryptionFilter::MAC_AT_END,  // Expect tag at end
      16  // Tag size
    );

    decryptionFilter.Put(encryptBuffer, lenIn);
    decryptionFilter.MessageEnd();
    memset(decryptedBuff, 0, lenInOut);
    memcpy(decryptedBuff, decryptedText.data(), decryptedText.size());
    lenInOut = decryptedText.size();
  }
  catch (const Exception& ex) {
    std::cerr << "Decryption failed: " << ex.what() << std::endl;
    return -1;
  }
  return 0;
}

