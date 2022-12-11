# Cryptography library

Cryptography, as the name implies, is a library that provides encryption and decryption functions.<br>
When using the library, include ```cryptography.h```.<br>
Currently, it includes the following secret key cryptographic functions and encryption modes.

## Secret key encryption

When encrypting plaintext with secret key cryptography, specify the algorithm and mode as follows, and create an instance.<br>

```
cryptography::secret_key<cryptography::Algorithm, cryptography::Mode> instance;
```

Secret key cryptographic algorithm:<br>
　DES, AES, AESNI, Camellia, CAST128, CAST256, RC6, SEED, Twofish

Block cipher modes of operation:<br>
　ECB, CBC, CFB, OFB, CTR

The usage is as follows.

```
#include <cstdio>
#include "cryptography.h"

using namespace cryptography;

static const uint8_t TEST_KEY_128BIT[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

static const uint8_t TEST_IV_128BIT[16] = {
  0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
  0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

int main() {
  int encret = SUCCESS;
  secret_key<AES, CBC> aes_cbc;
  uint8_t plaintext[47] = "Test encryption with the Cryptography library.";
  uint8_t ciphertext[48] = {0};
  uint8_t outtext[48] = {0};

  encret = aes_cbc.initialize(TEST_KEY_128BIT, sizeof(TEST_KEY_128BIT),
                              TEST_IV_128BIT,  sizeof(TEST_IV_128BIT));
  if (SUCCESS != encret) {
    return 1; // error
  }

  encret = aes_cbc.encrypt(plaintext, sizeof(plaintext),
                           ciphertext, sizeof(ciphertext));
  if (SUCCESS != encret) {
    return 1; // error
  }

  encret = aes_cbc.decrypt(ciphertext, sizeof(ciphertext),
                           outtext, sizeof(outtext));
  if (SUCCESS != encret) {
    return 1; // error
  }

  aes_cbc.clear();  // Clear the subkey held by secret_key.

  printf("%s\n", outtext);
  return 0;
}
```

The return code corresponding to the above encret is as follows.

| Error code  | Explanation |
|-------------|-------------|
| SUCCESS | Successful termination. |
| UNSET_KEY_ERROR | Encryption or decryption using the secret key cryptosystem was performed without setting the key. |
| KEY_SIZE_ERROR | The set secret key size is invalid. |
| STRING_SIZE_ERROR | The size of the buffer that stores the plaintext to be encrypted or the encrypted text is invalid. |
| UNSET_IV_ERROR | Encryption or decryption using the secret key cryptosystem was performed without setting the initialization vector. |
| IV_SIZE_ERROR | The set initialization vector size is invalid. |
| PADDING_ERROR | The padding could not be removed normally. |

Notes:<br>
- The ciphertext size must be specified in 16 bytes or a multiple of 8 bytes. For example, when encrypting with AES, you need to specify the array size as follows. <br>If plaintext[16] then ciphertext[32], if plaintext[20] then ciphertext[32], if plaintext[40] then ciphertext[48].
<br>The ciphertext size can be calculated by ```((Plaintext size / 16) + 1) * 16``` or ```((Plaintext size / 8) + 1) * 8```.
　
