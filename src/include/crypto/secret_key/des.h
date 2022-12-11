/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef DES_H
#define DES_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

/* Prototype declaration of class. */
class des_base;
class des;

/* Alias declaration */
using DES = des;

class des_base {
 public:
  des_base() noexcept {};

  ~des_base() {};

  static const uint32_t UNIT_SIZE = 8;
};

class des final : public des_base, public secret_key_base<des> {
 public:

  des() noexcept : encrypto_subkeys_{0}, decrypto_subkeys_{0}, has_subkeys_(false) {};

  ~des();

  int32_t initialize(const uint8_t *key, const uint32_t ksize);

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext);

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext);

  void clear();

 private:
  void create_encrypto_subkeys(const uint64_t key, uint64_t *subkeys) const noexcept;

  void create_decrypto_subkeys(const uint64_t key, uint64_t *subkeys) const noexcept;

  void permuted_choice1(const uint64_t key, uint32_t &left, uint32_t &right) const noexcept;

  void permuted_choice2(const uint32_t left, const uint32_t right, uint64_t &subkey) const noexcept;

  void initialize_permute(uint32_t *text) const noexcept;

  void finalize_permute(uint32_t *text) const noexcept;

  void round(const uint64_t subkey, const uint32_t rtext, uint32_t &roundtext) const noexcept;

  void expand(const uint32_t rtext, uint64_t &etext) const noexcept;

  void permute(const uint32_t rtext, uint32_t &ptext) const noexcept;

  uint64_t encrypto_subkeys_[16];

  uint64_t decrypto_subkeys_[16];

  bool has_subkeys_;
};

}

#endif