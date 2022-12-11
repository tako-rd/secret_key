/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef CAST128_H
#define CAST128_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

/* Prototype declaration of class. */
class cast128_base;
class cast128;

/* Alias declaration */
using CAST128 = cast128;

class cast128_base {
 public:
  cast128_base() noexcept {};

  ~cast128_base() {};

  static const uint32_t UNIT_SIZE = 8;
};

class cast128 final : public cast128_base, public secret_key_base<cast128> {
 public:
  cast128() noexcept : km_{0}, kr_{0}, has_subkeys_(false), is_12round_(false) {};

  ~cast128();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept;

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept;

  void clear() noexcept;

 private:
  void expand_key(const uint32_t * const key, uint32_t *km, uint32_t *kr) noexcept;

  uint32_t fa_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;
 
  uint32_t fb_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t fc_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t km_[16];

  uint32_t kr_[16];

  bool has_subkeys_;

  bool is_12round_;
};

}

#endif

