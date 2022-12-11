/*!
 * cryptography library
 *
 * Copyright (c) 2022 tako
 *
 * This software is released under the MIT license.
 * see https://opensource.org/licenses/MIT
 */

#ifndef CAST256_H
#define CAST256_H

#include "crypto/secret_key/secret_key_base.h"

namespace cryptography {

/* Prototype declaration of class. */
class cast256_base;
class cast256;

/* Alias declaration */
using CAST256 = cast256;

class cast256_base {
 public:
  cast256_base() noexcept {};

  ~cast256_base() {};

  static const uint32_t UNIT_SIZE = 16;
};

class cast256 final : public cast256_base, public secret_key_base<cast256> {
public:
  cast256() noexcept : km_{0}, kr_{0}, has_subkeys_(false) {};

  ~cast256();

  int32_t initialize(const uint8_t *key, const uint32_t ksize) noexcept;

  int32_t encrypt(const uint8_t * const ptext, uint8_t *ctext) noexcept;

  int32_t decrypt(const uint8_t * const ctext, uint8_t *ptext) noexcept;

  void clear() noexcept;

private:
  void expand_key(const uint32_t * const key, uint32_t *km, uint32_t *kr) noexcept;

  uint32_t f1_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t f2_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t f3_function(uint32_t d, uint32_t kmi, uint32_t kri) const noexcept;

  uint32_t km_[48];

  uint32_t kr_[48];

  bool has_subkeys_;
};

}

#endif
