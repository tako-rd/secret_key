/*!
* cryptography library
*
* Copyright (c) 2022 tako
*
* This software is released under the MIT license.
* see https://opensource.org/licenses/MIT
*/

#include <stdint.h>

#ifndef GTEST_SEED_DEFS_H
#define GTEST_SEED_DEFS_H

/**************************************************************/
/* See below.                                                 */
/* RFC 4269  The SEED Encryption Algorithm  December 2005     */
/* https://datatracker.ietf.org/doc/html/rfc4269              */
/**************************************************************/

/**************************************************************/
/* See below.                                                 */
/* Appendix B.  Test Vectors                                  */
/**************************************************************/

/* B.1. */
static const uint8_t SEED_EXAM1_128BIT_PLAINTEXT[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint8_t SEED_EXAM1_128BIT_KEY[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t SEED_EXAM1_128BIT_CIPHERTEXT[16] = {
  0x5E, 0xBA, 0xC6, 0xE0, 0x05, 0x4E, 0x16, 0x68, 0x19, 0xAF, 0xF1, 0xCC, 0x6D, 0x34, 0x6C, 0xDB
};

/* B.2. */
static const uint8_t SEED_EXAM2_128BIT_PLAINTEXT[16] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t SEED_EXAM2_128BIT_KEY[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint8_t SEED_EXAM2_128BIT_CIPHERTEXT[16] = {
  0xC1, 0x1F, 0x22, 0xF2, 0x01, 0x40, 0x50, 0x50, 0x84, 0x48, 0x35, 0x97, 0xE4, 0x37, 0x0F, 0x43,
};

/* B.3. */
static const uint8_t SEED_EXAM3_128BIT_PLAINTEXT[16] = {
  0x83, 0xA2, 0xF8, 0xA2, 0x88, 0x64, 0x1F, 0xB9, 0xA4, 0xE9, 0xA5, 0xCC, 0x2F, 0x13, 0x1C, 0x7D,
};

static const uint8_t SEED_EXAM3_128BIT_KEY[16] = {
  0x47, 0x06, 0x48, 0x08, 0x51, 0xE6, 0x1B, 0xE8, 0x5D, 0x74, 0xBF, 0xB3, 0xFD, 0x95, 0x61, 0x85,
};

static const uint8_t SEED_EXAM3_128BIT_CIPHERTEXT[16] = {
  0xEE, 0x54, 0xD1, 0x3E, 0xBC, 0xAE, 0x70, 0x6D, 0x22, 0x6B, 0xC3, 0x14, 0x2C, 0xD4, 0x0D, 0x4A,
};

/* B.4. */
static const uint8_t SEED_EXAM4_128BIT_PLAINTEXT[16] = {
  0xB4, 0x1E, 0x6B, 0xE2, 0xEB, 0xA8, 0x4A, 0x14, 0x8E, 0x2E, 0xED, 0x84, 0x59, 0x3C, 0x5E, 0xC7,
};

static const uint8_t SEED_EXAM4_128BIT_KEY[16] = {
  0x28, 0xDB, 0xC3, 0xBC, 0x49, 0xFF, 0xD8, 0x7D, 0xCF, 0xA5, 0x09, 0xB1, 0x1D, 0x42, 0x2B, 0xE7,
};

static const uint8_t SEED_EXAM4_128BIT_CIPHERTEXT[16] = {
  0x9B, 0x9B, 0x7B, 0xFC, 0xD1, 0x81, 0x3C, 0xB9, 0x5D, 0x0B, 0x36, 0x18, 0xF4, 0x0F, 0x51, 0x22,
};


#endif