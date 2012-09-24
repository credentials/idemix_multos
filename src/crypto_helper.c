/**
 * crypto_helper.c
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope t_ it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, September 2011.
 */

#include "crypto_helper.h"

#include <multosarith.h>
#include <multoscrypto.h>
#include <string.h>

#include "defs_externals.h"
#include "funcs_debug.h"
#include "funcs_helper.h"
#include "crypto_multos.h"

#ifdef TEST
  #include "defs_test.h"
  
  int m_count = 0;
#endif // TEST

/********************************************************************/
/* Cryptographic helper functions                                   */
/********************************************************************/

//////////////////////////////////////////////////////////////////////
// Shared functions                                                 //
//////////////////////////////////////////////////////////////////////

/**
 * Compute a cryptographic hash of the given input values
 * 
 * @param list of values to be included in the hash
 * @param length of the values list
 * @param result of the hashing operation
 * @param buffer which can be used for temporary storage
 * @param size of the buffer
 */
void crypto_compute_hash(ValueArray list, int length, ByteArray result,
                         ByteArray buffer, int size) {
  int i, offset = size;
  
  // Store the values
  for (i = length - 1; i >= 0; i--) {
    offset = asn1_encode_int(list[i].data, list[i].size, buffer, offset);
  }
  
  // Store the number of values in the sequence
  offset = asn1_encode_int((ByteArray) &length, 2, buffer, offset);
  
  // Finalise the sequence
  offset = asn1_encode_seq(size - offset, length, buffer, offset);
  
  // Hash the data
  debugValue("asn1rep", buffer + offset, size - offset);
  SHA1(size - offset, result, buffer + offset);
}

/**
 * Generate a random number in the buffer of length bits
 * 
 * @param buffer to store the generated random number
 * @param length in bits of the random number to generate
 */
void crypto_generate_random(ByteArray buffer, int length) {
#ifndef TEST
  Byte number[8];
  ByteArray random = buffer;
    
  // Generate the random number in blocks of eight bytes (64 bits)
  while (length >= 64) {
    GetRandomNumber(number);
    COPYN(8, random, number);
    length -= 64;
    random += 8;
  }
  
  // Generate the remaining few bytes/bits
  if (length > 0) {
    GetRandomNumber(number);
    if (length % 8 == 0) {
      memcpy(random, number, length / 8);
    } else {
      memcpy(random, number, (length / 8) + 1);
      buffer[0] &= 0xFF >> (8 - (length % 8));
    }
  }
#else // TEST

  // Copy a test value instead of generating a random
  switch (length) {
    case LENGTH_VPRIME:
      memcpy(buffer, TEST_vPrime, SIZE_VPRIME);
      break;
    case LENGTH_R_A - 7:
      memcpy(buffer, TEST_r_A, SIZE_R_A);
      break;
    case LENGTH_VPRIME_:
      memcpy(buffer, TEST_vPrime_, SIZE_VPRIME_);
      break;
    case LENGTH_S_A:
      memcpy(buffer, TEST_m_, SIZE_S_A);
      break;
    case LENGTH_STATZK:
      memcpy(buffer, TEST_n_2, SIZE_STATZK);
      break;
    case LENGTH_M_:
      switch (m_count % 4) {
        case 0:
          memcpy(buffer, TEST_m_0, SIZE_M_);
          break;
        case 1:
          memcpy(buffer, TEST_m_1, SIZE_M_);
          break;
        case 2:
          memcpy(buffer, TEST_m_2, SIZE_M_);
          break;
        case 3:
          memcpy(buffer, TEST_m_3, SIZE_M_);
          break;
        default:
          break;
      }
      m_count++;
      break;
    case LENGTH_E_:
      memcpy(buffer, TEST_e_, SIZE_E_);
      break;
    case LENGTH_V_:
      memcpy(buffer, TEST_v_, SIZE_V_);
      break;
    default:
      break;
  }
#endif // TEST
}

#define buffer apdu.temp.data

/**
 * Compute the helper value S' = S^(2_l) where l = SIZE_S_EXPONENT*8
 * 
 * This value is required for exponentiations with base S and an 
 * exponent which is larger than SIZE_N bytes.
 */
void crypto_compute_S_(void) {
  // Store the value l = SIZE_S_EXPONENT*8 in the buffer
  CLEARN(SIZE_S_EXPONENT + 1, buffer);
  buffer[0] = 0x01;
  
  // Compute S_ = S^(2_l)
  crypto_modexp(SIZE_S_EXPONENT + 1, SIZE_N, buffer, 
    credential->issuerKey.n, credential->issuerKey.S, credential->issuerKey.S_);
}

/**
 * Compute the modular exponentiation: result = S^exponent mod n
 * 
 * This function will use the helper value S' to compute exponentiations 
 * with exponents larger than SIZE_N bytes.
 * 
 * @param size of the exponent
 * @param exponent the power to which the base S should be raised
 * @param result of the computation
 */
void crypto_modexp_special(int size, ByteArray exponent, ByteArray result) {
  
  if (size > SIZE_N) {
    // Compute result = S^(exponent_bottom) * S_^(exponent_top)
    crypto_modexp(SIZE_S_EXPONENT, SIZE_N, 
      exponent + size - SIZE_S_EXPONENT, credential->issuerKey.n, credential->issuerKey.S, result);
    crypto_modexp(size - SIZE_S_EXPONENT, SIZE_N, 
      exponent, credential->issuerKey.n, credential->issuerKey.S_, buffer);
    crypto_modmul(SIZE_N, result, buffer, credential->issuerKey.n);
  } else {
    // Compute result = S^exponent
    crypto_modexp(size, SIZE_N, 
      exponent, credential->issuerKey.n, credential->issuerKey.S, result);
  }
}
