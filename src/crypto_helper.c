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
#ifndef SHA1_PADDED
  SHA256(size - offset, result, buffer + offset);
#else // SHA1_PADDED
  for (i = 0; i < SIZE_H; i++) {
	  result[i] = i;
  }
  SHA1(size - offset, result, buffer + offset);
#endif // SHA1_PADDED
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
  buffer += ((length + 7) / 8);

  // Generate the random number in blocks of eight bytes (64 bits)
  while (length >= 64) {
    buffer -= 8;
    __push(buffer);
    __code(PRIM, PRIM_RANDOM);
    __code(STOREI, 8);
    length -= 64;
  }

  // Generate the remaining few bytes/bits
  if (length > 0) {
    buffer -= (length + 7) / 8;
    GetRandomNumber(number);
    number[0] &= 0xFF >> ((64 - length) % 8);
    memcpy(buffer, number, (length + 7) / 8);
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

/**
 * Compute the helper value S' = S^(2_l) where l = SIZE_S_EXPONENT*8
 *
 * This value is required for exponentiations with base S and an
 * exponent which is larger than SIZE_N bytes.
 */
void crypto_compute_S_(void) {
  // Store the value l = SIZE_S_EXPONENT*8 in the buffer
  memset(public.issue.buffer.data, 0xFF, SIZE_S_EXPONENT);

  // Compute S_ = S^(2_l)
  crypto_modexp(SIZE_S_EXPONENT, SIZE_N, public.issue.buffer.data,
    credential->issuerKey.n, credential->issuerKey.S, credential->issuerKey.S_);
  crypto_modmul(SIZE_N, credential->issuerKey.S_, credential->issuerKey.S, 
    credential->issuerKey.n);
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
void crypto_modexp_special(int size, ByteArray exponent, ByteArray result, ByteArray buffer) {
  if (size > SIZE_N) {
    // Compute result = S^(exponent_bottom) * S_^(exponent_top)
    crypto_modexp(SIZE_S_EXPONENT, SIZE_N, exponent + size - SIZE_S_EXPONENT,
      credential->issuerKey.n, credential->issuerKey.S, result);
    crypto_modexp(size - SIZE_S_EXPONENT, SIZE_N,
      exponent, credential->issuerKey.n, credential->issuerKey.S_, buffer);
    crypto_modmul(SIZE_N, result, buffer, credential->issuerKey.n);
  } else {
    // Compute result = S^exponent
    crypto_modexp(size, SIZE_N,
      exponent, credential->issuerKey.n, credential->issuerKey.S, result);
  }
}

/**
 * Clear size bytes from a bytearray
 *
 * @param size the amount of bytes to clear
 * @param buffer to be cleared
 */
void crypto_clear(int size, ByteArray buffer) {
  while (size > 255) {
    __push(buffer);
    __code(PUSHZ, 255);
    __code(STOREI, 255);
    buffer += 255;
    size -= 255;
  }
  memset(buffer, 0x00, size);
}

/**
 * Clear the current credential.
 */
void crypto_clear_credential(void) {
  Byte i;

  // Put the address of the credential on the stack
  __push(credential);

  // Clear the credential in blocks of 255 bytes
  for (i = 0; i < sizeof(Credential) / 255; i++) {

    // Store a block of 255 zero bytes at the given address
    __code(PUSHZ, 255);
    __code(STOREI, 255);

    // Update the address for the next block (add 255)
    __code(PUSHW, 255);
    __code(ADDN, 2);
    __code(POPN, 2);
  }

  // Store the remaining block of zero bytes at the given address
  __code(PUSHZ, sizeof(Credential) % 255);
  __code(STOREI, sizeof(Credential) % 255);

  // Remove the address from the stack
  __code(POPN, 2);

  // Clear the pointer to the credential
  credential = NULL;
}

/**
 * Clear the current session.
 */
void crypto_clear_session(void) {
  CLEARN(255, session.base);
  CLEARN(sizeof(SessionData) % 255, session.base + 255);
  CLEARN(255, public.base);
  CLEARN(255, public.base + 255);
  CLEARN(255, public.base + 255*2);
  CLEARN(sizeof(PublicData) % 255, public.base + 255*3);
}
