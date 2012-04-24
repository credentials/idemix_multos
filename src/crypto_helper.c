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
#include "funcs_helper.h"

#ifdef TEST
#include "defs_test.h"
#endif // TEST

/********************************************************************/
/* Cryptographic helper functions                                   */
/********************************************************************/

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
    case LENGTH_VPRIME_:
      memcpy(buffer, TEST_vPrime_, SIZE_VPRIME_);
      break;
    case LENGTH_M_:
      memcpy(buffer, TEST_m_, SIZE_M_);
      break;
    case LENGTH_STATZK:
      memcpy(buffer, TEST_n_2, SIZE_STATZK);
      break;
    default:
      break;
  }
#endif // TEST
}

/**
 * Compute the response value vPrimeHat = vTilde + c*vPrime
 * 
 * Requires buffer of size SIZE_VPRIME_ + SIZE_VPRIME and vPrimeTilde 
 * to be stored in vPrimeHat.
 * 
 * @param c the challenge
 * @param vPrime the value to be hidden
 */
void crypto_compute_vPrimeHat(ByteArray c, ByteArray vPrime) {
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_VPRIME_ - SIZE_VPRIME, buffer);
  
  // Multiply c with least significant half of vPrime
  MULN(SIZE_VPRIME/2, buffer + SIZE_VPRIME_ - SIZE_VPRIME, c, 
    vPrime + (SIZE_VPRIME/2));
  
  // Multiply c with most significant half of vPrime
  MULN(SIZE_VPRIME/2, buffer + SIZE_VPRIME_, c, vPrime);
  
  // Combine the two multiplications into a single result
  ASSIGN_ADDN(SIZE_VPRIME/2 + SIZE_VPRIME_ - SIZE_VPRIME, 
    buffer, buffer + SIZE_VPRIME + SIZE_VPRIME/2);
  
  // Add vPrimeTilde and store the result in vPrimeHat
  ASSIGN_ADDN(SIZE_VPRIME_, vPrimeHat, buffer);
}

/**
 * Compute the response value vHat = vTilde + c*v
 * 
 * Requires buffer of size SIZE_V_ + SIZE_V and vTilde to be stored in 
 * vHat.
 * 
 * @param c the challenge
 * @param v the value to be hidden
 */
void crypto_compute_vHat(ByteArray c, ByteArray v) {
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_V_ - SIZE_V, buffer);
  
  // Multiply c with least significant half of v
  MULN(SIZE_V/2, buffer + SIZE_V_ - SIZE_V, c, v + (SIZE_V/2));
  
  // Multiply c with most significant half of v
  MULN(SIZE_V/2, buffer + SIZE_V_, c, v);
  
  // Combine the two multiplications into a single result
  ASSIGN_ADDN(SIZE_V/2 + SIZE_V_ - SIZE_V, buffer, 
    buffer + SIZE_V + SIZE_V/2);
  
  // Add vTilde and store the result in vHat
  ASSIGN_ADDN(SIZE_V_, vHat, buffer);
}

/**
 * Compute the response value mHat = mTilde + c*m
 * 
 * Requires buffer of size 2*SIZE_M_ + SIZE_M and mTilde[index] to be 
 * stored in mHat[index].
 * 
 * @param c the challenge
 * @param index of the message to be hidden
 */
void crypto_compute_mHat(ByteArray c, int index) {
  // Multiply c with m
  MULN(SIZE_M, buffer, c, messages[index]);
  
  // Add mTilde to the result of the multiplication
  ADDN(SIZE_M_, buffer + 2*SIZE_M, mHat[index], buffer + 2*SIZE_M - SIZE_M_);
  
  // Store the result in mHat
  COPYN(SIZE_M_, mHat[index], buffer + 2*SIZE_M);
}

/**
 * Compute the response value eHat = eTilde + c*ePrime
 * 
 * Requires buffer of size 2*SIZE_EPRIME and eTilde to be stored in eHat.
 * 
 * @param c the challenge
 * @param e the value to be hidden
 */
void crypto_compute_eHat(ByteArray c, ByteArray ePrime) {
  // Multiply c with ePrime (SIZE_H since SIZE_H > SIZE_E)
  MULN(SIZE_H, buffer + SIZE_E_ - 2*SIZE_H, c, ePrime);
  
  // Add eTilde and store the result in eHat
  ASSIGN_ADDN(SIZE_E_, eHat, buffer);
}

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
  ModularExponentiation(SIZE_S_EXPONENT + 1, SIZE_N, 
    buffer, issuerKey.n, issuerKey.S, issuerKey.S_);
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
void crypto_compute_SpecialModularExponentiation(int size, 
    ByteArray exponent, ByteArray result) {
  
  if (size > SIZE_N) {
    // Compute result = S^(exponent_bottom) * S_^(exponent_top)
    ModularExponentiation(SIZE_S_EXPONENT, SIZE_N, 
      exponent + size - SIZE_S_EXPONENT, issuerKey.n, issuerKey.S, result);
    ModularExponentiation(size - SIZE_S_EXPONENT, SIZE_N, 
      exponent, issuerKey.n, issuerKey.S_, buffer);
    ModularMultiplication(SIZE_N, result, buffer, issuerKey.n);
  } else {
    // Compute result = S^exponent
    ModularExponentiation(size, SIZE_N, 
      exponent, issuerKey.n, issuerKey.S, result);
  }
}
