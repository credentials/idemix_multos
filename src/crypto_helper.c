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
#include <multosccr.h>
#include <multoscrypto.h>
#include <string.h>

#include "defs_externals.h"
#include "funcs_debug.h"
#include "funcs_helper.h"

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
  ModularExponentiation(SIZE_S_EXPONENT + 1, SIZE_N, buffer, 
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
void crypto_compute_SpecialModularExponentiation(int size, 
    ByteArray exponent, ByteArray result) {
  
  if (size > SIZE_N) {
    // Compute result = S^(exponent_bottom) * S_^(exponent_top)
    ModularExponentiation(SIZE_S_EXPONENT, SIZE_N, 
      exponent + size - SIZE_S_EXPONENT, credential->issuerKey.n, credential->issuerKey.S, result);
    ModularExponentiation(size - SIZE_S_EXPONENT, SIZE_N, 
      exponent, credential->issuerKey.n, credential->issuerKey.S_, buffer);
    ModularMultiplication(SIZE_N, result, buffer, credential->issuerKey.n);
  } else {
    // Compute result = S^exponent
    ModularExponentiation(size, SIZE_N, 
      exponent, credential->issuerKey.n, credential->issuerKey.S, result);
  }
}

//////////////////////////////////////////////////////////////////////
// Issuing functions                                                //
//////////////////////////////////////////////////////////////////////

/**
 * Compute the response value vPrimeHat = vPrimeTilde + c*vPrime
 * 
 * @param buffer of size SIZE_VPRIME_ + SIZE_VPRIME
 * @param c in challenge.prefix_vPrimeHat
 * @param vPrime signature.v + SIZE_V - SIZE_VPRIME
 * @param vPrimeTilde in vHat
 * @return vPrimeHat in vHat
 */
void crypto_compute_vPrimeHat(void) {  
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_VPRIME_ - SIZE_VPRIME, buffer);
  
  // Multiply c with least significant part of vPrime
  MULN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_ - 2*SIZE_VPRIME/3, 
    challenge.prefix_vPrimeHat, credential->signature.v + SIZE_V - SIZE_VPRIME/3);
  
  // Multiply c with middle significant part of vPrime
  MULN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_, challenge.prefix_vPrimeHat, 
    credential->signature.v + SIZE_V - 2*SIZE_VPRIME/3);
  
  // Combine the two multiplications into a partial result
  /*  ASSIGN_ADDN(2*SIZE_VPRIME/3, buffer + SIZE_VPRIME_ - SIZE_VPRIME, buffer + SIZE_VPRIME_); /* fails somehow :-S what am I doing wrong? */
  ASSIGN_ADDN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_ - 2*SIZE_VPRIME/3, buffer + SIZE_VPRIME_ + SIZE_VPRIME/3);
  COPYN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_ - SIZE_VPRIME, buffer + SIZE_VPRIME_);

  // Multiply c with most significant part of vPrime
  MULN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_, challenge.prefix_vPrimeHat, 
    credential->signature.v + SIZE_V - SIZE_VPRIME);
  
  // Combine the two multiplications into a single result
/*  ASSIGN_ADDN(SIZE_VPRIME_ - 2*SIZE_VPRIME/3, buffer, buffer + 4*SIZE_VPRIME/3); /* fails somehow :-S what am I doing wrong? */
  ASSIGN_ADDN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_ - SIZE_VPRIME, buffer + SIZE_VPRIME_ + SIZE_VPRIME/3);
  COPYN(SIZE_VPRIME_ - SIZE_VPRIME, buffer, buffer + 4*SIZE_VPRIME/3);
  
  // Add (with carry) vPrimeTilde and store the result in vPrimeHat
  ASSIGN_ADDN(SIZE_VPRIME_/2, vHat + SIZE_VPRIME_/2, buffer + SIZE_VPRIME_/2);
  CFlag(buffer + SIZE_VPRIME_);
  if (buffer[SIZE_VPRIME_] != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_VPRIME_/2, vHat);
  }
  ASSIGN_ADDN(SIZE_VPRIME_/2, vHat, buffer);
}

/**
 * Compute the response value s_A = mTilde[0] + c*m[0]
 * 
 * @param buffer of size 2*SIZE_M_ + SIZE_M
 * @param c in challenge.prefix_m
 * @param m[0] in messages[0]
 * @param mTilde[0] in mHat[0]
 * @return s_A in mHat[0]
 */
void crypto_compute_s_A(void) {
  // Multiply c with m
  MULN(SIZE_M, buffer, challenge.prefix_mHat, masterSecret);
  
  // Add mTilde to the result of the multiplication
  ADDN(SIZE_S_A, buffer + 2*SIZE_M, mHat[0], buffer + 2*SIZE_M - SIZE_S_A);
  
  // Store the result in mHat
  COPYN(SIZE_S_A, mHat[0], buffer + 2*SIZE_M);
}

//////////////////////////////////////////////////////////////////////
// Proving functions                                                //
//////////////////////////////////////////////////////////////////////

/**
 * Compute the value vPrime = v - e*r_A
 *
 * @param buffer of size SIZE_V + 2*SIZE_R_A
 * @param e in signature.e
 * @param r_A in vHat
 * @param v in signature.v
 * @return vPrime in signature_.v
 */
#define r_A vHat
#define e_prefix_rA (buffer + SIZE_V + SIZE_R_A)
#define vPrime (buffer + SIZE_V)
void crypto_compute_vPrime(void) {
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_V - SIZE_R_A, buffer);

  // Prepare e for computations
  CLEARN(SIZE_R_A/2 - SIZE_E, e_prefix_rA);
  COPYN(SIZE_E, e_prefix_rA + SIZE_R_A/2 - SIZE_E, credential->signature.e);

  // Multiply e with least significant half of r_A
  MULN(SIZE_R_A/2, buffer + SIZE_V - SIZE_R_A, e_prefix_rA, r_A + SIZE_R_A/2);

  // Multiply e with most significant half of r_A
  MULN(SIZE_R_A/2, buffer + SIZE_V, e_prefix_rA, r_A);

  // Combine the two multiplications into a single result
  ASSIGN_ADDN(SIZE_V - SIZE_R_A/2, buffer, buffer + SIZE_R_A + SIZE_R_A/2);

  // Subtract (with carry) from v and store the result in v'
  SUBN(SIZE_V/3, vPrime + 2*SIZE_V/3, credential->signature.v + 2*SIZE_V/3, buffer + 2*SIZE_V/3);
  CFlag(buffer + 2*SIZE_V);
  if (buffer[2*SIZE_V] != 0x00) {
    debugMessage("Subtraction with carry, subtracting 1 (by increasing the buffer with 1)");
    INCN(SIZE_V/3, buffer + SIZE_V/3);
  }
  SUBN(SIZE_V/3, vPrime + SIZE_V/3, credential->signature.v + SIZE_V/3, buffer + SIZE_V/3);
  CFlag(buffer + 2*SIZE_V);
  if (buffer[2*SIZE_V] != 0x00) {
    debugMessage("Subtraction with carry, subtracting 1 (by increasing the buffer with 1)");
    INCN(SIZE_V/3, buffer);
  }
  SUBN(SIZE_V/3, vPrime, credential->signature.v, buffer);
  COPYN(SIZE_V, signature_.v, vPrime);
}
#undef r_A
#undef e_prefix_rA
#undef vPrime

/**
 * Compute the response value vHat = vTilde + c*vPrime
 * 
 * @param buffer of size SIZE_V_ + 2*SIZE_V/3
 * @param c in challenge.prefix_vHat
 * @param vPrime in signature_.v
 * @param vTilde in vHat
 * @return vHat
 */
void crypto_compute_vHat(void) {
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_V_ - SIZE_V, buffer);
  
  // Multiply c with least significant part of v
  MULN(SIZE_V/3, buffer + SIZE_V_ - 2*SIZE_V/3, challenge.prefix_vHat, 
    signature_.v + 2*SIZE_V/3);
  
  // Multiply c with middle significant part of v
  MULN(SIZE_V/3, buffer + SIZE_V_, challenge.prefix_vHat, 
    signature_.v + SIZE_V/3);
  
  // Combine the two multiplications into a partial result
/*  ASSIGN_ADDN(2*SIZE_V/3, buffer + SIZE_V_ - SIZE_V, buffer + SIZE_V_); /* works as expected */
  ASSIGN_ADDN(SIZE_V/3, buffer + SIZE_V_ - 2*SIZE_V/3, buffer + SIZE_V_ + SIZE_V/3);
  COPYN(SIZE_V/3, buffer + SIZE_V_ - SIZE_V, buffer + SIZE_V_);
    
  // Multiply c with most significant part of v
  MULN(SIZE_V/3, buffer + SIZE_V_, challenge.prefix_vHat, signature_.v);
  
  // Combine the two multiplications into a single result
/*  ASSIGN_ADDN(SIZE_V_ - 2*SIZE_V/3, buffer, buffer + 4*SIZE_V/3); /* fails somehow :-S what am I doing wrong? */
  ASSIGN_ADDN(SIZE_V/3, buffer + SIZE_V_ - SIZE_V, buffer + SIZE_V_ + SIZE_V/3);
  COPYN(SIZE_V_ - SIZE_V, buffer, buffer + 4*SIZE_V/3);
  
  // Add (with carry) vTilde and store the result in vHat
  ASSIGN_ADDN(SIZE_V_/3, vHat + 2*SIZE_V_/3, buffer + 2*SIZE_V_/3);
  CFlag(buffer + SIZE_V_);
  if (buffer[SIZE_V_] != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_V_/3, vHat + SIZE_V_/3);
  }
  ASSIGN_ADDN(SIZE_V_/3, vHat + SIZE_V_/3, buffer + SIZE_V_/3);
  CFlag(buffer + SIZE_V_);
  if (buffer[SIZE_V_] != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_V_/3, vHat);
  }
  ASSIGN_ADDN(SIZE_V_/3, vHat, buffer);
}

/**
 * Compute the response value mHat[i] = mTilde[i] + c*m[i]
 * 
 * @param buffer of size 2*SIZE_M_ + SIZE_M
 * @param c the challenge
 * @param m[i] in messages[i]
 * @param mTilde[index] in mHat[index]
 * @return mHat[i]
 */
void crypto_compute_mHat(int i) {
  // Multiply c with m
  MULN(SIZE_M, buffer, challenge.prefix_mHat, credential->messages[i]);
  
  // Add mTilde to the result of the multiplication
  ADDN(SIZE_M_, buffer + 2*SIZE_M, mHat[i], buffer + 2*SIZE_M - SIZE_M_);
  
  // Store the result in mHat
  COPYN(SIZE_M_, mHat[i], buffer + 2*SIZE_M);
}

/**
 * Compute the response value eHat = eTilde + c*ePrime
 * 
 * Requires buffer of size 2*SIZE_EPRIME and eTilde to be stored in eHat.
 * 
 * @param 
 * @param c in challenge.c
 * @param ePrime in signature.e + SIZE_E - SIZE_H
 * @param e the value to be hidden
 */
#define ePrime (credential->signature.e + SIZE_E - SIZE_H)
void crypto_compute_eHat(void) {
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_E_ - 2*SIZE_H, buffer);

  // Multiply c with ePrime (SIZE_H since SIZE_H > SIZE_EPRIME)
  MULN(SIZE_H, buffer + SIZE_E_ - 2*SIZE_H, challenge.c, ePrime);
  
  // Add eTilde and store the result in eHat
  ASSIGN_ADDN(SIZE_E_, eHat, buffer);
}
#undef ePrime

//////////////////////////////////////////////////////////////////////
// Secure Messaging functions                                       //
//////////////////////////////////////////////////////////////////////

uint pad(ByteArray in, int length) {
  in[length++] = 0x80;
  while (length % 8 != 0) {
    in[length++] = 0x00;
  }
  return length;
}

uint unpad(ByteArray in, int length) {
  while (length > 0 && in[--length] == 0x00);
  if (in[length] != 0x80) {
    debugError("Invalid padding");
    return INVALID_PADDING;
  }
  return length;
}
