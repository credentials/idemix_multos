/**
 * crypto_proving.c
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, April 2012.
 */
 
#include "crypto_proving.h"

#include <ISO7816.h>
#include <multosarith.h>
#include <multosccr.h>
#include <multoscrypto.h>

#include "defs_apdu.h"
#include "defs_externals.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"
#include "crypto_multos.h"

#define buffer apdu.temp.data
#define values apdu.temp.list

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

/**
 * Select the attributes to be disclosed
 */
void selectAttributes(ByteArray list, int length) {
  int i = 0;

  debugValue("Disclosure list", list, length);
  disclose = 0x00;
  for (i = 0; i < length; i++) {
    if (list[i] == 0 || list[i] > MAX_ATTR) {
      // FAIL, TODO: clear already stored things
      debugError("selectAttributes(): invalid attribute index");
      ReturnSW(ISO7816_SW_WRONG_DATA);
    }
    disclose |= 1 << list[i];
  }
  debugInteger("Disclosure selection", disclose);
}

/**
 * Construct a proof
 */
#define ZTilde (buffer + SIZE_N)
#define APrime (buffer + 2*SIZE_N)
#define ePrime (credential->signature.e + SIZE_E - SIZE_EPRIME)
#define r_A vHat
void constructProof(void) {
  int i;
  
  // Generate random r_A
  // IMPORTANT: Correction to the length of r_A to prevent negative values
  crypto_generate_random(r_A, LENGTH_R_A - 7);
  debugValue("r_A", r_A, SIZE_R_A);
  
  // Compute v' = v - e r_A
  crypto_compute_vPrime();
  debugValue("v' = v - e*r_A", signature_.v, SIZE_V);

  // Compute e' = e - 2^(l_e' - 1) (just ignore the first bit of e)
  debugValue("e' = e - 2^(l_e' - 1)", ePrime, SIZE_EPRIME);
  
  // Compute A' = A S^r_A
  crypto_modexp_special(SIZE_R_A, r_A, APrime);
  debugValue("A' = S^r_A mod n", APrime, SIZE_N);
  crypto_modmul(SIZE_N, APrime, credential->signature.A, credential->issuerKey.n);
  debugValue("A' = A' * A mod n", APrime, SIZE_N);
  COPYN(SIZE_N, signature_.A, APrime);
  
  // Generate random values for m~[i], e~, v~ and r_A
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_generate_random(mHat[i], LENGTH_M_);
    }
  }
  debugValues("m_", (ByteArray) mHat, SIZE_S_A, SIZE_L);
  crypto_generate_random(eHat, LENGTH_E_);
  debugValue("e_", eHat, SIZE_E_);
  crypto_generate_random(vHat, LENGTH_V_);
  debugValue("v_", vHat, SIZE_V_);
  
  // Compute ZTilde = A'^eTilde * S^vTilde * (R[i]^mHat[i] foreach i not in D)
  crypto_modexp_special(SIZE_V_, vHat, ZTilde);
  debugValue("ZTilde = S^v_", ZTilde, SIZE_N);
  crypto_modexp(SIZE_E_, SIZE_N, eHat, credential->issuerKey.n, APrime, buffer);
  debugValue("buffer = A'^eTilde", buffer, SIZE_N);
  crypto_modmul(SIZE_N, ZTilde, buffer, credential->issuerKey.n);
  debugValue("ZTilde = ZTilde * buffer", ZTilde, SIZE_N);
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_modexp(SIZE_M_, SIZE_N, mHat[i], credential->issuerKey.n, credential->issuerKey.R[i], buffer);
      debugValue("R_i^m_i", buffer, SIZE_N);
      crypto_modmul(SIZE_N, ZTilde, buffer, credential->issuerKey.n);
      debugValue("ZTilde = ZTilde * buffer", ZTilde, SIZE_N);
    }
  }
  
  // Compute challenge c = H(context | A' | ZTilde | nonce)
  values[0].data = context;
  values[0].size = SIZE_H;
  values[1].data = signature_.A;
  values[1].size = SIZE_N;      
  values[2].data = ZTilde;
  values[2].size = SIZE_N;
  values[3].data = nonce;
  values[3].size = SIZE_STATZK;
  crypto_compute_hash(values, 4, challenge.c, buffer, SIZE_BUFFER_C2);
  debugValue("c", challenge.c, SIZE_H);
  
  // Compute e^ = e~ + c e'
  crypto_compute_eHat();
  debugValue("eHat", eHat, SIZE_E_);
  
  // Compute v^ = v~ + c v'
  crypto_compute_vHat();
  debugValue("vHat", vHat, SIZE_V_);
  
  // Compute m_i^ = m_i~ + c m_i
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_compute_mHat(i);
    }
  }
  debugValues("mHat", (ByteArray) mHat, SIZE_M_, SIZE_L);
  
  // return eHat, vHat, mHat[i], c, A'
}
#undef ZTilde
#undef APrime
#undef ePrime
#undef r_A

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
 * @param m[i] in attribute[i]
 * @param mTilde[index] in mHat[index]
 * @return mHat[i]
 */
void crypto_compute_mHat(int i) {
  // Multiply c with m
  if (i == 0) {
    MULN(SIZE_M, buffer, challenge.prefix_mHat, masterSecret);
  } else {
    MULN(SIZE_M, buffer, challenge.prefix_mHat, credential->attribute[i - 1]);
  }
  
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
