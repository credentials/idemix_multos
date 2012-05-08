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
#include <multoscrypto.h>

#include "defs_apdu.h"
#include "defs_externals.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"

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
  D = 0;
  for (i = 0; i < length; i++) {
    if (list[i] == 0 || list[i] > MAX_ATTR) {
      // FAIL, TODO: clear already stored things
      debugError("selectAttributes(): invalid attribute index");
      ReturnSW(ISO7816_SW_WRONG_DATA);
    }
    D |= 1 << list[i];
  }
  debugInteger("Disclosure selection", D);
}

/**
 * Construct a proof
 */
#define ZTilde (buffer + SIZE_N)
#define APrime (buffer + 2*SIZE_N)
#define ePrime (signature.e + SIZE_E - SIZE_EPRIME)
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
  crypto_compute_SpecialModularExponentiation(SIZE_R_A, r_A, APrime);
  debugValue("A' = S^r_A mod n", APrime, SIZE_N);
  ModularMultiplication(SIZE_N, APrime, signature.A, issuerKey.n);
  debugValue("A' = A' * A mod n", APrime, SIZE_N);
  COPYN(SIZE_N, signature_.A, APrime);
  
  // Generate random values for m~[i], e~, v~ and r_A
  for (i = 0; i <= attributes; i++) {
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
  crypto_compute_SpecialModularExponentiation(SIZE_V_, vHat, ZTilde);
  debugValue("ZTilde = S^v_", ZTilde, SIZE_N);
  ModularExponentiation(SIZE_E_, SIZE_N, eHat, issuerKey.n, APrime, buffer);
  debugValue("buffer = A'^eTilde", buffer, SIZE_N);
  ModularMultiplication(SIZE_N, ZTilde, buffer, issuerKey.n);
  debugValue("ZTilde = ZTilde * buffer", ZTilde, SIZE_N);
  for (i = 0; i <= attributes; i++) {
    if (disclosed(i) == 0) {
      ModularExponentiation(SIZE_M_, SIZE_N, mHat[i], issuerKey.n, issuerKey.R[i], buffer);
      debugValue("R_i^m_i", buffer, SIZE_N);
      ModularMultiplication(SIZE_N, ZTilde, buffer, issuerKey.n);
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
  for (i = 0; i < SIZE_L; i++) {
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
