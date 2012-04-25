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
#include <multoscomms.h>
#include <multoscrypto.h>

#include "defs_externals.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

void selectAttributes(ByteArray list, int length) {
  int i = 0;

  debugValue("Disclosure list", list, length);
  CLEARN(MAX_ATTR, D);
  for (i = 0; i < length; i++) {
    if (list[i] == 0 || list[i] > MAX_ATTR) {
      // FAIL, TODO: clear already stored things
      debugError("selectAttributes(): invalid attribute index");
      ExitSW(ISO7816_SW_WRONG_DATA);
    }
    D[list[i]] = 0x01;
  }
  debugValue("Disclosure selection", D, MAX_ATTR);
}

void constructProof(void) {
  int i;
  
  // Generate randoms m~[i], e~, v~ and r_A
  for (i = 1; i <= attributes; i++) {
    if (D[i] == 0x00) {
      crypto_generate_random(mHat[i] + 1, LENGTH_M_);
    }
  }
  debugValues("m_", (ByteArray) mHat, SIZE_M_, SIZE_L);
  crypto_generate_random(signature_.e, LENGTH_E_);
  debugValue("e_", signature_.e, SIZE_E_);
  crypto_generate_random(signature_.v, LENGTH_V_);
  debugValue("v_", signature_.v, SIZE_V_);
  
  // Compute A' = A S^r_A
  crypto_generate_random(buffer, LENGTH_N + LENGTH_STATZK);
  debugValue("r_A", buffer, SIZE_N + SIZE_STATZK);
  // FIXME: crypto_compute_SpecialModularExponentiation also uses buffer
  crypto_compute_SpecialModularExponentiation(
    SIZE_N + SIZE_STATZK, buffer, signature_.A);
  debugValue("A' = S^r_A mod n", signature_.A, SIZE_N);
  ModularMultiplication(SIZE_N, signature_.A, signature.A, issuerKey.n);
  debugValue("A' = A' * A mod n", signature_.A, SIZE_N);
  
  // Compute v' = v - e r_A
  // FIXME: prepend e with sufficient zeros
  // FIXME: rA and output are both in buffer
  // FIXME: crypto_compute_SpecialModularExponentiation also used buffer 
  MULN(SIZE_N + SIZE_STATZK, buffer, signature.e, buffer);
  debugValue("buffer = e * r_A", buffer, 2*(SIZE_N + SIZE_STATZK));
  SUBN(SIZE_V, signature_.v, signature.v, buffer + 2*(SIZE_N + SIZE_STATZK) - SIZE_V);
  debugValue("v_ = v - buffer", signature_.v, SIZE_V);

  // Compute e' = e - 2^(l_e' - 1)
  CLEARN(SIZE_E, buffer);
  buffer[SIZE_E-SIZE_EPRIME] = 0x80;
  SUBN(SIZE_E, signature_.e, signature.e, buffer);
  debugValue("e_ = e - 2^(l_e' - 1)", signature_.e, SIZE_E);
  
  // Compute Z~ = A'^e_ * S^v_ * (R_i^m_i_ foreach i not in D)
  crypto_compute_SpecialModularExponentiation(
    SIZE_N + SIZE_STATZK, signature_.v, U_);
  debugValue("Z~ = S^v_", U_, SIZE_N);
  ModularExponentiation(SIZE_E, SIZE_N, signature_.e, issuerKey.n, signature_.A, buffer);
  debugValue("buffer = A'^e_", buffer, SIZE_N);
  ModularMultiplication(SIZE_N, U_, buffer, issuerKey.n);
  debugValue("Z~ = Z~ * buffer", U_, SIZE_N);
  for (i = 1; i <= attributes; i++) {
    if (D[i] == 0x00) {
      ModularExponentiation(SIZE_M_, SIZE_N, mHat[i], issuerKey.n, issuerKey.R[i], buffer);
      debugValue("R_i^m_i", buffer, SIZE_N);
      ModularMultiplication(SIZE_N, U_, buffer, issuerKey.n);
      debugValue("Z~ = Z~ * buffer", U_, SIZE_N);
    }
  }
  
  // Compute challenge c = H(context | A' | Z~ | n_1)
  values[0].data = context;
  values[0].size = SIZE_H;
  values[1].data = signature_.A;
  values[1].size = SIZE_N;      
  values[2].data = U_;
  values[2].size = SIZE_N;
  values[3].data = nonce;
  values[3].size = SIZE_STATZK;
  crypto_compute_hash(values, 4, challenge.c, buffer, SIZE_BUFFER_C1);
  debugValue("c", challenge.c, SIZE_H);
  
  // Compute e^ = e~ + c e' //= e~ + c(e - 2^(l_e - 1))
  crypto_compute_eHat(challenge.c, signature_.e);
  debugValue("eHat", eHat, SIZE_E_);
  
  // Compute v^ = v~ + c v' //= v~ + c(v - e r_A)
  crypto_compute_vHat(challenge.prefix_v, signature.v);
  debugValue("vHat", vHat, SIZE_V_);
  
  // Compute m_i^ = m_i~ + c m_i
  for (i = 1; i < SIZE_L; i++) {
    if (D[i] == 0x00) {
      crypto_compute_mHat(challenge.prefix_m, i);
    }
  }
  debugValues("mHat", (ByteArray) mHat, SIZE_M_, SIZE_L);
  
  // return eHat, vHat, mHat[i], c, A'
}
