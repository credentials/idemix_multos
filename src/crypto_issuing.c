/**
 * idemix_issuing.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, July 2011.
 */
 
#include "crypto_issuing.h"

#include <ISO7816.h>
#include <multosarith.h>
#include <multosccr.h>
#include <multoscomms.h>
#include <multoscrypto.h>
#include <string.h> // for memcmp()

#include "defs_externals.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"

#define buffer apdu.temp.data
#define values apdu.temp.list

#define vPrime signature.v + SIZE_V - SIZE_VPRIME
#define U Q
#define UTilde R
#define ZPrime s_e
#define AHat R

/********************************************************************/
/* Issuing functions                                                */
/********************************************************************/

void constructCommitment(void) {
  
  // Generate random vPrime
  crypto_generate_random(vPrime, LENGTH_VPRIME);
  debugValue("vPrime", vPrime, SIZE_VPRIME);

  // Compute U = S^vPrime * R[0]^m[0] mod n
  crypto_compute_SpecialModularExponentiation(SIZE_VPRIME, vPrime, U);
  debugValue("U = S^vPrime mod n", U, SIZE_N);
  ModularExponentiation(SIZE_M, SIZE_N, 
    messages[0], issuerKey.n, issuerKey.R[0], buffer);
  debugValue("buffer = R[0]^m[0] mod n", buffer, SIZE_N);
  ModularMultiplication(SIZE_N, U, buffer, issuerKey.n);
  debugValue("U = U * buffer mod n", U, SIZE_N);
  
  // Compute P1:
  // - Generate random vPrimeTilde, mTilde[0]
  crypto_generate_random(vHat, LENGTH_VPRIME_);
  debugValue("vPrimeTilde", vHat, SIZE_VPRIME_);
  crypto_generate_random(mHat[0], LENGTH_S_A);
  debugValue("mTilde[0]", mHat[0], SIZE_S_A);

  // - Compute UTilde = S^vPrimeTilde * R[0]^mTilde[0] mod n
  crypto_compute_SpecialModularExponentiation(SIZE_VPRIME_, vHat, UTilde);
  debugValue("UTilde = S^vPrimeTilde mod n", UTilde, SIZE_N);
  ModularExponentiation(SIZE_S_A, SIZE_N, 
    mHat[0], issuerKey.n, issuerKey.R[0], buffer);
  debugValue("buffer = R[0]^mTilde[0] mod n", buffer, SIZE_N);
  ModularMultiplication(SIZE_N, UTilde, buffer, issuerKey.n);
  debugValue("UTilde = UTilde * buffer mod n", UTilde, SIZE_N);

  // - Compute challenge c = H(context | U | UTilde | nonce)
  values[0].data = context;
  values[0].size = SIZE_H;
  values[1].data = U;
  values[1].size = SIZE_N;      
  values[2].data = UTilde;
  values[2].size = SIZE_N;
  values[3].data = nonce;
  values[3].size = SIZE_STATZK;
  crypto_compute_hash(values, 4, challenge.c, buffer, SIZE_BUFFER_C1);
  debugValue("c", challenge.c, SIZE_H);

  // - Compute response vPrimeHat = vPrimeTilde + c * vPrime
  crypto_compute_vPrimeHat();
  debugValue("vPrimeHat", vHat, SIZE_VPRIME_);

  // - Compute response s_A = mTilde[0] + c * m[0]
  crypto_compute_s_A();
  debugValue("s_A", mHat[0], SIZE_S_A);
  
  // Generate random n_2
  crypto_generate_random(nonce, LENGTH_STATZK);
  debugValue("nonce", nonce, SIZE_STATZK);
}

void constructSignature(void) {
  // Clear signature.v, to prevent garbage messing up the computation
  CLEARN(SIZE_V - SIZE_VPRIME, signature.v);
  
  // Compute v = v' + v'' using add with carry
  debugValue("vPrime", signature.v, SIZE_V);
  debugValue("vPrimePrime", buffer, SIZE_V);
  ASSIGN_ADDN(SIZE_V - SIZE_V_ADDITION, signature.v + SIZE_V_ADDITION, 
    buffer + SIZE_V_ADDITION);
  CFlag(buffer + SIZE_V);
  if (buffer[SIZE_V] != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_V_ADDITION, signature.v);
  }
  ASSIGN_ADDN(SIZE_V_ADDITION, signature.v, buffer);
  debugValue("vPrime + vPrimePrime", signature.v, SIZE_V);
}

void verifySignature(void) {
  int i;
  
  // Verification of signature (A, e, v)
  // - Compute R = R_i^(m_i) mod n for i=1..l-1
  ModularExponentiation(SIZE_M, SIZE_N, 
    messages[0], issuerKey.n, issuerKey.R[0], R); // R = R_1^m_1
  debugValue("R", R, SIZE_N);
  for (i = 1; i <= attributes; i++) {
    ModularExponentiation(SIZE_M, SIZE_N, 
      messages[i], issuerKey.n, issuerKey.R[i], buffer); // buffer = R_i^m_i
    debugValue("Ri^mi", buffer, SIZE_N);
    ModularMultiplication(SIZE_N, 
      R, buffer, issuerKey.n); // R = R * buffer
    debugValue("R", R, SIZE_N);
  }
  
  // - Compute Q = A^e mod n
  ModularExponentiation(SIZE_E, SIZE_N, 
    signature.e, issuerKey.n, signature.A, Q); // Q = A^e
  debugValue("Q", Q, SIZE_N);
  
  // - Compute Z' = Q * S^v * R
  crypto_compute_SpecialModularExponentiation(SIZE_V,
    signature.v, ZPrime); // ZPrime = S^v
  debugValue("S^v", ZPrime, SIZE_N);    
  ModularMultiplication(SIZE_N, ZPrime, R, issuerKey.n); // U_ = U_ * R
  debugValue("S^v * R", ZPrime, SIZE_N);
  ModularMultiplication(SIZE_N, ZPrime, Q, issuerKey.n); // U_ = U_ * Q
  debugValue("S^v * R * Q", ZPrime, SIZE_N);
  
  // - Verify Z =?= Z'
  debugValue("Z", issuerKey.Z, SIZE_N);    
  debugValue("ZPrime", ZPrime, SIZE_N);    
  if (memcmp(issuerKey.Z, ZPrime, SIZE_N) != 0) {
    // FAIL, TODO: clear already stored things 
    debugError("verifySignature(): verification of signature failed");
    ExitSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
  }
}

/**
 * (OPTIONAL) Verify the proof (round 3, part 3)
 */
void verifyProof(void) {

  // Compute AHat = A^(c + s_e e) mod n
  ModularExponentiation(SIZE_N, SIZE_N, s_e, issuerKey.n, Q, buffer);
  debugValue("buffer = Q^s_e mod n", buffer, SIZE_N);
  ModularExponentiation(SIZE_H, SIZE_N, challenge.c, issuerKey.n, signature.A, AHat);
  debugValue("AHat = A^c mod n", AHat, SIZE_N);
  ModularMultiplication(SIZE_N, AHat, buffer, issuerKey.n);
  debugValue("AHat = AHat * buffer", AHat, SIZE_N);
  
  // Compute challenge c' = H(context | Q | A | n_2 | AHat)
  values[0].data = context;
  values[0].size = SIZE_H;
  debugValue("context", context, SIZE_H);
  values[1].data = Q;
  values[1].size = SIZE_N;
  debugValue("Q", Q, SIZE_N);
  values[2].data = signature.A;
  values[2].size = SIZE_N;
  debugValue("A", signature.A, SIZE_N);
  values[3].data = nonce;
  values[3].size = SIZE_STATZK;
  debugValue("n2", nonce, SIZE_STATZK);
  values[4].data = AHat;
  values[4].size = SIZE_N;
  debugValue("A_", AHat, SIZE_N);
  crypto_compute_hash(values, 5, challenge.prefix_vPrime, buffer, SIZE_BUFFER_C2);
  debugValue("c_", challenge.prefix_vPrime, SIZE_H);

  // Verify c =?= c'
  debugValue("c ", challenge.c, SIZE_H);
  debugValue("c_", challenge.prefix_vPrime, SIZE_H);
  if (memcmp(challenge.c, challenge.prefix_vPrime, SIZE_H) != 0) {
    // FAIL, TODO: clear already stored things 
    debugError("verifyProof(): verification of P2 failed");
    ExitSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
  }
}
