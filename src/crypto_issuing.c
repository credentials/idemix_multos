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
#include <multoscrypto.h>
#include <string.h> // for memcmp()

#include "defs_apdu.h"
#include "defs_externals.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"

#define buffer apdu.temp.data
#define values apdu.temp.list

/********************************************************************/
/* Issuing functions                                                */
/********************************************************************/

/**
 * Construct a commitment (round 1)
 * 
 * @param issuerKey (S, R, n)
 * @param proof (nonce, context)
 * @param masterSecret
 * @param number for U
 * @param number for UTilde
 * @param vPrime in signature.v + SIZE_V - SIZE_VPRIME
 * @param vPrimeTilde in vHat
 * @param vPrimeHat in vHat
 * @param mTilde[0] in mHat[0]
 * @param s_A in mHat[0]
 * @param nonce
 * @param buffer for hash of SIZE_BUFFER_C1
 * @param (buffer for SpecialModularExponentiation of SIZE_N)
 */
#define vPrime (credential->signature.v + SIZE_V - SIZE_VPRIME)
#define U numa
#define UTilde numb
void constructCommitment(void) {
  
  // Generate random vPrime
  crypto_generate_random(vPrime, LENGTH_VPRIME);
  debugValue("vPrime", vPrime, SIZE_VPRIME);

  // Compute U = S^vPrime * R[0]^m[0] mod n
  crypto_compute_SpecialModularExponentiation(SIZE_VPRIME, vPrime, U);
  debugValue("U = S^vPrime mod n", U, SIZE_N);
  ModularExponentiation(SIZE_M, SIZE_N, 
    masterSecret, credential->issuerKey.n, credential->issuerKey.R[0], buffer);
  debugValue("buffer = R[0]^m[0] mod n", buffer, SIZE_N);
  ModularMultiplication(SIZE_N, U, buffer, credential->issuerKey.n);
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
    mHat[0], credential->issuerKey.n, credential->issuerKey.R[0], buffer);
  debugValue("buffer = R[0]^mTilde[0] mod n", buffer, SIZE_N);
  ModularMultiplication(SIZE_N, UTilde, buffer, credential->issuerKey.n);
  debugValue("UTilde = UTilde * buffer mod n", UTilde, SIZE_N);

  // - Compute challenge c = H(context | U | UTilde | nonce)
  values[0].data = credential->proof.context;
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
  crypto_generate_random(credential->proof.nonce, LENGTH_STATZK);
  debugValue("nonce", credential->proof.nonce, SIZE_STATZK);
}
#undef vPrime
#undef U
#undef UTilde

/**
 * Construct the signature (round 3, part 1)
 * 
 *   A, e, v = v' + v''
 * 
 * @param vPrime in signature.v
 * @param vPrimePrime in buffer
 * @param signature (v)
 */
void constructSignature(void) {
  
  // Clear v, to prevent garbage messing up the computation
  memset(credential->signature.v, 0x00, SIZE_V - SIZE_VPRIME);
  
  // Compute v = v' + v'' using add with carry
  ASSIGN_ADDN(SIZE_V/3, buffer + 2*SIZE_V/3, 
    credential->signature.v + 2*SIZE_V/3);
  CFlag(buffer + SIZE_V);
  if (buffer[SIZE_V] != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(2*SIZE_V/3, buffer);
  }
  ASSIGN_ADDN(SIZE_V/3, buffer + SIZE_V/3, 
    credential->signature.v + SIZE_V/3);
  CFlag(buffer + SIZE_V);
  if (buffer[SIZE_V] != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_V/3, buffer);
  }
  ASSIGN_ADDN(SIZE_V/3, buffer, credential->signature.v);
  COPYN(SIZE_V, credential->signature.v, buffer);
  debugValue("v = vPrime + vPrimePrime", credential->signature.v, SIZE_V);
}

/**
 * (OPTIONAL) Verify the signature (round 3, part 2)
 * 
 *   Z =?= A^e * S^v * R where R = R[i]^m[i] forall i
 * 
 * @param signature (A, e, v)
 * @param issuerKey (Z, S, R, n)
 * @param attribute
 * @param buffer for SpecialModularExponentiation of SIZE_N 
 * @param (buffer for computations of SIZE_N)
 * @param buffer for ZPrime of SIZE_N
 * @param buffer for Ri of SIZE_N
 */
#define ZPrime (buffer + SIZE_N)
#define Ri (buffer + 2*SIZE_N)
void verifySignature(void) {
  int i;
  
  // Compute Ri = R[i]^m[i] mod n forall i
  ModularExponentiation(SIZE_M, SIZE_N, masterSecret, 
    credential->issuerKey.n, credential->issuerKey.R[0], Ri);
  debugValue("Ri = R[0]^ms mod n", Ri, SIZE_N);
  for (i = 1; i <= credential->size; i++) {
    ModularExponentiation(SIZE_M, SIZE_N, credential->attribute[i - 1], 
      credential->issuerKey.n, credential->issuerKey.R[i], buffer);
    debugValue("buffer = R[i]^m[i] mod n", buffer, SIZE_N);    
    ModularMultiplication(SIZE_N, Ri, buffer, credential->issuerKey.n);
    debugValue("Ri = Ri * buffer mod n", Ri, SIZE_N);
  }
  
  // Compute Z' = A^e * S^v * Ri mod n
  crypto_compute_SpecialModularExponentiation(SIZE_V, credential->signature.v, ZPrime);
  debugValue("Z' = S^v mod n", ZPrime, SIZE_N);    
  ModularMultiplication(SIZE_N, ZPrime, Ri, credential->issuerKey.n);
  debugValue("Z' = Z' * Ri mod n", ZPrime, SIZE_N);
  ModularExponentiation(SIZE_E, SIZE_N, credential->signature.e, 
    credential->issuerKey.n, credential->signature.A, Ri);
  debugValue("Ri = A^e mod n", Ri, SIZE_N);
  ModularMultiplication(SIZE_N, ZPrime, Ri, credential->issuerKey.n);
  debugValue("Z' = Z' * R mod n", ZPrime, SIZE_N);
  
  // - Verify Z =?= Z'
  if (memcmp(credential->issuerKey.Z, ZPrime, SIZE_N) != 0) {
    // TODO: clear already stored things?
    debugError("verifySignature(): verification of signature failed");
    ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
  }
}
#undef ZPrime
#undef R

/**
 * (OPTIONAL) Verify the proof (round 3, part 3)
 * 
 *   c =?= H(context, A^e, A, nonce, A^(c + s_e * e))
 * 
 * @param signature (A, e)
 * @param issuerKey (n)
 * @param proof (nonce, context, challenge, response)
 * @param number for Q (cannot be in buffer)
 * @param buffer for hash of SIZE_BUFFER_C2
 * @param (buffer for computations of SIZE_N)
 * @param (buffer for AHat of SIZE_N)
 */
#define AHat (buffer + SIZE_N)
#define Q numa
#define s_e credential->proof.response
void verifyProof(void) {

  // Compute Q = A^e mod n
  ModularExponentiation(SIZE_E, SIZE_N, credential->signature.e, 
    credential->issuerKey.n, credential->signature.A, Q);
  debugValue("Q = A^e mod n", Q, SIZE_N);

  // Compute AHat = A^(c + s_e * e) = Q^s_e * A^c mod n
  ModularExponentiation(SIZE_N, SIZE_N, s_e, credential->issuerKey.n, Q, buffer);
  debugValue("buffer = Q^s_e mod n", buffer, SIZE_N);
  ModularExponentiation(SIZE_H, SIZE_N, credential->proof.challenge, 
    credential->issuerKey.n, credential->signature.A, AHat);
  debugValue("AHat = A^c mod n", AHat, SIZE_N);
  ModularMultiplication(SIZE_N, AHat, buffer, credential->issuerKey.n);
  debugValue("AHat = AHat * buffer", AHat, SIZE_N);
  
  // Compute challenge c' = H(context | Q | A | nonce | AHat)
  values[0].data = credential->proof.context;
  values[0].size = SIZE_H;
  debugValue("context", credential->proof.context, SIZE_H);
  values[1].data = Q;
  values[1].size = SIZE_N;
  debugValue("Q", Q, SIZE_N);
  values[2].data = credential->signature.A;
  values[2].size = SIZE_N;
  debugValue("A", credential->signature.A, SIZE_N);
  values[3].data = credential->proof.nonce;
  values[3].size = SIZE_STATZK;
  debugValue("nonce", credential->proof.nonce, SIZE_STATZK);
  values[4].data = AHat;
  values[4].size = SIZE_N;
  debugValue("AHat", AHat, SIZE_N);
  crypto_compute_hash(values, 5, challenge.c, buffer, SIZE_BUFFER_C2);
  debugValue("c'", challenge.c, SIZE_H);

  // Verify c =?= c'
  if (memcmp(credential->proof.challenge, challenge.c, SIZE_H) != 0) {
    // TODO: clear already stored things?
    debugError("verifyProof(): verification of P2 failed");
    ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
  }
}
#undef AHat
#undef Q
#undef s_e
