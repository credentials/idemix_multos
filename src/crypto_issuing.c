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
#include "crypto_multos.h"

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
void constructCommitment(void) {
  
  // Generate random vPrime
  crypto_generate_random(session.issue.vPrime, LENGTH_VPRIME);
  debugValue("vPrime", session.issue.vPrime, SIZE_VPRIME);

  // Compute U = S^vPrime * R[0]^m[0] mod n
  crypto_modexp_special(SIZE_VPRIME, session.issue.vPrime, public.issue.U,
    public.issue.buffer.number[0]);
  debugValue("U = S^vPrime mod n", public.issue.U, SIZE_N);
  crypto_modexp_secure(SIZE_M, SIZE_N, masterSecret, credential->issuerKey.n,
    credential->issuerKey.R[0], public.issue.buffer.number[0]);
  debugValue("buffer = R[0]^m[0] mod n", public.issue.buffer.number[0], SIZE_N);
  crypto_modmul(SIZE_N, public.issue.U, public.issue.buffer.number[0],
    credential->issuerKey.n);
  debugValue("U = U * buffer mod n", public.issue.U, SIZE_N);
  
  // Compute P1:
  // - Generate random vPrimeTilde, mTilde[0]
  crypto_generate_random(public.issue.vPrimeHat, LENGTH_VPRIME_);
  debugValue("vPrimeTilde", public.issue.vPrimeHat, SIZE_VPRIME_);
  crypto_generate_random(session.issue.sA, LENGTH_S_A);
  debugValue("mTilde[0]", session.issue.sA, SIZE_S_A);

  // - Compute UTilde = S^vPrimeTilde * R[0]^mTilde[0] mod n
  crypto_modexp_special(SIZE_VPRIME_, public.issue.vPrimeHat,
    public.issue.buffer.number[1], public.issue.buffer.number[0]);
  debugValue("UTilde = S^vPrimeTilde mod n", public.issue.buffer.number[1], SIZE_N);
  crypto_modexp(SIZE_S_A, SIZE_N, session.issue.sA, credential->issuerKey.n,
    credential->issuerKey.R[0], public.issue.buffer.number[0]);
  debugValue("buffer = R[0]^mTilde[0] mod n", public.issue.buffer.number[0], SIZE_N);
  crypto_modmul(SIZE_N, public.issue.buffer.number[1], 
    public.issue.buffer.number[0], credential->issuerKey.n);
  debugValue("UTilde = UTilde * buffer mod n", public.issue.buffer.number[1], SIZE_N);

  // - Compute challenge c = H(context | U | UTilde | nonce)
  public.issue.list[0].data = credential->proof.context;
  public.issue.list[0].size = SIZE_H;
  public.issue.list[1].data = public.issue.U;
  public.issue.list[1].size = SIZE_N;      
  public.issue.list[2].data = public.issue.buffer.number[1];
  public.issue.list[2].size = SIZE_N;
  public.issue.list[3].data = session.issue.nonce;
  public.issue.list[3].size = SIZE_STATZK;
  crypto_compute_hash(public.issue.list, 4, session.issue.challenge, 
    public.issue.buffer.data, SIZE_BUFFER_C1);
  debugValue("c", session.issue.challenge, SIZE_H);

  // - Compute response vPrimeHat = vPrimeTilde + c * vPrime
  crypto_compute_vPrimeHat();
  debugValue("vPrimeHat", public.issue.vPrimeHat, SIZE_VPRIME_);

  // - Compute response s_A = mTilde[0] + c * m[0]
  crypto_compute_sA();
  debugValue("s_A", session.issue.sA, SIZE_S_A);
  
  // Generate random n_2
  crypto_generate_random(credential->proof.nonce, LENGTH_STATZK);
  debugValue("nonce", credential->proof.nonce, SIZE_STATZK);
}

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
  
  // Compute v = v' + v'' using add with carry
  do {
    __push(BLOCKCAST(1 + SIZE_V/2)(public.apdu.data + SIZE_V/2));
    __push(BLOCKCAST(1 + SIZE_V/2)(session.issue.vPrime + SIZE_V/2));
    __code(ADDN, 1 + SIZE_V/2);
    __code(POPN, 1 + SIZE_V/2);
    __push(credential->signature.v + SIZE_V/2);
    __code(STOREI, 1 + SIZE_V/2);
  } while (0);
  CFlag(&flag);
  if (flag != 0x00) {
    debugMessage("Addition with carry, adding 1");
    __code(INCN, public.apdu.data, SIZE_V/2);
  }
  do {
    __push(BLOCKCAST(SIZE_V/2)(public.apdu.data));
    __push(BLOCKCAST(SIZE_V/2)(session.issue.vPrime));
    __code(ADDN, SIZE_V/2);
    __code(POPN, SIZE_V/2);
    __push(credential->signature.v);
    __code(STOREI, SIZE_V/2);
  } while (0);
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
void verifySignature(void) {
  int i;
  
  // Compute Ri = R[i]^m[i] mod n forall i
  crypto_modexp_secure(SIZE_M, SIZE_N, masterSecret,
    credential->issuerKey.n, credential->issuerKey.R[0], public.issue.buffer.number[0]);
  debugValue("Ri = R[0]^ms mod n", public.issue.buffer.number[0], SIZE_N);
  for (i = 1; i <= credential->size; i++) {
    crypto_modexp(SIZE_M, SIZE_N, credential->attribute[i - 1], credential->issuerKey.n, 
      credential->issuerKey.R[i], public.issue.buffer.number[1]);
    debugValue("buffer = R[i]^m[i] mod n", public.issue.buffer.number[1], SIZE_N);
    crypto_modmul(SIZE_N, public.issue.buffer.number[0], 
      public.issue.buffer.number[1], credential->issuerKey.n);
    debugValue("Ri = Ri * buffer mod n", public.issue.buffer.number[0], SIZE_N);
  }
  
  // Compute Z' = A^e * S^v * Ri mod n
  crypto_modexp_special(SIZE_V, credential->signature.v, 
    public.issue.buffer.number[1], public.issue.buffer.number[2]);
  debugValue("Z' = S^v mod n", public.issue.buffer.number[1], SIZE_N);
  crypto_modmul(SIZE_N, public.issue.buffer.number[1], 
    public.issue.buffer.number[0], credential->issuerKey.n);
  debugValue("Z' = Z' * Ri mod n", public.issue.buffer.number[1], SIZE_N);
  crypto_modexp(SIZE_E, SIZE_N, credential->signature.e, credential->issuerKey.n,
    credential->signature.A, public.issue.buffer.number[0]);
  debugValue("Ri = A^e mod n", public.issue.buffer.number[0], SIZE_N);
  crypto_modmul(SIZE_N, public.issue.buffer.number[1], 
    public.issue.buffer.number[0], credential->issuerKey.n);
  debugValue("Z' = Z' * R mod n", public.issue.buffer.number[1], SIZE_N);
  
  // - Verify Z =?= Z'
  if (memcmp(credential->issuerKey.Z, public.issue.buffer.number[1], SIZE_N) != 0) {
    // TODO: clear already stored things?
    debugError("verifySignature(): verification of signature failed");
    ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
  }
}

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
void verifyProof(void) {

  // Compute Q = A^e mod n
  crypto_modexp(SIZE_E, SIZE_N, credential->signature.e,
    credential->issuerKey.n, credential->signature.A, session.issue.v);
  debugValue("Q = A^e mod n", session.issue.v, SIZE_N);

  // Compute AHat = A^(c + s_e * e) = Q^s_e * A^c mod n
  crypto_modexp(SIZE_N, SIZE_N, credential->proof.response, 
    credential->issuerKey.n, session.issue.v, public.issue.buffer.number[1]);
  debugValue("buffer = Q^s_e mod n", public.issue.buffer.number[1], SIZE_N);
  crypto_modexp(SIZE_H, SIZE_N, credential->proof.challenge,
    credential->issuerKey.n, credential->signature.A, public.issue.buffer.number[0]);
  debugValue("AHat = A^c mod n", public.issue.buffer.number[0], SIZE_N);
  crypto_modmul(SIZE_N, public.issue.buffer.number[0], public.issue.buffer.number[1], credential->issuerKey.n);
  debugValue("AHat = AHat * buffer", public.issue.buffer.number[0], SIZE_N);
  
  // Compute challenge c' = H(context | Q | A | nonce | AHat)
  public.issue.list[0].data = credential->proof.context;
  public.issue.list[0].size = SIZE_H;
  public.issue.list[1].data = session.issue.v;
  public.issue.list[1].size = SIZE_N;
  public.issue.list[2].data = credential->signature.A;
  public.issue.list[2].size = SIZE_N;
  public.issue.list[3].data = credential->proof.nonce;
  public.issue.list[3].size = SIZE_STATZK;
  public.issue.list[4].data = public.issue.buffer.number[0];
  public.issue.list[4].size = SIZE_N;
  crypto_compute_hash(public.issue.list, 5, session.issue.challenge,
    public.issue.buffer.data, SIZE_BUFFER_C2);
  debugValue("c'", session.issue.challenge, SIZE_H);

  // Verify c =?= c'
  if (memcmp(credential->proof.challenge, session.issue.challenge, SIZE_H) != 0) {
    // TODO: clear already stored things?
    debugError("verifyProof(): verification of P2 failed");
    ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
  }
}

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
  __code(CLEARN, public.issue.buffer.data, SIZE_VPRIME_ - SIZE_VPRIME);
  
  // Multiply c (padded to match size) with least significant part of vPrime
//  MULN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_ - 2*SIZE_VPRIME/3, 
//    public.temp.challenge.prefix_vPrimeHat, credential->signature.v + SIZE_V - SIZE_VPRIME/3);
  __code(PUSHZ, SIZE_VPRIME/2 - SIZE_H);
  __push(BLOCKCAST(SIZE_H)(session.issue.challenge));
  __push(BLOCKCAST(SIZE_VPRIME/2)(session.issue.vPrime + SIZE_VPRIME/2));
  __code(PRIM, PRIM_MULTIPLY, SIZE_VPRIME/2);
  __code(STORE, public.issue.buffer.data + SIZE_VPRIME_ - SIZE_VPRIME, SIZE_VPRIME);
  
  // Multiply c (padded to match size) with most significant part of vPrime
//  MULN(SIZE_VPRIME/3, buffer + SIZE_VPRIME_, public.temp.challenge.prefix_vPrimeHat, 
//    credential->signature.v + SIZE_V - 2*SIZE_VPRIME/3);
  __code(PUSHZ, SIZE_VPRIME/2 - SIZE_H);
  __push(BLOCKCAST(SIZE_H)(session.issue.challenge));
  __push(BLOCKCAST(SIZE_VPRIME/2)(session.issue.vPrime));
  __code(PRIM, PRIM_MULTIPLY, SIZE_VPRIME/3);
//  __code(STORE, public.issue.buffer.data + SIZE_VPRIME_, SIZE_VPRIME);
  
  // Combine the two multiplications into a single result
//  ASSIGN_ADDN(SIZE_VPRIME_ - SIZE_VPRIME/2, public.issue.buffer.data, 
//    public.issue.buffer.data + SIZE_VPRIME + SIZE_VPRIME/2);
  __code(ADDN, public.issue.buffer.data, SIZE_VPRIME_ - SIZE_VPRIME/2);
  __code(POPN, SIZE_VPRIME);
  
  // Add (with carry) vPrimeTilde and store the result in vPrimeHat
  ASSIGN_ADDN(SIZE_VPRIME_/2, public.issue.vPrimeHat + SIZE_VPRIME_/2, public.issue.buffer.data + SIZE_VPRIME_/2);
  CFlag(&flag);
  if (flag != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_VPRIME_/2, public.issue.vPrimeHat);
  }
  ASSIGN_ADDN(SIZE_VPRIME_/2, public.issue.vPrimeHat, public.issue.buffer.data);
}
