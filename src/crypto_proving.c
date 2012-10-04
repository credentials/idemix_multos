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

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

/**
 * Select the attributes to be disclosed
 */
void selectAttributes(ByteArray list, int length) {
  int i = 0;

  debugValue("Disclosure list", list, length);
  session.prove.disclose = 0x00;
  for (i = 0; i < length; i++) {
    if (list[i] == 0 || list[i] > MAX_ATTR) {
      // FAIL, TODO: clear already stored things
      debugError("selectAttributes(): invalid attribute index");
      ReturnSW(ISO7816_SW_WRONG_DATA);
    }
    session.prove.disclose |= 1 << list[i];
  }
  debugInteger("Disclosure selection", session.prove.disclose);
}

/**
 * Construct a proof
 */
void constructProof(void) {
  int i;
  
  // Generate random values for m~[i], e~, v~ and rA
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_generate_random(session.prove.mHat[i], LENGTH_M_);
    }
  }
  debugValues("m_", (ByteArray) session.prove.mHat, SIZE_M_, SIZE_L);
  crypto_generate_random(public.prove.eHat, LENGTH_E_);
  debugValue("e_", public.prove.eHat, SIZE_E_);
  crypto_generate_random(public.prove.vHat, LENGTH_V_);
  debugValue("v_", public.prove.vHat, SIZE_V_);
  // IMPORTANT: Correction to the length of rA to prevent negative values
  crypto_generate_random(public.prove.rA, LENGTH_R_A - 7);
  debugValue("rA", public.prove.rA, SIZE_R_A);
  
  // Compute A' = A S^r_A
  crypto_modexp_special(SIZE_R_A, public.prove.rA, public.prove.APrime, 
    public.prove.buffer.number[0]);
  debugValue("A' = S^r_A mod n", public.prove.APrime, SIZE_N);
  crypto_modmul(SIZE_N, public.prove.APrime, credential->signature.A, credential->issuerKey.n);
  debugValue("A' = A' * A mod n", public.prove.APrime, SIZE_N);
  
  // Compute ZTilde = A'^eTilde * S^vTilde * (R[i]^mHat[i] foreach i not in D)
  crypto_modexp_special(SIZE_V_, public.prove.vHat, public.prove.buffer.number[0],
    public.prove.buffer.number[1]);
  debugValue("ZTilde = S^v_", public.prove.buffer.number[0], SIZE_N);
  crypto_modexp(SIZE_E_, SIZE_N, public.prove.eHat,
    credential->issuerKey.n, public.prove.APrime, public.prove.buffer.number[1]);
  debugValue("buffer = A'^eTilde", public.prove.buffer.number[1], SIZE_N);
  crypto_modmul(SIZE_N, public.prove.buffer.number[0],
    public.prove.buffer.number[1], credential->issuerKey.n);
  debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_modexp(SIZE_M_, SIZE_N, session.prove.mHat[i], credential->issuerKey.n, 
        credential->issuerKey.R[i], public.prove.buffer.number[1]);
      debugValue("R_i^m_i", public.prove.buffer.number[1], SIZE_N);
      crypto_modmul(SIZE_N, public.prove.buffer.number[0], 
        public.prove.buffer.number[1], credential->issuerKey.n);
      debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
    }
  }
  
  // Compute challenge c = H(context | A' | ZTilde | nonce)
#ifndef SIMULATOR
  public.prove.list[0].data = public.prove.context;
#else // SIMULATOR
  public.prove.list[0].data = session.prove.context;
#endif // SIMULATOR
  public.prove.list[0].size = SIZE_H;
  public.prove.list[1].data = public.prove.APrime;
  public.prove.list[1].size = SIZE_N;
  public.prove.list[2].data = public.prove.buffer.number[0];
  public.prove.list[2].size = SIZE_N;
  public.prove.list[3].data = public.prove.apdu.nonce;
  public.prove.list[3].size = SIZE_STATZK;
  crypto_compute_hash(public.prove.list, 4, public.prove.apdu.challenge, 
    public.prove.buffer.data, SIZE_BUFFER_C1);
  debugValue("c", public.prove.apdu.challenge, SIZE_H);
  
  // Compute e' = e - 2^(l_e' - 1) (just ignore the first bit of e)
  debugValue("e' = e - 2^(l_e' - 1)", 
    credential->signature.e + SIZE_E - SIZE_EPRIME, SIZE_EPRIME);
  
  // Compute e^ = e~ + c e'
  crypto_compute_eHat();
  debugValue("eHat", public.prove.eHat, SIZE_E_);
  
  // Compute v' = v - e r_A
  crypto_compute_vPrime();
  debugValue("v' = v - e*r_A", public.prove.buffer.data, SIZE_V);

  // Compute v^ = v~ + c v'
  crypto_compute_vHat();
  debugValue("vHat", public.prove.vHat, SIZE_V_);
  
  // Compute m_i^ = m_i~ + c m_i
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_compute_mHat(i);
    }
  }
  debugValues("mHat", (ByteArray) session.prove.mHat, SIZE_M_, SIZE_L);
  
  // return eHat, vHat, mHat[i], c, A'
}

/**
 * Compute the value vPrime = v - e*r_A
 *
 * @param buffer of size SIZE_V + 2*SIZE_R_A
 * @param e in signature.e
 * @param r_A in vHat
 * @param v in signature.v
 * @return vPrime in signature_.v
 */
void crypto_compute_vPrime(void) {
  // Clear the buffer, to prevent garbage messing up the computation
  CLEARN(SIZE_V - SIZE_R_A, public.prove.buffer.data);

  // Multiply e with least significant half of r_A
//  MULN(SIZE_R_A/2, buffer + SIZE_V - SIZE_R_A, e_prefix_rA, r_A + SIZE_R_A/2);
  do {
    __code(PUSHZ, SIZE_R_A/2 - SIZE_E);
    __push(BLOCKCAST(SIZE_E)(credential->signature.e));
    __push(BLOCKCAST(SIZE_R_A/2)(public.prove.rA + SIZE_R_A/2));
    __code(PRIM, PRIM_MULTIPLY, SIZE_R_A/2);
    __code(STORE, public.prove.buffer.data + SIZE_V - SIZE_R_A, SIZE_R_A);
  } while (0);

  // Multiply e with most significant half of r_A
//  MULN(SIZE_R_A/2, buffer + SIZE_V, e_prefix_rA, r_A);
  do {
    __code(PUSHZ, SIZE_R_A/2 - SIZE_E);
    __push(BLOCKCAST(SIZE_E)(credential->signature.e));
    __push(BLOCKCAST(SIZE_R_A/2)(public.prove.rA));
    __code(PRIM, PRIM_MULTIPLY, SIZE_R_A/2);
//    __code(STORE, public.prove.buffer.data + SIZE_V, SIZE_R_A);
  } while (0);

  // Combine the two multiplications into a single result
//  ASSIGN_ADDN(SIZE_V - SIZE_R_A/2, public.prove.buffer.data, 
//    public.prove.buffer.data + SIZE_R_A + SIZE_R_A/2);
  __code(ADDN, public.prove.buffer.data, SIZE_V - SIZE_R_A/2);
  __code(POPN, SIZE_R_A);

  // Subtract (with carry) from v and store the result in v'
  SUBN(SIZE_V/3, public.prove.buffer.data + 2*SIZE_V/3, 
    credential->signature.v + 2*SIZE_V/3, public.prove.buffer.data + 2*SIZE_V/3);
  CFlag(&flag);
  if (flag != 0x00) {
    debugMessage("Subtraction with carry, subtracting 1 (by increasing the buffer with 1)");
    INCN(SIZE_V/3, public.prove.buffer.data + SIZE_V/3);
  }
  SUBN(SIZE_V/3, public.prove.buffer.data + SIZE_V/3, 
    credential->signature.v + SIZE_V/3, public.prove.buffer.data + SIZE_V/3);
  CFlag(&flag);
  if (flag != 0x00) {
    debugMessage("Subtraction with carry, subtracting 1 (by increasing the buffer with 1)");
    INCN(SIZE_V/3, public.prove.buffer.data);
  }
  SUBN(SIZE_V/3, public.prove.buffer.data, 
    credential->signature.v, public.prove.buffer.data);
}

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
  CLEARN(SIZE_V_ - SIZE_V, public.prove.buffer.data + SIZE_V);
  
  // Multiply c with least significant part of v
//  MULN(SIZE_V/3, buffer + SIZE_V_ - 2*SIZE_V/3, public.temp.challenge.prefix_vHat, 
//    public.temp.signature_.v + 2*SIZE_V/3);
  do {
    __code(PUSHZ, SIZE_V/3 - SIZE_H);
    __push(BLOCKCAST(SIZE_H)(public.prove.apdu.challenge));
    __push(BLOCKCAST(SIZE_V/3)(public.prove.buffer.data + 2*SIZE_V/3));
    __code(PRIM, PRIM_MULTIPLY, SIZE_V/3);
    __code(STORE, public.prove.buffer.data + SIZE_V + SIZE_V_ - 2*SIZE_V/3, 2*SIZE_V/3);
  } while (0);
  
  // Multiply c with middle significant part of v
//  MULN(SIZE_V/3, buffer + SIZE_V_, public.temp.challenge.prefix_vHat, 
//    public.temp.signature_.v + SIZE_V/3);
  do {
    __code(PUSHZ, SIZE_V/3 - SIZE_H);
    __push(BLOCKCAST(SIZE_H)(public.prove.apdu.challenge));
    __push(BLOCKCAST(SIZE_V/3)(public.prove.buffer.data + SIZE_V/3));
    __code(PRIM, PRIM_MULTIPLY, SIZE_V/3);
    __code(STORE, public.prove.buffer.data + SIZE_V + SIZE_V_, 2*SIZE_V/3);
  } while (0);
  
  // Combine the two multiplications into a partial result
/*  ASSIGN_ADDN(2*SIZE_V/3, buffer + SIZE_V_ - SIZE_V, buffer + SIZE_V_); /* works as expected */
  ASSIGN_ADDN(SIZE_V/3, public.prove.buffer.data + SIZE_V + SIZE_V_ - 2*SIZE_V/3, public.prove.buffer.data + SIZE_V + SIZE_V_ + SIZE_V/3);
  COPYN(SIZE_V/3, public.prove.buffer.data + SIZE_V + SIZE_V_ - SIZE_V, public.prove.buffer.data + SIZE_V + SIZE_V_);
    
  // Multiply c with most significant part of v
//  MULN(SIZE_V/3, buffer + SIZE_V_, public.temp.challenge.prefix_vHat, public.temp.signature_.v);
  do {
    __code(PUSHZ, SIZE_V/3 - SIZE_H);
    __push(BLOCKCAST(SIZE_H)(public.prove.apdu.challenge));
    __push(BLOCKCAST(SIZE_V/3)(public.prove.buffer.data));
    __code(PRIM, PRIM_MULTIPLY, SIZE_V/3);
    __code(STORE, public.prove.buffer.data + SIZE_V + SIZE_V_, 2*SIZE_V/3);
  } while (0);
  
  // Combine the two multiplications into a single result
/*  ASSIGN_ADDN(SIZE_V_ - 2*SIZE_V/3, buffer, buffer + 4*SIZE_V/3); /* fails somehow :-S what am I doing wrong? */
  ASSIGN_ADDN(SIZE_V/3, public.prove.buffer.data + SIZE_V + SIZE_V_ - SIZE_V, 
    public.prove.buffer.data + SIZE_V + SIZE_V_ + SIZE_V/3);
  COPYN(SIZE_V_ - SIZE_V, public.prove.buffer.data + SIZE_V, 
    public.prove.buffer.data + SIZE_V + 4*SIZE_V/3);
  
  // Add (with carry) vTilde and store the result in vHat
  ASSIGN_ADDN(SIZE_V_/3, public.prove.vHat + 2*SIZE_V_/3, 
    public.prove.buffer.data + SIZE_V + 2*SIZE_V_/3);
  CFlag(&flag);
  if (flag != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_V_/3, public.prove.vHat + SIZE_V_/3);
  }
  ASSIGN_ADDN(SIZE_V_/3, public.prove.vHat + SIZE_V_/3, 
    public.prove.buffer.data + SIZE_V + SIZE_V_/3);
  CFlag(&flag);
  if (flag != 0x00) {
    debugMessage("Addition with carry, adding 1");
    INCN(SIZE_V_/3, public.prove.vHat);
  }
  ASSIGN_ADDN(SIZE_V_/3, public.prove.vHat, public.prove.buffer.data + SIZE_V);
}
