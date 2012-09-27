/**
 * crypto_proving.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, July 2011.
 */
 
#ifndef __crypto_proving_H
#define __crypto_proving_H

#include "defs_types.h"
#include "crypto_multos.h"

/**
 * Select the attributes to be disclosed
 */
void selectAttributes(ByteArray list, int length);

/**
 * Construct a proof
 */
void constructProof(void);

/**
 * Compute the response value v' = v - e*r_A
 *
 * Requires buffer of size SIZE_V + 2*SIZE_R_A.
 *
 * @param r_A the randomisation value
 */
void crypto_compute_vPrime(void);

/**
 * Compute the response value vHat = vTilde + c*v'
 * 
 * Requires buffer of size SIZE_V_ + SIZE_V and vTilde to be stored in 
 * vHat.
 * 
 * @param c the challenge
 */
void crypto_compute_vHat(void);

/**
 * Compute the response value eHat = eTilde + c*e
 * 
 * Requires eTilde to be stored in eHat.
 */
#define crypto_compute_eHat() \
do { \
  /* Push ZERO bytes for padding (since 2*SIZE_H < SIZE_E_)*/\
  __code(PUSHZ, SIZE_E_ - 2*SIZE_H); \
  /* Multiply c with ePrime (SIZE_H since SIZE_H > SIZE_EPRIME) */\
  __push(BLOCKCAST(SIZE_H)(public.prove.apdu.challenge)); \
  __push(BLOCKCAST(SIZE_H)(credential->signature.e + SIZE_E - SIZE_H)); /* ePrime */\
  __code(PRIM, PRIM_MULTIPLY, SIZE_H); \
  /* Add eTilde and store the result in eHat */\
  __code(ADDN, public.prove.eHat, SIZE_E_); \
  __code(POPN, SIZE_E_); \
} while (0)

/**
 * Compute the response value mHat[i] = mTilde[i] + c*m[i]
 * 
 * Requires mTilde[i] to be stored in mHat[i].
 * 
 * @param i index of the message to be hidden
 * @param size of mTilde and mHat
 */
#define crypto_compute_mHat(i) \
do { \
  /* Multiply c with m */\
  __code(PUSHZ, SIZE_M - SIZE_H); \
  __push(BLOCKCAST(SIZE_H)(public.prove.apdu.challenge)); \
  __push(BLOCKCAST(SIZE_M)(i == 0 ? masterSecret : credential->attribute[i - 1])); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_M); \
  /* Put the result address in front of the operand (for STOREI) */\
  __push(session.prove.mHat[i]); \
  __code(PUSHZ, SIZE_M_); \
  __code(ORN, SIZE_M_ + 2); \
  __code(POPN, SIZE_M_ + 2); \
  /* Add mTilde to the result of the multiplication and store in mHat*/\
  __push(BLOCKCAST(SIZE_M_)(session.prove.mHat[i])); \
  __code(ADDN, SIZE_M_); \
  __code(POPN, SIZE_M_); \
  __code(STOREI, SIZE_M_); \
} while (0)

/**
 * Determine whether an attribute is to be disclosed or not.
 * 
 * @param index of the attribute
 * @return 1 if disclosed, 0 if not
 */
#define disclosed(index) ((session.prove.disclose >> (index)) & 0x0001)

#endif // __crypto_proving_H
