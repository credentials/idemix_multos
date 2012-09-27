/**
 * crypto_issuing.h
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
 
#ifndef __crypto_issuing_H
#define __crypto_issuing_H

/**
 * Construct a commitment (round 1)
 */
void constructCommitment(void);

/**
 * Construct the signature (round 3, part 1)
 */
void constructSignature(void);

/**
 * (OPTIONAL) Verify the signature (round 3, part 2)
 */
void verifySignature(void);

/**
 * (OPTIONAL) Verify the proof (round 3, part 3)
 */
void verifyProof(void);

/**
 * Compute the response value vPrimeHat = vPrimeTilde + c*vPrime
 * 
 * @param buffer of size SIZE_VPRIME_ + SIZE_VPRIME
 * @param c in challenge.prefix_vPrime
 * @param vPrime signature.v + SIZE_V - SIZE_VPRIME
 * @param vTilde in vPrimeHat
 * @return vPrimeHat
 */
void crypto_compute_vPrimeHat(void);

/**
 * Compute the response value mHat[i] = mTilde[i] + c*m[i]
 * 
 * Requires mTilde[i] to be stored in mHat[i].
 * 
 * @param i index of the message to be hidden
 * @param size of mTilde and mHat
 */
#define crypto_compute_sA() \
do { \
  /* Multiply c with m */\
  __code(PUSHZ, SIZE_M - SIZE_H); \
  __push(BLOCKCAST(SIZE_H)(session.issue.challenge)); \
  __push(BLOCKCAST(SIZE_M)(masterSecret)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_M); \
  /* Add the result of the multiplication to mTilde and store in sA */\
  __code(ADDN, session.issue.sA, SIZE_S_A); \
  /* Cleanup the stack */\
  __code(POPN, 2*SIZE_M - SIZE_S_A); \
} while (0)

#endif // __crypto_issuing_H
