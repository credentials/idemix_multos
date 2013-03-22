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
 * Requires vPrimeTilde to be stored in vPrimeHat.
 */
#define crypto_compute_vPrimeHat() \
do { \
  /* Clear the buffer, to prevent garbage messing up the computation */\
  __code(CLEARN, public.issue.buffer.data, SIZE_VPRIME_ - SIZE_VPRIME); \
  /* Multiply c (padded to match size) with least significant part of vPrime */\
  __code(PUSHZ, SIZE_VPRIME/2 - SIZE_H); \
  __push(BLOCKCAST(SIZE_H)(session.issue.challenge)); \
  __push(BLOCKCAST(SIZE_VPRIME/2)(session.issue.vPrime + SIZE_VPRIME/2)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_VPRIME/2); \
  __code(STORE, public.issue.buffer.data + SIZE_VPRIME_ - SIZE_VPRIME, SIZE_VPRIME); \
  /* Multiply c (padded to match size) with most significant part of vPrime */\
  __code(PUSHZ, SIZE_VPRIME/2 - SIZE_H); \
  __push(BLOCKCAST(SIZE_H)(session.issue.challenge)); \
  __push(BLOCKCAST(SIZE_VPRIME/2)(session.issue.vPrime)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_VPRIME/2); \
  /* Combine the two multiplications into a single result */\
  __code(ADDN, public.issue.buffer.data, SIZE_VPRIME_ - SIZE_VPRIME/2); \
  __code(POPN, SIZE_VPRIME); \
  /* Add vPrimeTilde and store the result in vPrimeHat */\
  __push(BLOCKCAST(SIZE_VPRIME_)(public.issue.buffer.data)); \
  __code(ADDN, session.issue.vPrimeHat, SIZE_VPRIME_); \
  __code(POPN, SIZE_VPRIME_); \
} while (0)

/**
 * Compute the response value sHat = sTilde + c * s
 * 
 * Requires sTilde to be stored in sHat.
 */
#define crypto_compute_sHat() \
do { \
  /* Multiply c with m */\
  __code(PUSHZ, SIZE_S_ - 2*SIZE_M); \
  __push(BLOCKCAST(SIZE_H)(session.issue.challenge)); \
  __push(BLOCKCAST(SIZE_M)(masterSecret)); \
  __code(PRIM, PRIM_MULTIPLY, SIZE_M); \
  /* Add the result of the multiplication to sTilde and store in sHat */\
  __code(ADDN, session.issue.sHat, SIZE_S_); \
  /* Cleanup the stack */\
  __code(POPN, SIZE_S_); \
} while (0)

#endif // __crypto_issuing_H
