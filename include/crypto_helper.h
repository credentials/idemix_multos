/**
 * crypto_helper.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, September 2011.
 */
 
#ifndef __crypto_helper_H
#define __crypto_helper_H

#include "defs_types.h"

//////////////////////////////////////////////////////////////////////
// Shared functions                                                 //
//////////////////////////////////////////////////////////////////////

/**
 * Compute a cryptographic hash of the given input values
 * 
 * @param list of values to be included in the hash
 * @param length of the values list
 * @param result of the hashing operation
 * @param buffer which can be used for temporary storage
 * @param size of the buffer
 */
void crypto_compute_hash(ValueArray list, int length, ByteArray result,
                         ByteArray buffer, int size);

/**
 * Generate a random number in the buffer of size bytes
 * 
 * @param buffer to store the generated random number
 * @param length of the random number to generate
 */
void crypto_generate_random(ByteArray buffer, int length);

/**
 * Compute the helper value S' = S^(2_l) where l = SIZE_S_EXPONENT*8
 * 
 * This value is required for exponentiations with base S and an 
 * exponent which is larger than SIZE_N bytes.
 */
void crypto_compute_S_(void);

/**
 * Compute the modular exponentiation: result = S^exponent mod n
 * 
 * This function will use the helper value S' to compute exponentiations 
 * with exponents larger than SIZE_N bytes.
 * 
 * @param size of the exponent
 * @param exponent the power to which the base S should be raised
 * @param result of the computation
 */
void crypto_compute_SpecialModularExponentiation(int size, 
                                                 ByteArray exponent, 
                                                 ByteArray result);

//////////////////////////////////////////////////////////////////////
// Issuing functions                                                //
//////////////////////////////////////////////////////////////////////

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
 * Compute the response value s_A = mTilde[0] + c*m[0]
 * 
 * @param buffer of size 2*SIZE_M_ + SIZE_M
 * @param c in challenge.prefix_m
 * @param m[0] in messages[0]
 * @param mTilde[0] in mHat[0]
 * @return s_A in mHat[0]
 */
void crypto_compute_s_A(void);

//////////////////////////////////////////////////////////////////////
// Proving functions                                                //
//////////////////////////////////////////////////////////////////////

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
 * Compute the response value mHat = mTilde + c*m
 * 
 * Requires buffer of size 2*SIZE_M_ + SIZE_M and mTilde[index] to be 
 * stored in mHat[index].
 * 
 * @param c the challenge
 * @param index of the message to be hidden
 */
void crypto_compute_mHat(int index);

/**
 * Compute the response value eHat = eTilde + c*e
 * 
 * Requires buffer of size 2*SIZE_E and eTilde to be stored in eHat.
 * 
 * @param c the challenge
 * @param e the value to be hidden
 */
void crypto_compute_eHat(void);

/**
 * Determine whether an attribute is to be disclosed or not.
 * 
 * @param index of the attribute
 * @return 1 if disclosed, 0 if not
 */
#define disclosed(index) ((disclose >> (index)) & 0x0001)

#endif // __crypto_helper_H
