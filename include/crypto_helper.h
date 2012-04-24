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
 * Compute the response value vHat = vTilde + c*vPrime
 * 
 * Requires buffer of size SIZE_VPRIME_ + SIZE_VPRIME and vTilde to be 
 * stored in vHat.
 * 
 * @param c the challenge
 * @param vPrime the value to be hidden
 */
void crypto_compute_vPrimeHat(ByteArray c, ByteArray vPrime);

/**
 * Compute the response value vHat = vTilde + c*v
 * 
 * Requires buffer of size SIZE_V_ + SIZE_V and vTilde to be stored in 
 * vHat.
 * 
 * @param c the challenge
 * @param v the value to be hidden
 */
void crypto_compute_vHat(ByteArray c, ByteArray v);

/**
 * Compute the response value mHat = mTilde + c*m
 * 
 * Requires buffer of size 2*SIZE_M_ + SIZE_M and mTilde[index] to be 
 * stored in mHat[index].
 * 
 * @param c the challenge
 * @param index of the message to be hidden
 */
void crypto_compute_mHat(ByteArray c, int index);

/**
 * Compute the response value eHat = eTilde + c*e
 * 
 * Requires buffer of size 2*SIZE_E and eTilde to be stored in eHat.
 * 
 * @param c the challenge
 * @param e the value to be hidden
 */
void crypto_compute_eHat(ByteArray c, ByteArray e);

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

#endif // __crypto_helper_H