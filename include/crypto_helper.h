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
void crypto_modexp_special(int size, ByteArray exponent, ByteArray result, ByteArray buffer);

/**
 * Clear size bytes from a bytearray
 *
 * @param size the amount of bytes to clear
 * @param buffer to be cleared
 */
void crypto_clear(int size, ByteArray buffer);

/**
 * Clear the current credential.
 */
void crypto_clear_credential(void);

/**
 * Clear the current session.
 */
void crypto_clear_session(void);

#ifdef SIMULATOR
#define SHA1_PADDED
#endif // SIMULATOR

#endif // __crypto_helper_H
