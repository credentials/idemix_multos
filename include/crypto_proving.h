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

#endif // __crypto_proving_H
