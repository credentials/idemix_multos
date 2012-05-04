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

#endif // __crypto_issuing_H
