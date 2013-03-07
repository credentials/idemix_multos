/**
 * crypto_multos.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, September 2012.
 */

#ifndef __crypto_multos_H
#define __crypto_multos_H

#include <multoscrypto.h>

#define PRIM_MULTIPLY 0x10
#define PRIM_RANDOM 0xc4
#define PRIM_RSA_VERIFY 0xEB
#define PRIM_SECURE_HASH 0xCF

#define crypto_modmul(ModulusLength, LHS, RHS, Modulus) \
  ModularMultiplication(ModulusLength, LHS, RHS, Modulus)

#define crypto_modexp_secure(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) \
  ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result)

// Use the efficient RSA_VERIFY primitive on ML3
#ifdef ML3
// This primitive is not supported by the simulator
#ifndef SIMULATOR

#define crypto_modexp(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) \
do { \
  __push(__typechk(unsigned int, ExponentLength)); \
  __push(__typechk(unsigned int, ModulusLength)); \
  __push(__typechk(unsigned char *, Exponent)); \
  __push(__typechk(unsigned char *, Modulus)); \
  __push(__typechk(unsigned char *, Base)); \
  __push(__typechk(unsigned char *, Result)); \
  __code(PRIM, PRIM_RSA_VERIFY); \
} while (0)

#endif // SIMULATOR
#endif // ML3

#ifndef crypto_modexp

#define crypto_modexp(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) \
  ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result)

#endif // crypto_modexp

#define SHA256(PlainTextLength, HashDigest, PlainText) \
do { \
  __push(__typechk(unsigned int, PlainTextLength));	\
  __code(PUSHW, 32); \
  __push(__typechk(unsigned char *, HashDigest)); \
  __push(__typechk(unsigned char *, PlainText)); \
  __code(PRIM, PRIM_SECURE_HASH); \
} while (0)

#endif // __crypto_multos_H
