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

#define crypto_modmul(ModulusLength, LHS, RHS, Modulus) \
  ModularMultiplication(ModulusLength, LHS, RHS, Modulus)

#define crypto_modexp_secure(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) \
  ModularExponentiation(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result)

#define crypto_modexp(ExponentLength, ModulusLength, Exponent, Modulus, Base, Result) \
do { \
  __push(__typechk(unsigned int, ExponentLength)); \
  __push(__typechk(unsigned int, ModulusLength)); \
  __push(__typechk(unsigned char *, Exponent)); \
  __push(__typechk(unsigned char *, Modulus)); \
  __push(__typechk(unsigned char *, Base)); \
  __push(__typechk(unsigned char *, Result)); \
  __code(PRIM, 0xEB); \
} while (0)

#define PRIM_MULTIPLY 0x10
#define PRIM_RANDOM 0xc4

#endif // __crypto_multos_H
