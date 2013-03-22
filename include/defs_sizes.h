/**
 * defs_sizes.h
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

#ifndef __sizes_H
#define __sizes_H

// Attribute and credential definitions
#define MAX_ATTR      5
#define MAX_CRED      8

// System parameter lengths
#define LENGTH_N      1024
#define LENGTH_M       256
#define LENGTH_STATZK   80
#define LENGTH_H       256 // SHA-256
#define LENGTH_V      1700 // > L_N(1024) + L_STATZK(80) + L_H(256) + L_M(256) + 83
#define LENGTH_E       597 // > L_STATZK(80) + L_H(256) + L_M(256) + 4
#define LENGTH_EPRIME  120
#define LENGTH_VPRIME   (LENGTH_N + LENGTH_STATZK)
#define LENGTH_VPRIME_  (LENGTH_N + 2*LENGTH_STATZK + LENGTH_H)
#define LENGTH_V_       (LENGTH_V + LENGTH_STATZK + LENGTH_H)
#define LENGTH_S_       (LENGTH_M + LENGTH_STATZK + LENGTH_H + 1)
#define LENGTH_R_A      (LENGTH_N + LENGTH_STATZK)
#define LENGTH_M_       (LENGTH_M + LENGTH_STATZK + LENGTH_H)
#define LENGTH_E_       (LENGTH_EPRIME + LENGTH_STATZK + LENGTH_H)

// Variable byte size definitions
#define SIZE_L      MAX_ATTR + 1
#define SIZE_N      128 // 1024 bits
#define SIZE_M       32 //  256 bits
#define SIZE_STATZK  10 //   80 bits
#define SIZE_H       32 //  256 bits
#define SIZE_V      213 // 1700 bits
#define SIZE_E       75 //  597 bits
#define SIZE_EPRIME  15 //  120 bits

#define SIZE_VPRIME  (SIZE_N + SIZE_STATZK) // 138 bytes
#define SIZE_VPRIME_ (SIZE_N + 2*SIZE_STATZK + SIZE_H) // 180 bytes
#define SIZE_M_      (SIZE_M + SIZE_STATZK + SIZE_H) // 74 bytes
#define SIZE_S_      (SIZE_M + SIZE_STATZK + SIZE_H + 1) // 75 bytes
#define SIZE_R_A     (SIZE_N + SIZE_STATZK) // 138 bytes
#define SIZE_V_      (SIZE_V + SIZE_STATZK + SIZE_H) // 255 bytes
#define SIZE_E_      (SIZE_EPRIME + SIZE_STATZK + SIZE_H) // 57 bytes

#define SIZE_BUFFER_C1 ((SIZE_H+3) + 2*(SIZE_N+4) + (SIZE_STATZK+3) + 3 + 4) // 319 bytes
#define SIZE_BUFFER_C2 ((SIZE_H+3) + 3*(SIZE_N+4) + (SIZE_STATZK+3) + 3 + 4) // 450 bytes

// Auxiliary sizes
#define SIZE_S_EXPONENT 128
#define SIZE_V_ADDITION 80

#define SIZE_IV 8
#define SIZE_SSC 8
#define SIZE_MAC 8
#define SIZE_KEY 16
#define SIZE_KEY_SEED_CARD 128
#define LENGTH_KEY_SEED_CARD (SIZE_KEY_SEED_CARD*8)
#define SIZE_KEY_SEED_TERMINAL 128
#define SIZE_KEY_SEED (SIZE_KEY_SEED_CARD + SIZE_KEY_SEED_TERMINAL)

#define SIZE_RSA_EXPONENT 128
#define SIZE_RSA_MODULUS 128

#define SIZE_PIN_MAX 8
#define SIZE_CRED_PIN 4
#define SIZE_CARD_PIN 6

#define SIZE_LOG 30
#define SIZE_TERMINAL_ID 4
#define SIZE_TIMESTAMP 4
#define SIZE_FLAGS 2

#ifdef ML2
#ifdef ML3
#error Cannot build for both ML2 and ML3
#endif // ML3
#endif // ML2

#ifndef ML2
#ifndef ML3
#error ML2 or ML3 must be specified
#endif // ML3
#endif // ML2

#ifdef I4F
#define SIZE_PUBLIC // = -17 (exclude APDU headers section)
#endif // I4F

#ifdef ML2
#define SIZE_PUBLIC 685 // = 702 - 17 (exclude APDU headers section)
#endif // ML2

#ifdef ML3
#define SIZE_PUBLIC 1071 // = 1088 - 17 (exclude APDU headers section)
#endif // ML3

#endif // __sizes_H
