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

// Attribute definitions
#define MAX_ATTR      5

// System parameter lengths
#define LENGTH_N      1024
#define LENGTH_M       160
#define LENGTH_STATZK   80
#define LENGTH_H       160 // SHA-1
#define LENGTH_V      1604
#define LENGTH_E       501 // > L_STATZK(80) + L_H(160) + L_M(256) + 4
#define LENGTH_EPRIME  120
#define LENGTH_VPRIME   (LENGTH_N + LENGTH_STATZK)
#define LENGTH_VPRIME_  (LENGTH_N + 2*LENGTH_STATZK + LENGTH_H)
#define LENGTH_V_       (LENGTH_V + LENGTH_STATZK + LENGTH_H)
#define LENGTH_S_A      (LENGTH_M + LENGTH_STATZK + LENGTH_H + 1)
#define LENGTH_R_A      (LENGTH_N + LENGTH_STATZK)
#define LENGTH_M_       (LENGTH_M + LENGTH_STATZK + LENGTH_H)
#define LENGTH_E_       (LENGTH_EPRIME + LENGTH_STATZK + LENGTH_H)

// Variable byte size definitions
#define SIZE_L      MAX_ATTR + 1
#define SIZE_N      128 // 1024 bits
#define SIZE_M       20 //  160 bits
#define SIZE_STATZK  10 //   80 bits
#define SIZE_H       20 //  160 bits
#define SIZE_V      201 // 1604 bits
#define SIZE_E       63 //  504 bits
#define SIZE_EPRIME  15 //  120 bits

#define SIZE_VPRIME  (SIZE_N + SIZE_STATZK) // 138 bytes
#define SIZE_VPRIME_ (SIZE_N + 2*SIZE_STATZK + SIZE_H) // 168 bytes
#define SIZE_M_      (SIZE_M + SIZE_STATZK + SIZE_H) // 62 bytes
#define SIZE_S_A     (SIZE_M + SIZE_STATZK + SIZE_H + 1) // 51 bytes
#define SIZE_R_A     (SIZE_N + SIZE_STATZK) // 138 bytes
#define SIZE_V_      (SIZE_V + SIZE_STATZK + SIZE_H) // 231 bytes
#define SIZE_E_      (SIZE_EPRIME + SIZE_STATZK + SIZE_H) // 45 bytes

#define SIZE_BUFFER_C1 ((SIZE_H+3) + 2*(SIZE_N+4) + (SIZE_STATZK+3) + 3 + 4) // 307 bytes
#define SIZE_BUFFER_C2 ((SIZE_H+3) + 3*(SIZE_N+4) + (SIZE_STATZK+3) + 3 + 4) // 438 bytes

// Auxiliary sizes
#define SIZE_S_EXPONENT 120
#define SIZE_V_ADDITION 80

#define SIZE_IV 8
#define SIZE_SSC 8
#define SIZE_MAC 8
#define SIZE_KEY 16

#endif // __sizes_H
