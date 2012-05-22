/**
 * defs_types.h
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
 
#ifndef __defs_types_H
#define __defs_types_H

#include "defs_sizes.h"

typedef unsigned int uint;
typedef const char *String;

typedef unsigned char Byte;
typedef Byte *ByteArray;

typedef Byte Hash[SIZE_H];
typedef Byte Nonce[SIZE_STATZK];
typedef Byte ResponseE[SIZE_E_];
typedef Byte ResponseM[SIZE_S_A];
typedef Byte ResponseV[SIZE_V_];
typedef Byte ResponseVPRIME[SIZE_VPRIME_];
typedef Byte Number[SIZE_N];
typedef Number Numbers[];

typedef struct {
  ByteArray data;
  int size;
} Value;
typedef Value *ValueArray;

typedef struct {
  Number n;
  Number Z;
  Number S;
  Number S_;
  Number R[SIZE_L];
} CLPublicKey;

typedef Byte CLMessage[SIZE_M];
typedef CLMessage CLMessages[SIZE_L];

typedef struct {
  Number A;
  Byte e[SIZE_E];
  Byte v[SIZE_V];
} CLSignature;

typedef struct {
  Nonce nonce;
  Hash context;
  Hash challenge;
  Number response;
} CLProof;

typedef struct {
  Byte prefix_vHat[SIZE_V/3 - SIZE_VPRIME/3];
  Byte prefix_vPrimeHat[SIZE_VPRIME/3 - SIZE_M];
  Byte prefix_mHat[SIZE_M - SIZE_H];
  Hash c;
} Challenge;

typedef union {
  Byte data[255];
  Byte public[530];
  struct {
    Byte data[SIZE_BUFFER_C2];
    Value list[5];
  } temp;
} APDUData;

#endif // __defs_types_H
