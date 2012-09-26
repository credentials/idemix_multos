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
typedef Byte ResponseM[SIZE_M_];
typedef Byte ResponseV[SIZE_V_];
typedef Byte ResponseVPRIME[SIZE_VPRIME_];
typedef Byte Number[SIZE_N];
typedef Byte Counter[SIZE_SSC];
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
typedef CLMessage CLMessages[MAX_ATTR];

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
  CLPublicKey issuerKey;
  CLSignature signature;
  CLMessages attribute;
  CLProof proof;
  Byte flags;
  Byte size;
  int id;
} Credential;

typedef union {
  struct {
    Byte data[255]; // 255
    Byte session[SIZE_PUBLIC - 255]; // SIZE_PUBLIC - 255
  } apdu; // SIZE_PUBLIC

  struct {
    union {
      Nonce nonce; // 10
      Hash challenge; // 20
    } apdu; // 20
    union {
      Byte data[SIZE_VPRIME + SIZE_R_A]; // 138 + 138 = 276
      Number number[2]; // 256
    } buffer; // 276
    Hash context; // 20
    Value list[4]; // 16
    Byte rA[SIZE_R_A]; // 138
    Number APrime; // 128
    ResponseV vHat; // 231
    ResponseE eHat; // 45
  } prove; // 20 + 276 + 20 + 16 + 138 + 128 + 231 + 45 = 874

  struct {
    Number U; // 128
    union {
      Byte data[SIZE_BUFFER_C1]; // 307
      Number number[3]; // 384
    } buffer; // 384
    Value list[5]; // 20
    Nonce nonce; // 10
  } issue; // 128 + 384 + 20 + 10 = 542

  struct {
    Number ZPrime; // 128
    Number buffer; // 128
    Number tmp; // 128
  } vfySig; // 384

  struct {
    Byte buffer[SIZE_BUFFER_C2]; // 438
  } vfyPrf; // 438
} PublicData;

typedef union {
  struct {
    ResponseM mHat[SIZE_L]; // 62*6 (372)
    Byte disclose; // 1
  } prove; // 372 + 1 = 373

  struct {
    Hash challenge; // 20
    Byte sA[SIZE_S_A]; // 63
    Byte vPrime[SIZE_VPRIME]; // 138
    ResponseVPRIME vPrimeHat; // 168
  } issue; // 20 + 63 + 138 + 168 = 389

  struct {
    Value list[5]; // 20
    Hash challenge; // 20
    Number Q; // 128
    Number AHat; // 128
  } vfyPrf; // 20 + 20 + 128 + 128 = 296
} SessionData;

#endif // __defs_types_H
