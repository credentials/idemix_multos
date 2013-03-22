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

#define NULL 0x0000

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
  Byte size;
  int flags;
  int id;
} Credential;

typedef struct {
  Byte code[SIZE_PIN_MAX];
  Byte minSize;
  Byte count;
  Byte flag;
} PIN;

typedef struct {
  Byte timestamp[SIZE_TIMESTAMP];
  Byte terminal[SIZE_TERMINAL_ID];
  Byte action;
  int credential;
  union {
    struct {
      int selection;
    } prove;
    Byte data[5];
  } details;
} LogEntry;

#define ACTION_ISSUE 0x01;
#define ACTION_PROVE 0x02;
#define ACTION_REMOVE 0x03;

typedef union {
  Byte base[1];

  struct {
    Byte data[255]; // 255
    Byte session[SIZE_PUBLIC - 255]; // SIZE_PUBLIC - 255
  } apdu; // SIZE_PUBLIC

  struct {
	int id;
	Hash context;
	int selection;
	Byte timestamp[SIZE_TIMESTAMP];
	Byte terminal[SIZE_TERMINAL_ID];
  } verificationSetup;

  struct {
    union {
      Nonce nonce; // 10
      Hash challenge; // 20
    } apdu; // 20
    union {
      Byte data[SIZE_BUFFER_C1]; // 319
      Number number[2]; // 256
    } buffer; // 319
    Hash context; // 20
    Value list[4]; // 16
    Byte rA[SIZE_R_A]; // 138
    Number APrime; // 128
    ResponseV vHat; // 231
    ResponseE eHat; // 45
  } prove; // 20 + 307 + 20 + 16 + 138 + 128 + 231 + 45 = 905

  struct {
	int id;
	Hash context;
	int size;
	int flags;
	Byte timestamp[SIZE_TIMESTAMP];
  } issuanceSetup;
  
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
  Byte base[1];

  struct {
    ResponseM mHat[SIZE_L]; // 74*6 (444)
    int disclose; // 2
#ifdef SIMULATOR
    // Store values to work around the simulator clearing public
    Hash context; // 32
    Number APrime; // 128
    ResponseV vHat; // 255
    ResponseE eHat; // 57
#endif // SIMULATOR
  } prove; // 444 + 2 = 446 (444 + 2 + 32 + 128 + 255 + 57 = 918)

  struct {
    Hash challenge; // 32
    Byte sHat[SIZE_S_]; // 75
    Byte vPrime[SIZE_VPRIME]; // 138
    ResponseVPRIME vPrimeHat; // 180
  } issue; // 32 + 75 + 138 + 180 = 425

  struct {
    Value list[5]; // 20
    Hash challenge; // 32
    Number Q; // 128
    Number AHat; // 128
  } vfyPrf; // 20 + 32 + 128 + 128 = 308
} SessionData;

#endif // __defs_types_H
