/**
 * crypto_messaging.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012.
 */
 
#include "crypto_messaging.h"

#include <DES.h>
#include <ISO7816.h>
#include <multosarith.h>
#include <multoscrypto.h>
#include <string.h>

#include "defs_apdu.h"
#include "defs_externals.h"
#include "crypto_helper.h"
#include "funcs_debug.h"

/********************************************************************/
/* Secure Messaging functions                                       */
/********************************************************************/

/**
 * Unwrap a command APDU from secure messaging
 */
#define buffer apdu.data
#define tmp (apdu.public + 255)
void crypto_unwrap(void) {
  Byte mac[SIZE_MAC];
  int i;
  int offset = 0;
  int do87DataLen = 0;
  int do87Data_p = 0;
  int do87LenBytes = 0;

  INCN(SIZE_SSC, ssc);

  if (buffer[offset] == 0x87) { // do87
    if (buffer[++offset] > 0x80) {
      do87LenBytes = buffer[offset++] & 0x7f;
    } else {
      do87LenBytes = 1;
    }
    
    for (i = 0; i < do87LenBytes; i++) {
      do87DataLen += buffer[offset + i] << (do87LenBytes - 1 - i) * 8;
    }
    offset += do87LenBytes;

    if (buffer[offset++] != 0x01) ExitSW(ISO7816_SW_WRONG_DATA);
    do87DataLen--; // compensate for 0x01 marker
    
    // store pointer to data and defer decrypt to after mac check (do8e)
    do87Data_p = offset;
    offset += do87DataLen;
  }

  if (buffer[offset] == 0x97) { // do97
    if (buffer[++offset] != 0x01) ExitSW(ISO7816_SW_WRONG_DATA);
    Le = buffer[++offset];
    offset++;
  }

  // do8e
  if (buffer[offset] != 0x8e) ExitSW(ISO7816_SW_WRONG_DATA);
  if (buffer[offset + 1] != 8) ExitSW(ISO7816_SW_DATA_INVALID);

  // verify mac
  i = 0;
  
  // SSC
  COPYN(SIZE_SSC, tmp, ssc); 
  i += SIZE_SSC;
  
  // Header
  tmp[i++] = CLA;
  tmp[i++] = INS;
  tmp[i++] = P1;
  tmp[i++] = P2;
  
  // Padding
  i = pad(tmp, i);
  
  // Cryptogram (do87 and do97)
  memcpy(tmp + i, buffer, offset);
  do87Data_p += i;
  i += offset;
  
  // Padding
  i = pad(tmp, i);

  // Verify the MAC
  GenerateTripleDESCBCSignature(i, iv, key_mac, mac, tmp);
  if (memcmp(mac, buffer + offset + 2, SIZE_MAC) != 0) {
    ExitSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
  }

  // Decrypt data if available
  if (do87DataLen != 0) {
    TripleDES2KeyCBCDecipherMessageNoPad(do87DataLen, tmp + do87Data_p, iv, key_enc, buffer);
    Lc = unpad(buffer, do87DataLen);
    if (Lc > do87DataLen) {
      ExitSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
    }
  }
}
#undef buffer
#undef tmp

/**
 * Wrap a response APDU for secure messaging
 */
#define buffer apdu.data
#define tmp (apdu.public + 255)
#define hasDo87 (La > 0)
#define do87DataLenBytes (La > 0xff ? 2 : 1)
#define do87DataLen (La + 1)
void crypto_wrap(void) {
  int i, offset = 0;

  INCN(SIZE_SSC, ssc);

  if(hasDo87) {
    // Padding
    La = pad(buffer, La);
    
    // Build do87 header
    tmp[offset++] = 0x87;
    if(do87DataLen < 0x80) {
      tmp[offset++] = do87DataLen; 
    } else {
      tmp[offset++] = 0x80 + do87DataLenBytes;
      for(i = do87DataLenBytes - 1; i >= 0; i--) {
        tmp[offset++] = do87DataLen >> (i * 8);
      }
    }
    tmp[offset++] = 0x01;

    // Build the do87 data
    TripleDES2KeyCBCEncipherMessageNoPad(La, buffer, iv, key_enc, tmp + offset);
    offset += La;
  }
        
  // build do99
  tmp[offset++] = 0x99;
  tmp[offset++] = 0x02;
  tmp[offset++] = SW1;
  tmp[offset++] = SW2;
  
  // padding
  i = pad(tmp, offset);

  // calculate and write mac
  COPYN(SIZE_SSC, tmp - SIZE_SSC, ssc);
  GenerateTripleDESCBCSignature(i + SIZE_SSC, iv, key_mac, buffer + offset + 2, tmp - SIZE_SSC);
  
  // write do8e
  tmp[offset++] = 0x8e;
  tmp[offset++] = 0x08;
  La = offset + 8; // for mac written earlier
  
  // Put it all in the buffer (the mac is already there)
  memcpy(buffer, tmp, offset);
}
#undef buffer
#undef tmp
#undef hadDo87
#undef do87DataLenBytes
#undef do87DataLen
