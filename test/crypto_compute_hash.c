/**
 * crypto_compute_hash.c
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope t_ it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 * 
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, December 2011.
 */

// Name everything "idemix"
#pragma attribute("aid", "69 64 65 6D 69 78")
#pragma attribute("dir", "61 10 4f 6 69 64 65 6D 69 78 50 6 69 64 65 6D 69 78")

#include <ISO7816.h>
#include <multosarith.h> // for COPYN()
#include <multoscomms.h>

#include "defs_sizes.h"
#include "defs_types.h"
#include "crypto_helper.h"

/********************************************************************/
/* APDU buffer variable declaration                                 */
/********************************************************************/
#pragma melpublic

union {
  Byte data[255];
  Number number;
  Nonce nonce;
  Hash hash;
} apdu;


/********************************************************************/
/* RAM variable declaration                                         */
/********************************************************************/
#pragma melsession

struct {
  Hash context;
  Number U;
  Number U_;
  Nonce nonce;
  Byte buffer[SIZE_BUFFER_C1];
} ram;


/********************************************************************/
/* EEPROM variable declarations                                     */
/********************************************************************/
#pragma melstatic


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
  Value numbers[4];
  
  switch (INS) {
    case 0x01:
      COPYN(SIZE_H, ram.context, apdu.hash);
      ExitSW(ISO7816_SW_NO_ERROR);
      
    case 0x02:
      COPYN(SIZE_N, ram.U, apdu.number);
      ExitSW(ISO7816_SW_NO_ERROR);

    case 0x03:
      COPYN(SIZE_N, ram.U_, apdu.number);
      ExitSW(ISO7816_SW_NO_ERROR);

    case 0x04:
      COPYN(SIZE_STATZK, ram.nonce, apdu.nonce);
      ExitSW(ISO7816_SW_NO_ERROR);

    case 0x10:
      numbers[0].data = ram.context;
      numbers[0].size = SIZE_H;
      numbers[1].data = ram.U;
      numbers[1].size = SIZE_N;
      numbers[2].data = ram.U_;
      numbers[2].size = SIZE_N;
      numbers[3].data = ram.nonce;
      numbers[3].size = SIZE_STATZK;
      crypto_compute_hash(numbers, 4, apdu.hash, ram.buffer, SIZE_BUFFER_C1);
      ExitLa(SIZE_H);
      break;
    
    // Unknown instruction
    default:
      ExitSW(ISO7816_SW_INS_NOT_SUPPORTED);
  }
}
