/**
 * crypto_compute_vhat.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, January 2012.
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
} apdu;


/********************************************************************/
/* RAM variable declaration                                         */
/********************************************************************/
#pragma melsession


struct {
  Byte pre[SIZE_VPRIME/2 - SIZE_H];
  Challenge c;
} challenge;
Byte vPrime[SIZE_VPRIME];
ResponseV vHat;
Byte buffer[SIZE_VPRIME_ + SIZE_VPRIME];
CLMessages messages;
ResponseM mHat[SIZE_L];

/********************************************************************/
/* EEPROM variable declarations                                     */
/********************************************************************/
#pragma melstatic


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
  switch (INS) {
    case 0x01:
      COPYN(SIZE_H, challenge.c, apdu.data);
      ExitSW(ISO7816_SW_NO_ERROR);
      
    case 0x02:
      COPYN(SIZE_VPRIME, vPrime, apdu.data);
      ExitSW(ISO7816_SW_NO_ERROR);

    case 0x03:
      COPYN(SIZE_VPRIME_, vHat, apdu.data);
      ExitSW(ISO7816_SW_NO_ERROR);

    case 0x10:
      crypto_compute_vHat(challenge.pre, vPrime);
      COPYN(SIZE_VPRIME_, apdu.data, vHat);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_VPRIME_);
      break;
    
    // Unknown instruction
    default:
      ExitSW(ISO7816_SW_INS_NOT_SUPPORTED);
  }
}
