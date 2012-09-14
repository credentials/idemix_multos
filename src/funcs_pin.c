/**
 * funcs_pin.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, May 2012.
 */

#include "funcs_pin.h"

#include <ISO7816.h>
#include <multosarith.h>
#include <string.h>

#include "defs_apdu.h"
#include "defs_externals.h"
#include "funcs_debug.h"

// Card holder verification
Byte pinCode[SIZE_PIN] = { 0x30, 0x30, 0x30, 0x30 };
Byte pinCount = PIN_COUNT;

/**
 * Verify a PIN code
 * 
 * @param buffer which contains the code to verify
 */
void pin_verify(ByteArray buffer) {
  // Verify if the PIN has not been blocked
  if (pinCount == 0) {
    ReturnSW(ISO7816_SW_COUNTER_PROVIDED_BY_X(0));
  }
  
  // Compare the PIN with the stored code
  if (memcmp(buffer, pinCode, SIZE_PIN) != 0) {
    debugWarning("PIN verification failed");
    debugInteger("Tries left", pinCount - 1);
    ReturnSW(ISO7816_SW_COUNTER_PROVIDED_BY_X(0) | --pinCount);
  } else {
    debugMessage("PIN verified ");
    pinCount = PIN_COUNT;
    flags |= PIN_OK;
  }
}

/**
 * Modify a PIN code
 *
 * @param buffer which contains the old and new code
 */
void pin_modify(ByteArray buffer) {
  pin_verify(buffer);

  if (memcmp(buffer, buffer + SIZE_PIN, SIZE_PIN) == 0) {
    // This is not a modification
    ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
  } else {
    // Store the new code
    COPYN(SIZE_PIN, pinCode, buffer + SIZE_PIN);
  }
}
