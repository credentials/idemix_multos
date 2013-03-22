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

/**
 * Verify a PIN code
 *
 * @param buffer which contains the code to verify
 */
void pin_verify(PIN* pin, ByteArray buffer) {
  // Verify if the PIN has not been blocked
  if (pin->count == 0) {
    ReturnSW(ISO7816_SW_COUNTER_PROVIDED_BY_X(0));
  }

  // Compare the PIN with the stored code
  if (memcmp(buffer, pin->code, SIZE_PIN_MAX) != 0) {
    debugWarning("PIN verification failed");
    debugInteger("Tries left", pin->count - 1);
    ReturnSW(ISO7816_SW_COUNTER_PROVIDED_BY_X(0) | --(pin->count));
  } else {
    debugMessage("PIN verified ");
    pin->count = PIN_COUNT;
    flags |= pin->flag;
  }
}

/**
 * Modify a PIN code
 *
 * @param buffer which contains the old and new code
 */
void pin_update(PIN* pin, ByteArray buffer) {
  int i;
  
  // Verify the original PIN
  pin_verify(pin, buffer);

  // Verify the new PIN size
  for (i = 0; i < pin->minSize; i++) {
	  if (buffer[SIZE_PIN_MAX + i] == 0x00) {
		  ReturnSW(ISO7816_SW_WRONG_LENGTH);
	  }
  }

  // Store the new code
  memcpy(pin->code, buffer + SIZE_PIN_MAX, SIZE_PIN_MAX);
}
