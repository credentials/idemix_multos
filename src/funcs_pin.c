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
void pin_verify(PIN* pin, ByteArray buffer, Byte size) {
  // Verify if the PIN has not been blocked
  if (pin->count == 0) {
    ReturnSW(ISO7816_SW_COUNTER_PROVIDED_BY_X(0));
  }

  // Verify the PIN size
  if (pin->size != size) {
    ReturnSW(ISO7816_SW_WRONG_LENGTH);
  }

  // Compare the PIN with the stored code
  if (memcmp(buffer, pin->code, pin->size) != 0) {
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
 * Update a PIN code
 *
 * @param buffer which contains the new code
 */
void pin_update(PIN* pin, ByteArray buffer, Byte size) {
  // Verify the PIN size and original PIN
  if (size < SIZE_PIN_MAX + pin->minSize || size > 2*SIZE_PIN_MAX) {
    ReturnSW(ISO7816_SW_WRONG_LENGTH);
  }
  pin_verify(pin, buffer, pin->size);

  // Determine the new PIN size
  pin->size = size - SIZE_PIN_MAX;

  // Store the new code
  memcpy(pin->code, buffer + SIZE_PIN_MAX, pin->size);
}
