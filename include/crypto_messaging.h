/**
 * crypto_messaging.h
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
 
#ifndef __crypto_messaging_H
#define __crypto_messaging_H

#include "defs_types.h"

/**
 * Unwrap an incomming command APDU from secure messaging
 */
void crypto_unwrap(void);

/**
 * Wrap an outgoing response APDU for secure messaging
 */
void crypto_wrap(void);

/**
 * Add padding to the input data according to ISO7816-4
 * 
 * @param data that needs to be padded
 * @param size of the data that needs to be padded
 * @return the new size of the data including padding  
 */
uint pad(ByteArray data, int size);

/**
 * Remove padding from the input data according to ISO7816-4
 * 
 * @param data that contains padding
 * @param size of the data including padding
 * @return the new size of the data excluding padding  
 */
uint unpad(ByteArray data, int size);

#define INVALID_PADDING 0xffff;

/**
 * Perform card authentication and secure messaging setup
 */
void crypto_authenticate_card(void);

#endif // __crypto_messaging_H
