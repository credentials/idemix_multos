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

#define SW_INTERNAL_ERROR 0x6D66
#define TMP_SIZE 256
#define MAC_SIZE 8
#define KEY_SIZE 16

Byte[] PAD_DATA = { 0x80, 0, 0, 0, 0, 0, 0, 0 };

/**
 * Wrap a response APDU for secure messaging
 */
int crypto_wrap(void);

/**
 * Unwrap a command APDU from secure messaging
 */
int crypto_unwrap(void);

#endif // __crypto_messaging_H
