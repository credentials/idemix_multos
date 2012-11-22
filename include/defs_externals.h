/**
 * defs_externals.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, July 2011.
 */

#ifndef __defs_externals_H
#define __defs_externals_H

#include "defs_types.h"

// Idemix: protocol public variables
extern PublicData public;

// Idemix: protocol session variables
extern SessionData session;
extern Credential *credential;
extern Byte flags;
extern Byte flag;

// Idemix: master secret
extern CLMessage masterSecret;

// Secure messaging: send sequence counter and session keys
extern Byte ssc[SIZE_SSC];
extern Byte key_enc[SIZE_KEY];
extern Byte key_mac[SIZE_KEY];

// Card authentication: private key and modulus
extern Byte rsaExponent[SIZE_RSA_EXPONENT];
extern Byte rsaModulus[SIZE_RSA_MODULUS];

// Secure messaging: initialisation vector
extern Byte iv[SIZE_IV];

// Card holder verification: PIN
extern PIN cardPIN;
extern PIN credPIN;

// Logging
extern LogEntry *log;

#endif // __defs_externals_H
