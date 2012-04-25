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

extern CLPublicKey issuerKey;
extern CLSignature signature;
extern CLMessages messages;
extern Hash context;
extern int attributes;

extern Byte buffer[3*SIZE_VPRIME];//SIZE_BUFFER_C1 + SIZE_H];
extern Byte D[SIZE_L];
extern Nonce nonce;
extern Challenge challenge;
extern ResponseE eHat;
extern ResponseM mHat[SIZE_L];
extern ResponseV vHat;
extern ResponseVPRIME vPrimeHat;
extern CLSignature signature_;

extern Number Q, R, U_;
extern Value values[5];

#endif // __defs_externals_H

