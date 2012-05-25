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

extern APDUData apdu;

extern CLMessage masterSecret;
extern Credential *credential;

extern Byte disclose;
extern Hash context;
extern Nonce nonce;
extern Challenge challenge;
extern ResponseE eHat;
extern ResponseM mHat[SIZE_L];
extern ResponseV vHat;

extern CLSignature signature_;
extern Number numa, numb;

extern Byte key_enc[SIZE_KEY];
extern Byte key_mac[SIZE_KEY];

extern Byte iv[SIZE_IV];
extern Byte ssc[SIZE_SSC];

#endif // __defs_externals_H
