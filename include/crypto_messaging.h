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

/**
 * Unwrap an incomming command APDU from secure messaging
 */
void crypto_unwrap(void);

/**
 * Wrap an outgoing response APDU for secure messaging
 */
void crypto_wrap(void);

#endif // __crypto_messaging_H
