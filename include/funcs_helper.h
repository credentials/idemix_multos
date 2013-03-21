/**
 * funcs_helper.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, July 2011.
 */

#ifndef __funcs_helper_H
#define __funcs_helper_H

#include "defs_types.h"

/**
 * Encode the given number (of length bytes) into an ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * @param number the value to be encoded
 * @param length of the value stored in number
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
int asn1_encode_int(ByteArray number, int length, ByteArray buffer, int offset);

/**
 * Encode the given sequence (of length bytes) into an ASN.1 DER object.
 *
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 *
 * Note: In order for the result to be a valid DER object, the value for
 * this sequence must be in the buffer at the given offset.
 *
 * @param length of the sequence stored in the buffer
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
int asn1_encode_seq(int length, int size, ByteArray buffer, int offset);

/**
 * Clear size bytes from a bytearray
 *
 * @param size the amount of bytes to clear
 * @param buffer to be cleared
 */
void clear(int size, ByteArray buffer);

#define log_new_entry() \
  log = &logList[logHead]; \
  logHead = (logHead + 1) % SIZE_LOG;
// FIXME: CLEAR this log entry.

#define log_get_entry(index) \
  log = &logList[(2*SIZE_LOG + logHead - 1 - ((index) % SIZE_LOG)) % SIZE_LOG];

#endif // __funcs_helper_H
