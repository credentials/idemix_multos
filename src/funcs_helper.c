/**
 * funcs_helper.c
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

#include "funcs_helper.h"

#include <ISO7816.h>
#include <multosarith.h>
#include <string.h> // for memcpy()

#include "defs_apdu.h"
#include "defs_externals.h"
#include "funcs_debug.h"

/********************************************************************/
/* Helper functions                                                 */
/********************************************************************/

/**
 * Encode the given length using ASN.1 DER formatting.
 * 
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 * 
 * @param length value to be encoded
 * @param buffer to store the DER formatted length
 * @param offset in front of which the length should be stored
 * @return the offset of the encoded length in the buffer
 */
int asn1_encode_length(int length, ByteArray buffer, int offset) {
  Byte prefix = 0x80;
  
  // Use the short form when the length is between 0 and 127
  if (length < 0x80) {
    buffer[--offset] = (Byte) length;

  // Use the long form when the length is 128 or greater
  } else {
    while (length > 0) {
      buffer[--offset] = (Byte) length;
      length >>= 8;
      prefix++;
    }
    
    buffer[--offset] = prefix;
  }
  
  return offset;
}

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
int asn1_encode_int(ByteArray number, int length, 
                    ByteArray buffer, int offset) {
  int skip = 0;

  // Determine the number of zero (0x00) bytes to skip
  while(number[skip] == 0x00 && skip < length - 1) {
    skip++;
  }
  
  // Store the value
  length -= skip;
  offset -= length;
  memcpy(buffer + offset, number + skip, length);
  
  // If needed, add a 0x00 byte for correct two-complements encoding
  if ((buffer[offset] & 0x80) != 0x00) {
    debugMessage("Correcting value for two-complements encoding");
    buffer[--offset] = 0x00;
    length++;
  }
  
  // Store the length
  offset = asn1_encode_length(length, buffer, offset);
  
  // Store the tag
  buffer[--offset] = 0x02; // ASN.1 INTEGER

  return offset;
}

/**
 * Encode the given sequence (of length bytes) into an ASN.1 DER object.
 * 
 * DER encoding rules standard (ITU-T Rec. X.690 | ISO/IEC 8825-1):
 * http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 * 
 * Note: In order for the result to be a valid DER object, the value for
 * this sequence must be in the buffer at the given offset.
 * 
 * @param length of the sequence stored in the buffer (in bytes)
 * @param size of the sequence stored in the buffer (number of items)
 * @param buffer to store the DER object
 * @param offset in front of which the object should be stored
 * @return the offset of the encoded object in the buffer
 */
int asn1_encode_seq(int length, int size, ByteArray buffer, int offset) {  
  // Store the length
  offset = asn1_encode_length(length, buffer, offset);
  
  // Store the tag
  buffer[--offset] = 0x30; // ASN.1 SEQUENCE

  return offset;
}

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
    pinOK = 0xFF;
  }
}

/**
 * Update a PIN code
 *
 * @param buffer which contains the new code
 */
void pin_update(ByteArray buffer) {
  if (!pinOK) {
    ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
  }
  COPYN(SIZE_PIN, pinCode, apdu.data);
}
