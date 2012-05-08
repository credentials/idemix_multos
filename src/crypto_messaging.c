/**
 * crypto_messaging.c
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
 
#include "crypto_messaging.h"

#include <ISO7816.h>
#include <multoscomms.h>
#include <multoscrypto.h>

#include "defs_externals.h"

/********************************************************************/
/* Secure Messaging functions                                       */
/********************************************************************/

/**
 * Wrap a response APDU for secure messaging
 */
int crypto_wrap(void) {
  ByteArray apdu_p = apdu.data;
  // smallest multiple of 8 strictly larger than plaintextLen (length + padding)
  int do87DataLen = (short) ((((short) (length + 8)) / 8) * 8);
  // for 0x01 marker (indicating padding is used)
  do87DataLen++;
  int do87DataLenBytes = (short)(do87DataLen > 0xff? 2 : 1);
        short do87HeaderBytes = getApduBufferOffset(length);
        int do87Bytes = (int)(do87HeaderBytes + do87DataLen - 1); // 0x01 is counted twice 
        boolean hasDo87 = length > 0;

        INCN(SIZE_SSC, ssc);

        int ciphertextLength=0;
        if(hasDo87) {
            // Copy the plain text to temporary buffer to avoid data corruption.
            Util.arrayCopyNonAtomic(buffer, offset, tmp, (int) 0, length);
            // Put the cipher text in the proper position.
            ciphertextLength = cipher.doFinal(tmp, (int) 0, length, apdu, 
                    do87HeaderBytes);
        }
        //sanity check
        //note that this check
        //  (possiblyPaddedPlaintextLength != (int)(do87DataLen -1))
        //does not always hold because some algs do the padding in the final, some in the init.
        if (hasDo87 && (((int) (do87DataLen - 1) != ciphertextLength)))
            ExitSW(SW_INTERNAL_ERROR);
        
        if (hasDo87) {
            // build do87
            apdu[apdu_p++] = (byte) 0x87;
            if(do87DataLen < 0x80) {
                apdu[apdu_p++] = (byte)do87DataLen; 
            } else {
                apdu[apdu_p++] = (byte) (0x80 + do87DataLenBytes);
                for(int i = (int) (do87DataLenBytes - 1); i >= 0; i--) {
                    apdu[apdu_p++] = (byte) ((do87DataLen >>> (i * 8)) & 0xff);
                }
            }
            apdu[apdu_p++] = 0x01;
        }

        if(hasDo87) {
            apdu_p = do87Bytes;
        }
        
        // build do99
        apdu[apdu_p++] = (byte) 0x99;
        apdu[apdu_p++] = 0x02;
        Util.setint(apdu, apdu_p, status);
        apdu_p += 2;

        // calculate and write mac
        signer.update(ssc, (int) 0, (int) ssc.length);
        signer.sign(apdu, (int) 0, apdu_p, apdu, (int) (apdu_p + 2));

        // write do8e
        apdu[apdu_p++] = (byte) 0x8e;
        apdu[apdu_p++] = 0x08;
        apdu_p += 8; // for mac written earlier

        return apdu_p;
  
}

/**
 * Unwrap a command APDU from secure messaging
 */
#define buf apdu.data
int crypto_unwrap(void) {
  int i;
  int apdu_p = 0;
  int start_p = apdu_p;
  int le = 0;
  int do87DataLen = 0;
  int do87Data_p = 0;
  int do87LenBytes = 0;
  int hdrLen = 4;
  int hdrPadLen = 8 - hdrLen;

  INCN(SIZE_SSC, ssc);

  if (buf[apdu_p] == 0x87) {
    apdu_p++;
    // do87
    if (buf[apdu_p] > 0x80) {
      do87LenBytes = buf[apdu_p] & 0x7f;
      apdu_p++;
    } else {
      do87LenBytes = 1;
    }
    
    if (do87LenBytes > 2) ExitSW(SW_INTERNAL_ERROR); // sanity check
    
    for (i = 0; i < do87LenBytes; i++) {
      do87DataLen += buf[apdu_p + i] << (do87LenBytes - 1 - i) * 8;
    }
    apdu_p += do87LenBytes;

    if (buf[apdu_p] != 1) ExitSW(SW_INTERNAL_ERROR);
    
    // store pointer to data and defer decrypt to after mac check (do8e)
    do87Data_p = (int) (apdu_p + 1);
    apdu_p += do87DataLen;
    do87DataLen--; // compensate for 0x01 marker
  }

  if (buf[apdu_p] == (byte) 0x97) {
    // do97
    if (buf[++apdu_p] != 1) ExitSW(SW_INTERNAL_ERROR);
    
    le = buf[++apdu_p];
    apdu_p++;
  }

  // do8e
  if (buf[apdu_p] != 0x8e) ExitSW(SW_INTERNAL_ERROR);
  
  if (buf[++apdu_p] != 8) ExitSW(ISO7816_SW_DATA_INVALID);

  // verify mac
  verifier.update(ssc, 0, SIZE_SSC);
  verifier.update(buf, 0, hdrLen);
  verifier.update(PAD_DATA, 0, hdrPadLen);
  if (!verifier.verify(buf, start_p, apdu_p - 1 - start_p, buf, apdu_p + 1, MAC_SIZE)) {
    ExitSW(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
  }

  int lc = 0;
  if (do87DataLen != 0) {
    // decrypt data, and leave room for lc
    lc = decipher.doFinal(buf, do87Data_p, do87DataLen, buf, hdrLen + 1);
    buf[hdrLen] = lc;
  }

  return le;  
}

        signer = Signature.getInstance(
                Signature.ALG_DES_MAC8_ISO9797_1_M2_ALG3, false);
        decipher = Cipher.getInstance(
                Cipher.ALG_DES_CBC_ISO9797_M2, false);
        
        keyMAC = (DESKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_DES_TRANSIENT_DESELECT, 
                KeyBuilder.LENGTH_DES3_2KEY, false);
    
    /***
     * Get the amount of space to reserve in the buffer when using secure 
     * messaging.
     * 
     * @param length length of plain text in which this offset depends.
     * @return the amount of space to reserve.
     */
    private short getApduBufferOffset(short length) {
        short do87Bytes = 2; // 0x87 length data 0x01
        // smallest multiple of 8 strictly larger than plaintextLen + 1
        // byte is probably the length of the cipher text (including do87 0x01)
        short do87DataLen = (short) ((((short) (length + 8) / 8) * 8) + 1);        
        
        if (do87DataLen < 0x80) {
            do87Bytes++;
        } else if (do87DataLen <= 0xff) {
            do87Bytes += 2;
        } else {
            do87Bytes += (short) (length > 0xff ? 2 : 1);
        }
        
        return do87Bytes;
    }
