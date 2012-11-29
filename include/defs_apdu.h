/**
 * defs_apdu.h
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

#ifndef __defs_apdu_H
#define __defs_apdu_H

#include <multoscomms.h>

#include "crypto_messaging.h"

// Incorrect constant name in ISO7816.h, so just define it here
#define ISO7816_INS_GET_CHALLENGE 0x84
#define ISO7816_INS_CHANGE_REFERENCE_DATA 0x24

// Command APDU definitions
#define CLA_IDEMIX              0x80

#define INS_SELECT_CREDENTIAL   0x00
#define INS_GENERATE_SECRET     0x01
#define INS_RSA_SECRET          0x02

#define INS_ISSUE_CREDENTIAL    0x10

#define INS_ISSUE_PUBLIC_KEY_N  0x11
#define INS_ISSUE_PUBLIC_KEY_Z  0x12
#define INS_ISSUE_PUBLIC_KEY_S  0x13
#define INS_ISSUE_PUBLIC_KEY_R  0x14
#define INS_ISSUE_ATTRIBUTES    0x15
#define INS_ISSUE_FLAGS         0x1B

#define INS_ISSUE_NONCE_1       0x16
#define INS_ISSUE_PROOF_U       0x17
#define INS_ISSUE_NONCE_2       0x18
#define INS_ISSUE_SIGNATURE     0x19
#define INS_ISSUE_PROOF_A       0x1A

#define INS_PROVE_CREDENTIAL    0x20

#define INS_PROVE_SELECTION     0x21
#define INS_PROVE_NONCE         0x22
#define INS_PROVE_SIGNATURE     0x23
#define INS_PROVE_ATTRIBUTE     0x24
#define INS_PROVE_RESPONSE      0x25

#define INS_ADMIN_CREDENTIAL    0x30
#define INS_ADMIN_CREDENTIALS   0x31
#define INS_ADMIN_ATTRIBUTE     0x32
#define INS_ADMIN_REMOVE        0x33
#define INS_ADMIN_FLAGS         0x34
#define INS_ADMIN_LOG           0x35

#define P1_RSA_EXPONENT         0x00
#define P1_RSA_MODULUS          0x01

#define P1_CARD_PIN             0x01
#define P1_CRED_PIN             0x00

#define P1_PROOF_U_C            0x00
#define P1_PROOF_U_VPRIMEHAT    0x01
#define P1_PROOF_U_S_A          0x02

#define P1_SIGNATURE_A          0x00
#define P1_SIGNATURE_E          0x01
#define P1_SIGNATURE_V          0x02
#define P1_SIGNATURE_VERIFY     0x03

#define P1_PROOF_A_C            0x00
#define P1_PROOF_A_S_E          0x01
#define P1_PROOF_A_VERIFY       0x02

#define wrapped ((CLA & 0x0C) != 0)

#define ReturnSW(sw) {\
  SetSW((sw)); \
  if (wrapped) { crypto_wrap(); } \
  Exit(); \
}

#define ReturnLa(sw,len) {\
  SetSWLa((sw), (len)); \
  if (wrapped) { crypto_wrap(); } \
  Exit(); \
}

#endif // __defs_apdu_H
