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
#define ISO7816_INS_CHANGE_REFERENCE_DATA 0x24

// Command APDU definitions
#define CLA_IRMACARD               0x80

#define INS_GENERATE_SECRET        0x01
#define INS_AUTHENTICATION_SECRET  0x02

#define INS_ISSUE_CREDENTIAL       0x10
#define INS_ISSUE_PUBLIC_KEY       0x11
#define INS_ISSUE_ATTRIBUTES       0x12

#define INS_ISSUE_COMMITMENT       0x1A
#define INS_ISSUE_COMMITMENT_PROOF 0x1B
#define INS_ISSUE_CHALLENGE        0x1C
#define INS_ISSUE_SIGNATURE        0x1D
#define INS_ISSUE_SIGNATURE_PROOF  0x1E

#define INS_PROVE_CREDENTIAL       0x20

#define INS_PROVE_COMMITMENT       0x2A
#define INS_PROVE_SIGNATURE        0x2B
#define INS_PROVE_ATTRIBUTE        0x2C

#define INS_ADMIN_CREDENTIAL       0x30
#define INS_ADMIN_REMOVE           0x31
#define INS_ADMIN_ATTRIBUTE        0x32
#define INS_ADMIN_FLAGS            0x33

#define INS_ADMIN_CREDENTIALS      0x3A
#define INS_ADMIN_LOG              0x3B

#define P1_AUTHENTICATION_EXPONENT 0x00
#define P1_AUTHENTICATION_MODULUS  0x01

#define P1_PUBLIC_KEY_N 0x00
#define P1_PUBLIC_KEY_S 0x01
#define P1_PUBLIC_KEY_Z 0x02
#define P1_PUBLIC_KEY_R 0x03

#define P2_CRED_PIN             0x00
#define P2_CARD_PIN             0x01

#define P1_PROOF_VERIFY       0x00
#define P1_PROOF_C            0x01
#define P1_PROOF_VPRIMEHAT    0x02
#define P1_PROOF_SHAT         0x03
#define P1_PROOF_S_E          0x04

#define P1_SIGNATURE_VERIFY     0x00
#define P1_SIGNATURE_A          0x01
#define P1_SIGNATURE_E          0x02
#define P1_SIGNATURE_V          0x03


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
