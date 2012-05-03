/**
 * idemix.c
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

// Name everything "idemix"
#pragma attribute("aid", "69 64 65 6D 69 78")
#pragma attribute("dir", "61 10 4f 6 69 64 65 6D 69 78 50 6 69 64 65 6D 69 78")

#include <ISO7816.h>
#include <multosarith.h> // for COPYN()
#include <multoscomms.h>
#include <string.h> // for memcmp()

#include "defs_apdu.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"
#include "crypto_issuing.h"
#include "crypto_proving.h"

/********************************************************************/
/* APDU buffer variable declaration                                 */
/********************************************************************/
#pragma melpublic

APDUData apdu;


/********************************************************************/
/* RAM variable declaration                                         */
/********************************************************************/
#pragma melsession

Byte buffer[SIZE_BUFFER_C2]; // 438
Hash context; // + 20 = 458
Nonce nonce; // + 10 = 468
Challenge challenge; // + 69 = 537


/********************************************************************/
/* EEPROM variable declarations                                     */
/********************************************************************/
#pragma melstatic

// Issuer parameters
CLPublicKey issuerKey;

// Credential storage
int attributes;
CLMessages messages;
CLSignature signature;

// Shared protocol variables
ResponseE eHat;
ResponseM mHat[SIZE_L];
ResponseV vHat;
ResponseVPRIME vPrimeHat;
Number Q, R, s_e;
CLSignature signature_;
Byte D[SIZE_L];
Byte rA[SIZE_R_A];

Value values[5];
Number U_; 

#ifdef TEST
int m_count = 0;
int r_count = 0;
#endif // TEST


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
  if (CLA != CLA_IDEMIX) {
    ExitSW(ISO7816_SW_CLA_NOT_SUPPORTED);
  }
  
  switch (INS) {
    // Initialisation instructions
    case INS_SET_PUBLIC_KEY_N:
      debugMessage("INS_SET_PUBLIC_KEY_N");
      if (!(CheckCase(3) && Lc == SIZE_N)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, issuerKey.n, apdu.data);
      debugValue("Initialised isserKey.n", issuerKey.n, SIZE_N);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_PUBLIC_KEY_Z:
      debugMessage("INS_SET_PUBLIC_KEY_Z");
      if (!(CheckCase(3) && Lc == SIZE_N)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, issuerKey.Z, apdu.data);
      debugValue("Initialised isserKey.Z", issuerKey.Z, SIZE_N);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_PUBLIC_KEY_S:
      debugMessage("INS_SET_PUBLIC_KEY_S");
      if (!(CheckCase(3) && Lc == SIZE_N)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, issuerKey.S, apdu.data);
      debugValue("Initialised isserKey.S", issuerKey.S, SIZE_N);
      crypto_compute_S_();
      debugValue("Initialised isserKey.S_", issuerKey.S_, SIZE_N);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_PUBLIC_KEY_R:
      debugMessage("INS_SET_PUBLIC_KEY_R");
      if (!(CheckCase(3) && Lc == SIZE_N)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 > MAX_ATTR) ExitSW(ISO7816_SW_WRONG_P1P2);
      COPYN(SIZE_N, issuerKey.R[P1], apdu.data);
      debugNumberI("Initialised isserKey.R", issuerKey.R, P1);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_CONTEXT:
      debugMessage("INS_SET_CONTEXT");
      if (!(CheckCase(3) && Lc == SIZE_H)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_H, context, apdu.data);
      debugValue("Initialised context", context, SIZE_H);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_MASTER_SECRET:
      debugMessage("INS_SET_MASTER_SECRET");
      if (!(CheckCase(3) && Lc == SIZE_M)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_M, messages[0], apdu.data);
      debugCLMessageI("Initialised messages", messages, 0);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_ATTRIBUTES:
      debugMessage("INS_SET_ATTRIBUTES");
      if (!(CheckCase(3) && Lc == SIZE_M)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 == 0 || P1 > MAX_ATTR) ExitSW(ISO7816_SW_WRONG_P1P2);
      // Do not allow NULL values
      CLEARN(SIZE_M, buffer);
      if (memcmp(buffer, apdu.data, SIZE_M) == 0) ExitSW(ISO7816_SW_WRONG_DATA);
      COPYN(SIZE_M, messages[P1], apdu.data);
      debugCLMessageI("Initialised messages", messages, P1);
      // TODO: Implement some proper handling of the number of attributes
      if (P1 > attributes) {
        attributes = P1;
      }
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
    
    // Personalisation / Issuance instructions
    case INS_ISSUE_NONCE_1:
      debugMessage("INS_ISSUE_NONCE_1");
      if (!(CheckCase(3) && Lc == SIZE_STATZK)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_STATZK, nonce, apdu.data);
      debugValue("Initialised nonce", nonce, SIZE_STATZK);
      constructCommitment(signature.v + SIZE_V - SIZE_VPRIME, apdu.number);
      debugValue("Returned U", apdu.data, SIZE_N);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
      
    case INS_ISSUE_PROOF_U:
      debugMessage("INS_ISSUE_PROOF_U");
      switch (P1) {
        case P1_PROOF_U_C:
          debugMessage("P1_PROOF_U_C");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_H, apdu.data, challenge.c);
          debugValue("Returned c", apdu.data, SIZE_H);
          ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_H);
          break;
          
        case P1_PROOF_U_VPRIMEHAT:
          debugMessage("P1_PROOF_U_VPRIMEHAT");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_VPRIME_, apdu.data, vPrimeHat);
          debugValue("Returned vPrimeHat", apdu.data, SIZE_VPRIME_);
          ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_VPRIME_);
          break;
          
        case P1_PROOF_U_S_A:
          debugMessage("P1_PROOF_U_S_A");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_S_A, apdu.data, mHat[0]);
          debugValue("Returned s_A", apdu.data, SIZE_S_A);
          ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_S_A);
          break;
        
        default:
          debugWarning("Unknown parameter");
          ExitSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;
      
    case INS_ISSUE_NONCE_2:
      debugMessage("INS_ISSUE_NONCE_2");
      COPYN(SIZE_STATZK, apdu.data, nonce);
      debugValue("Returned nonce", apdu.data, SIZE_STATZK);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_STATZK);
      break;
    
    case INS_ISSUE_SIGNATURE:
      debugMessage("INS_ISSUE_SIGNATURE");
      switch(P1) {
        case P1_SIGNATURE_A:
          debugMessage("P1_SIGNATURE_A");
          if (!(CheckCase(3) && Lc == SIZE_N)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_N, signature.A, apdu.data);
          debugValue("Initialised signature.A", signature.A, SIZE_N);
          ExitSW(ISO7816_SW_NO_ERROR);
          break;

        case P1_SIGNATURE_E:
          debugMessage("P1_SIGNATURE_E");
          if (!(CheckCase(3) && Lc == SIZE_E)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_E, signature.e, apdu.data);
          debugValue("Initialised signature.e", signature.e, SIZE_E);
          ExitSW(ISO7816_SW_NO_ERROR);
          break;
        
        case P1_SIGNATURE_V:
          debugMessage("P1_SIGNATURE_V");
          if (!(CheckCase(3) && Lc == SIZE_V)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          constructSignature(apdu.data);          
          debugValue("Initialised signature.v", signature.v, SIZE_V);
          ExitSW(ISO7816_SW_NO_ERROR);
          break;
        
        case P1_SIGNATURE_VERIFY:
          debugMessage("P1_SIGNATURE_VERIFY");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          verifySignature();
          debugMessage("Verified signature");
          ExitSW(ISO7816_SW_NO_ERROR);
          break;
        
        default:
          debugWarning("Unknown parameter");
          ExitSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;

    case INS_ISSUE_PROOF_A:
      debugMessage("INS_ISSUE_PROOF_A");
      switch(P1) {
        case P1_PROOF_A_C:
          debugMessage("P1_PROOF_A_C");
          if (!(CheckCase(3) && Lc == SIZE_H)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_H, challenge.c, apdu.data);
          debugValue("Initialised c", challenge.c, SIZE_H);
          ExitSW(ISO7816_SW_NO_ERROR);
          break;

        case P1_PROOF_A_S_E:
          debugMessage("P1_PROOF_A_S_E");
          if (!(CheckCase(3) && Lc == SIZE_N)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_N, s_e, apdu.data);
          debugValue("Initialised s_e", s_e, SIZE_N);
          ExitSW(ISO7816_SW_NO_ERROR);
          break;
        
        case P1_PROOF_A_VERIFY:
          debugMessage("P1_PROOF_A_VERIFY");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          verifyProof(s_e);
          debugMessage("Verified proof");
          ExitSW(ISO7816_SW_NO_ERROR);
          break;
        
        default:
          debugWarning("Unknown parameter");
          ExitSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;
    
    // Disclosure / Proving instructions
    case INS_PROVE_SELECTION:
      debugMessage("INS_PROVE_SELECTION");
      if (!(CheckCase(3) && Lc < SIZE_L)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      selectAttributes(apdu.data, Lc);
      ExitSW(ISO7816_SW_NO_ERROR);
      break;
      
    case INS_PROVE_NONCE:
      debugMessage("INS_PROVE_NONCE");
      if (!(CheckCase(3) && Lc == SIZE_STATZK)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_STATZK, nonce, apdu.data);
      debugValue("Initialised nonce", nonce, SIZE_STATZK);
      constructProof();
      COPYN(SIZE_H, apdu.data, challenge.c);
      debugValue("Returned c", apdu.data, SIZE_H);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_H);
      break;
    
    case INS_PROVE_SIGNATURE:
      debugMessage("INS_PROVE_SIGNATURE");
      switch(P1) {
        case P1_SIGNATURE_A:
          debugMessage("P1_SIGNATURE_A");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_N, apdu.data, signature_.A);
          debugValue("Returned A'", apdu.data, SIZE_N);
          ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_N);
          break;

        case P1_SIGNATURE_E:
          debugMessage("P1_SIGNATURE_E");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_E_, apdu.data, eHat);
          debugValue("Returned e^", apdu.data, SIZE_E_);
          ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_E_);
          break;

        case P1_SIGNATURE_V:
          debugMessage("P1_SIGNATURE_V");
          if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_V_, apdu.data, vHat);
          debugValue("Returned v^", apdu.data, SIZE_V_);
          ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_V_);
          break;

        default:
          debugWarning("Unknown parameter");
          ExitSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;
    
    case INS_PROVE_ATTRIBUTE:
      debugMessage("INS_PROVE_ATTRIBUTE");
      if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 == 0 || P1 > MAX_ATTR) ExitSW(ISO7816_SW_WRONG_P1P2);
      if (D[P1] != 0x01) ExitSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation!
      COPYN(SIZE_M, apdu.data, messages[P1]);
      debugValue("Returned attribute", apdu.data, SIZE_M);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_M);
      break;
      
    case INS_PROVE_RESPONSE:
      debugMessage("INS_PROVE_RESPONSE");
      if (!CheckCase(1)) ExitSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 > MAX_ATTR) ExitSW(ISO7816_SW_WRONG_P1P2);
      if (D[P1] != 0x00) ExitSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation?
      COPYN(SIZE_M_, apdu.data, mHat[P1]);
      debugValue("Returned response", apdu.data, SIZE_M_);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_M_);
      break;
    
    // Fetch instructions
    case INS_GET_PUBLIC_KEY_N:
      debugMessage("INS_GET_PUBLIC_KEY_N");
      COPYN(SIZE_N, apdu.data, issuerKey.n);
      debugValue("Fetched isserKey.n", issuerKey.n, SIZE_N);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_PUBLIC_KEY_Z:
      debugMessage("INS_GET_PUBLIC_KEY_Z");
      COPYN(SIZE_N, apdu.data, issuerKey.Z);
      debugValue("Fetched isserKey.Z", issuerKey.Z, SIZE_N);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_PUBLIC_KEY_S:
      debugMessage("INS_GET_PUBLIC_KEY_S");
      if (P1 == 0) {
        COPYN(SIZE_N, apdu.data, issuerKey.S);
        debugValue("Fetched isserKey.S", issuerKey.S, SIZE_N);
      } else {
        COPYN(SIZE_N, apdu.data, issuerKey.S_);
        debugValue("Fetched isserKey.S_", issuerKey.S_, SIZE_N);
      }
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_PUBLIC_KEY_R:
      debugMessage("INS_GET_PUBLIC_KEY_R");
      if (P1 > MAX_ATTR) ExitSW(ISO7816_SW_WRONG_P1P2);
      COPYN(SIZE_N, apdu.data, issuerKey.R[P1]);
      debugNumberI("Fetched isserKey.R", issuerKey.R, P1);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_CONTEXT:
      debugMessage("INS_GET_CONTEXT");
      COPYN(SIZE_H, apdu.data, context);
      debugValue("Fetched context", context, SIZE_H);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_H);
      break;
    
    case INS_GET_MASTER_SECRET:
      debugMessage("INS_GET_MASTER_SECRET");
      // FIXME: disable this instruction
      COPYN(SIZE_M, apdu.data, messages[0]);
      debugCLMessageI("Fetched messages", messages, 0);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_M);
      break;
    
    case INS_GET_ATTRIBUTES:
      debugMessage("INS_GET_ATTRIBUTES");
      if (P1 == 0 || P1 > MAX_ATTR) ExitSW(ISO7816_SW_WRONG_P1P2);
      COPYN(SIZE_M, apdu.data, messages[P1]);
      debugCLMessageI("Fetched messages", messages, P1);
      ExitSWLa(ISO7816_SW_NO_ERROR, SIZE_M);
      break;
    
    // Unknown instruction
    default:
      debugWarning("Unknown instruction");
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      ExitSW(ISO7816_SW_INS_NOT_SUPPORTED);
      break;
  }
}
