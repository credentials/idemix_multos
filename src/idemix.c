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
#include <multosarith.h>
#include <string.h>

#include "defs_apdu.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"
#include "crypto_issuing.h"
#include "crypto_proving.h"
#include "crypto_messaging.h"

#define buffer apdu.temp.data
#define U numa

/********************************************************************/
/* APDU buffer variable declaration                                 */
/********************************************************************/
#pragma melpublic

APDUData apdu; // 458


/********************************************************************/
/* RAM variable declaration                                         */
/********************************************************************/
#pragma melsession

Nonce nonce; // 10 = 10
Hash context; // + 20 = 30
int D; // + 2 = 32
Challenge challenge; // + 69 = 101
ResponseE eHat; // + 45 = 146
ResponseV vHat; // + 231 = 377
ResponseM mHat[SIZE_L]; // + 63*6 (378) = 755
Byte ssc[SIZE_SSC]; // + 8 = 763


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
CLProof proof; // For postponed signature/proof verification

// Shared protocol variables
Number numa, numb;
CLSignature signature_;

// Secure Messaging
Byte iv[SIZE_IV];
Byte key_enc[SIZE_KEY];
Byte key_mac[SIZE_KEY];

#ifdef TEST
int m_count = 0;
#endif // TEST


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
  if ((CLA & 0xF3) != CLA_IDEMIX) {
    ReturnSW(ISO7816_SW_CLA_NOT_SUPPORTED);
  }
  
  // Check whether the APDU has been wrapped for secure messaging
  if (wrapped) {
    debugMessage("Unwrapping APDU");
    if (!CheckCase(4)) ExitSW(ISO7816_SW_WRONG_LENGTH);
    debugInteger("Lc", Lc);
    crypto_unwrap();
    debugValue("Unwrapped APDU", apdu.data, Lc);
    debugInteger("Lc", Lc);
  }
  
  switch (INS) {
    
    //////////////////////////////////////////////////////////////////
    // Initialisation instructions                                  //
    //////////////////////////////////////////////////////////////////
    
    case INS_SET_PUBLIC_KEY_N:
      debugMessage("INS_SET_PUBLIC_KEY_N");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, issuerKey.n, apdu.data);
      debugValue("Initialised isserKey.n", issuerKey.n, SIZE_N);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_PUBLIC_KEY_Z:
      debugMessage("INS_SET_PUBLIC_KEY_Z");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, issuerKey.Z, apdu.data);
      debugValue("Initialised isserKey.Z", issuerKey.Z, SIZE_N);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_PUBLIC_KEY_S:
      debugMessage("INS_SET_PUBLIC_KEY_S");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, issuerKey.S, apdu.data);
      debugValue("Initialised isserKey.S", issuerKey.S, SIZE_N);
      crypto_compute_S_();
      debugValue("Initialised isserKey.S_", issuerKey.S_, SIZE_N);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_PUBLIC_KEY_R:
      debugMessage("INS_SET_PUBLIC_KEY_R");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 > MAX_ATTR) ReturnSW(ISO7816_SW_WRONG_P1P2);
      COPYN(SIZE_N, issuerKey.R[P1], apdu.data);
      debugNumberI("Initialised isserKey.R", issuerKey.R, P1);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_MASTER_SECRET:
      debugMessage("INS_SET_MASTER_SECRET");
#ifdef TEST
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_M)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_M, messages[0], apdu.data);
#else // TEST
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      crypto_generate_random(messages[0], LENGTH_M);
#endif // TEST
      debugCLMessageI("Initialised messages", messages, 0);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
    
    case INS_SET_ATTRIBUTES:
      debugMessage("INS_SET_ATTRIBUTES");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_M)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 == 0 || P1 > MAX_ATTR) ReturnSW(ISO7816_SW_WRONG_P1P2);
      CLEARN(SIZE_M, buffer + SIZE_M);
      if (memcmp(buffer + SIZE_M, apdu.data, SIZE_M) == 0) ReturnSW(ISO7816_SW_WRONG_DATA);
      COPYN(SIZE_M, messages[P1], apdu.data);
      debugCLMessageI("Initialised messages", messages, P1);
      // TODO: Implement some proper handling of the number of attributes
      if (P1 > attributes) {
        attributes = P1;
      }
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
    
    //////////////////////////////////////////////////////////////////
    // Personalisation / Issuance instructions                      //
    //////////////////////////////////////////////////////////////////
    
    case INS_ISSUE_CONTEXT:
      debugMessage("INS_ISSUE_CONTEXT");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_H, proof.context, apdu.data);
      debugValue("Initialised context", proof.context, SIZE_H);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;

    case INS_ISSUE_NONCE_1:
      debugMessage("INS_ISSUE_NONCE_1");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_STATZK, nonce, apdu.data);
      debugValue("Initialised nonce", nonce, SIZE_STATZK);
      constructCommitment();
      COPYN(SIZE_N, apdu.data, U);
      debugValue("Returned U", apdu.data, SIZE_N);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
      
    case INS_ISSUE_PROOF_U:
      debugMessage("INS_ISSUE_PROOF_U");
      switch (P1) {
        case P1_PROOF_U_C:
          debugMessage("P1_PROOF_U_C");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_H, apdu.data, challenge.c);
          debugValue("Returned c", apdu.data, SIZE_H);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_H);
          break;
          
        case P1_PROOF_U_VPRIMEHAT:
          debugMessage("P1_PROOF_U_VPRIMEHAT");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_VPRIME_, apdu.data, vHat);
          debugValue("Returned vPrimeHat", apdu.data, SIZE_VPRIME_);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_VPRIME_);
          break;
          
        case P1_PROOF_U_S_A:
          debugMessage("P1_PROOF_U_S_A");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_S_A, apdu.data, mHat[0]);
          debugValue("Returned s_A", apdu.data, SIZE_S_A);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_S_A);
          break;
        
        default:
          debugWarning("Unknown parameter");
          ReturnSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;
      
    case INS_ISSUE_NONCE_2:
      debugMessage("INS_ISSUE_NONCE_2");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_STATZK, apdu.data, proof.nonce);
      debugValue("Returned nonce", apdu.data, SIZE_STATZK);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_STATZK);
      break;
    
    case INS_ISSUE_SIGNATURE:
      debugMessage("INS_ISSUE_SIGNATURE");
      switch(P1) {
        case P1_SIGNATURE_A:
          debugMessage("P1_SIGNATURE_A");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_N, signature.A, apdu.data);
          debugValue("Initialised signature.A", signature.A, SIZE_N);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case P1_SIGNATURE_E:
          debugMessage("P1_SIGNATURE_E");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_E)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_E, signature.e, apdu.data);
          debugValue("Initialised signature.e", signature.e, SIZE_E);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case P1_SIGNATURE_V:
          debugMessage("P1_SIGNATURE_V");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_V)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          constructSignature();          
          debugValue("Initialised signature.v", signature.v, SIZE_V);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case P1_SIGNATURE_VERIFY:
          debugMessage("P1_SIGNATURE_VERIFY");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          verifySignature();
          debugMessage("Verified signature");
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        default:
          debugWarning("Unknown parameter");
          ReturnSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;

    case INS_ISSUE_PROOF_A:
      debugMessage("INS_ISSUE_PROOF_A");
      switch(P1) {
        case P1_PROOF_A_C:
          debugMessage("P1_PROOF_A_C");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_H, proof.challenge, apdu.data);
          debugValue("Initialised c", proof.challenge, SIZE_H);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case P1_PROOF_A_S_E:
          debugMessage("P1_PROOF_A_S_E");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_N, proof.response, apdu.data);
          debugValue("Initialised s_e", proof.response, SIZE_N);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case P1_PROOF_A_VERIFY:
          debugMessage("P1_PROOF_A_VERIFY");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          verifyProof();
          debugMessage("Verified proof");
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        default:
          debugWarning("Unknown parameter");
          ReturnSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;
    
    ////////////////////////////////////////////////////////////////// 
    // Disclosure / Proving instructions                            //
    //////////////////////////////////////////////////////////////////
    
    case INS_PROVE_CONTEXT:
      debugMessage("INS_SET_CONTEXT");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_H, context, apdu.data);
      debugValue("Initialised context", context, SIZE_H);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;

    case INS_PROVE_SELECTION:
      debugMessage("INS_PROVE_SELECTION");
      if (!((wrapped || CheckCase(3)) && Lc < SIZE_L)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      selectAttributes(apdu.data, Lc);
      ReturnSW(ISO7816_SW_NO_ERROR);
      break;
      
    case INS_PROVE_NONCE:
      debugMessage("INS_PROVE_NONCE");
      if (!((wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_STATZK, nonce, apdu.data);
      debugValue("Initialised nonce", nonce, SIZE_STATZK);
      constructProof();
      COPYN(SIZE_H, apdu.data, challenge.c);
      debugValue("Returned c", apdu.data, SIZE_H);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_H);
      break;
    
    case INS_PROVE_SIGNATURE:
      debugMessage("INS_PROVE_SIGNATURE");
      switch(P1) {
        case P1_SIGNATURE_A:
          debugMessage("P1_SIGNATURE_A");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_N, apdu.data, signature_.A);
          debugValue("Returned A'", apdu.data, SIZE_N);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
          break;

        case P1_SIGNATURE_E:
          debugMessage("P1_SIGNATURE_E");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_E_, apdu.data, eHat);
          debugValue("Returned e^", apdu.data, SIZE_E_);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_E_);
          break;

        case P1_SIGNATURE_V:
          debugMessage("P1_SIGNATURE_V");
          if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
          COPYN(SIZE_V_, apdu.data, vHat);
          debugValue("Returned v^", apdu.data, SIZE_V_);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_V_);
          break;

        default:
          debugWarning("Unknown parameter");
          ReturnSW(ISO7816_SW_WRONG_P1P2);
          break;
      }
      break;
    
    case INS_PROVE_ATTRIBUTE:
      debugMessage("INS_PROVE_ATTRIBUTE");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 == 0 || P1 > MAX_ATTR) ReturnSW(ISO7816_SW_WRONG_P1P2);
      if (disclosed(P1) != 1) ReturnSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation!
      COPYN(SIZE_M, apdu.data, messages[P1]);
      debugValue("Returned attribute", apdu.data, SIZE_M);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M);
      break;
      
    case INS_PROVE_RESPONSE:
      debugMessage("INS_PROVE_RESPONSE");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 > MAX_ATTR) ReturnSW(ISO7816_SW_WRONG_P1P2);
      if (disclosed(P1) != 0) ReturnSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation?
      COPYN(SIZE_M_, apdu.data, mHat[P1]);
      debugValue("Returned response", apdu.data, SIZE_M_);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M_);
      break;
    
    //////////////////////////////////////////////////////////////////
    // Fetch instructions                                           //
    //////////////////////////////////////////////////////////////////
    
    case INS_GET_PUBLIC_KEY_N:
      debugMessage("INS_GET_PUBLIC_KEY_N");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, apdu.data, issuerKey.n);
      debugValue("Fetched isserKey.n", issuerKey.n, SIZE_N);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_PUBLIC_KEY_Z:
      debugMessage("INS_GET_PUBLIC_KEY_Z");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      COPYN(SIZE_N, apdu.data, issuerKey.Z);
      debugValue("Fetched isserKey.Z", issuerKey.Z, SIZE_N);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_PUBLIC_KEY_S:
      debugMessage("INS_GET_PUBLIC_KEY_S");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 == 0) {
        COPYN(SIZE_N, apdu.data, issuerKey.S);
        debugValue("Fetched isserKey.S", issuerKey.S, SIZE_N);
      } else {
        COPYN(SIZE_N, apdu.data, issuerKey.S_);
        debugValue("Fetched isserKey.S_", issuerKey.S_, SIZE_N);
      }
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;
    
    case INS_GET_PUBLIC_KEY_R:
      debugMessage("INS_GET_PUBLIC_KEY_R");
      if (!(wrapped || CheckCase(1))) ReturnSW(ISO7816_SW_WRONG_LENGTH);
      if (P1 > MAX_ATTR) ReturnSW(ISO7816_SW_WRONG_P1P2);
      COPYN(SIZE_N, apdu.data, issuerKey.R[P1]);
      debugNumberI("Fetched isserKey.R", issuerKey.R, P1);
      ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
      break;

    // Unknown instruction
    default:
      debugWarning("Unknown instruction");
      debugInteger("CLA", CLA);
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      debugInteger("P2", P2);
      debugInteger("Lc", Lc);
      debugValue("data", apdu.data, Lc);
      ReturnSW(ISO7816_SW_INS_NOT_SUPPORTED);
      break;
  }
}
