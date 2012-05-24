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
#include <multosccr.h>
#include <string.h>

#include "defs_apdu.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "funcs_helper.h"
#include "crypto_helper.h"
#include "crypto_issuing.h"
#include "crypto_proving.h"
#include "crypto_messaging.h"

/********************************************************************/
/* APDU buffer variable declaration                                 */
/********************************************************************/
#pragma melpublic

APDUData apdu; // 458


/********************************************************************/
/* RAM variable declaration                                         */
/********************************************************************/
#pragma melsession

Counter ssc; // 8 = 8
Nonce nonce; // + 10 = 18
Hash context; // + 20 = 38
Byte disclose; // + 1 = 39
Challenge challenge; // + 67 = 106
ResponseE eHat; // + 45 = 151
ResponseV vHat; // + 231 = 382
ResponseM mHat[SIZE_L]; // + 63*6 (378) = 760
Credential *credential; // + 2 = 762
Byte pinOK; // + 1 = 763


/********************************************************************/
/* EEPROM variable declarations                                     */
/********************************************************************/
#pragma melstatic

// Master secret
CLMessage masterSecret;

// Credentials
Credential credentials[MAX_CRED];

// Shared protocol variables
Number numa, numb;
CLSignature signature_;

// Secure Messaging
Byte iv[SIZE_IV];
Byte key_enc[SIZE_KEY];
Byte key_mac[SIZE_KEY];

// Card holder verification
Byte pinCode[SIZE_PIN];
Byte pinCount = PIN_COUNT;

/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

#define buffer apdu.temp.data
#define U numa
void main(void) {
  int i;
  
  switch (CLA & 0xF3) {
    
    //////////////////////////////////////////////////////////////////
    // Generic functionality                                        //
    //////////////////////////////////////////////////////////////////
    
    case ISO7816_CLA:
      // Process the instruction
      switch (INS) {

        //////////////////////////////////////////////////////////////
        // Terminal authentication                                  //
        //////////////////////////////////////////////////////////////
        
        case ISO7816_INS_GET_CHALLENGE:
          // Construct a challenge for the terminal
          break;
          
        case ISO7816_INS_EXTERNAL_AUTHENTICATE:
          // Perform terminal authentication
          break;
        
        //////////////////////////////////////////////////////////////
        // Card holder verification                                 //
        //////////////////////////////////////////////////////////////
        
        case ISO7816_INS_VERIFY:
          // Perform card holder verification
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_PIN)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          pin_verify(apdu.data);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
          
        case ISO7816_INS_CHANGE_REFERENCE_DATA:
          // Update card holder verification
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_PIN)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          pin_update(apdu.data);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        //////////////////////////////////////////////////////////////
        // Unknown instruction                                      //
        //////////////////////////////////////////////////////////////
        
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
      break;
    
    //////////////////////////////////////////////////////////////////
    // Idemix functionality                                         //
    //////////////////////////////////////////////////////////////////
    
    case CLA_IDEMIX:
      // Check whether the APDU has been wrapped for secure messaging
      if (wrapped) {
        if (!CheckCase(4)) {
          ExitSW(ISO7816_SW_WRONG_LENGTH);
        }
        crypto_unwrap();
        debugValue("Unwrapped APDU", apdu.data, Lc);
      }
      
      // Process the instruction
      switch (INS) {
        
        //////////////////////////////////////////////////////////////
        // Initialisation instructions                              //
        //////////////////////////////////////////////////////////////
        
        case INS_SELECT_CREDENTIAL:
          debugMessage("INS_SELECT_CREDENTIAL");
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          
          // Lookup the given credential ID and select it if it exists
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == P1P2) {
              credential = &credentials[i];
              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }
          debugWarning("Unknown credential");
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
          break;
          
        case INS_GENERATE_SECRET:
          debugMessage("INS_GENERATE_SECRET");
#ifndef TEST
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          // Prevent reinitialisation of the master secret
          TESTN(SIZE_M, masterSecret);
          ZFlag(buffer);
          if (buffer[0] == 0) {
            debugWarning("Master secret is already generated");
            ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED_AGAIN);
          }
          
          // Generate a random value for the master secret
          crypto_generate_random(masterSecret, LENGTH_M);
#else // TEST
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_M)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          // Use the test value for the master secret
          COPYN(SIZE_M, masterSecret, apdu.data);
#endif // TEST
          debugValue("Initialised master secret", masterSecret, SIZE_M);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        //////////////////////////////////////////////////////////////
        // Personalisation / Issuance instructions                  //
        //////////////////////////////////////////////////////////////
    
        case INS_ISSUE_CREDENTIAL:
          debugMessage("INS_ISSUE_CREDENTIAL");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          
          // Prevent reissuance of a credential
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == P1P2) {
              debugWarning("Credential is already issued");
              ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED_AGAIN);
            }
          }
          
          // Create a new credential
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == 0) {          
              credential = &credentials[i];
              credential->id = P1P2;
              COPYN(SIZE_H, credential->proof.context, apdu.data);
              debugValue("Initialised context", credential->proof.context, SIZE_H);
              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }
          
          // Out of space
          debugWarning("Cannot issue another credential");
          ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED);
          break;
        
        case INS_ISSUE_PUBLIC_KEY_N:
          debugMessage("INS_ISSUE_PUBLIC_KEY_N");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          COPYN(SIZE_N, credential->issuerKey.n, apdu.data);
          debugValue("Initialised isserKey.n", credential->issuerKey.n, SIZE_N);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case INS_ISSUE_PUBLIC_KEY_Z:
          debugMessage("INS_ISSUE_PUBLIC_KEY_Z");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          COPYN(SIZE_N, credential->issuerKey.Z, apdu.data);
          debugValue("Initialised isserKey.Z", credential->issuerKey.Z, SIZE_N);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case INS_ISSUE_PUBLIC_KEY_S:
          debugMessage("INS_ISSUE_PUBLIC_KEY_S");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          COPYN(SIZE_N, credential->issuerKey.S, apdu.data);
          debugValue("Initialised isserKey.S", credential->issuerKey.S, SIZE_N);
          crypto_compute_S_();
          debugValue("Initialised isserKey.S_", credential->issuerKey.S_, SIZE_N);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case INS_ISSUE_PUBLIC_KEY_R:
          debugMessage("INS_ISSUE_PUBLIC_KEY_R");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 > MAX_ATTR) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          
          COPYN(SIZE_N, credential->issuerKey.R[P1], apdu.data);
          debugNumberI("Initialised isserKey.R", credential->issuerKey.R, P1);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case INS_ISSUE_ATTRIBUTES:
          debugMessage("INS_ISSUE_ATTRIBUTES");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_M)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > MAX_ATTR) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          TESTN(SIZE_M, apdu.data);
          ZFlag(buffer + SIZE_M);
          if (buffer[SIZE_M] != 0) {
            debugWarning("Attribute cannot be empty");
            ReturnSW(ISO7816_SW_WRONG_DATA);
          }
          
          COPYN(SIZE_M, credential->attribute[P1 - 1], apdu.data);
          debugCLMessageI("Initialised attribute", credential->attribute, P1 - 1);
          // TODO: Implement some proper handling of the number of attributes
          if (P1 > credential->size) {
            credential->size = P1;
          }
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
        
        case INS_ISSUE_NONCE_1:
          debugMessage("INS_ISSUE_NONCE_1");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
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
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_H, apdu.data, challenge.c);
              debugValue("Returned c", apdu.data, SIZE_H);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_H);
              break;
              
            case P1_PROOF_U_VPRIMEHAT:
              debugMessage("P1_PROOF_U_VPRIMEHAT");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_VPRIME_, apdu.data, vHat);
              debugValue("Returned vPrimeHat", apdu.data, SIZE_VPRIME_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_VPRIME_);
              break;
              
            case P1_PROOF_U_S_A:
              debugMessage("P1_PROOF_U_S_A");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
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
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          COPYN(SIZE_STATZK, apdu.data, credential->proof.nonce);
          debugValue("Returned nonce", apdu.data, SIZE_STATZK);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_STATZK);
          break;
        
        case INS_ISSUE_SIGNATURE:
          debugMessage("INS_ISSUE_SIGNATURE");
          switch(P1) {
            case P1_SIGNATURE_A:
              debugMessage("P1_SIGNATURE_A");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_N, credential->signature.A, apdu.data);
              debugValue("Initialised signature.A", credential->signature.A, SIZE_N);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;
    
            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_E)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_E, credential->signature.e, apdu.data);
              debugValue("Initialised signature.e", credential->signature.e, SIZE_E);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;
            
            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_V)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              constructSignature();          
              debugValue("Initialised signature.v", credential->signature.v, SIZE_V);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;
            
            case P1_SIGNATURE_VERIFY:
              debugMessage("P1_SIGNATURE_VERIFY");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
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
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_H, credential->proof.challenge, apdu.data);
              debugValue("Initialised c", credential->proof.challenge, SIZE_H);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;
    
            case P1_PROOF_A_S_E:
              debugMessage("P1_PROOF_A_S_E");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_N, credential->proof.response, apdu.data);
              debugValue("Initialised s_e", credential->proof.response, SIZE_N);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;
            
            case P1_PROOF_A_VERIFY:
              debugMessage("P1_PROOF_A_VERIFY");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
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
        
        //////////////////////////////////////////////////////////////
        // Disclosure / Proving instructions                        //
        //////////////////////////////////////////////////////////////
        
        case INS_PROVE_CREDENTIAL:
          debugMessage("INS_PROVE_CREDENTIAL");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          
          // Lookup the given credential ID and select it if it exists
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == P1P2) {
              credential = &credentials[i];
              COPYN(SIZE_H, context, apdu.data);
              debugValue("Initialised context", context, SIZE_H);
              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
          break;
    
        case INS_PROVE_SELECTION:
          debugMessage("INS_PROVE_SELECTION");
          if (!((wrapped || CheckCase(3)) && Lc < SIZE_L)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          selectAttributes(apdu.data, Lc);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;
          
        case INS_PROVE_NONCE:
          debugMessage("INS_PROVE_NONCE");
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
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
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_N, apdu.data, signature_.A);
              debugValue("Returned A'", apdu.data, SIZE_N);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
              break;
    
            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
              COPYN(SIZE_E_, apdu.data, eHat);
              debugValue("Returned e^", apdu.data, SIZE_E_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_E_);
              break;
    
            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }
              
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
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > credential->size) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          if (disclosed(P1) != 1) {
            ReturnSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation!
          }
          
          COPYN(SIZE_M, apdu.data, credential->attribute[P1 - 1]);
          debugValue("Returned attribute", apdu.data, SIZE_M);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M);
          break;
          
        case INS_PROVE_RESPONSE:
          debugMessage("INS_PROVE_RESPONSE");
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 > MAX_ATTR) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          if (disclosed(P1) != 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation?
          }
          
          COPYN(SIZE_M_, apdu.data, mHat[P1]);
          debugValue("Returned response", apdu.data, SIZE_M_);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M_);
          break;
        
        //////////////////////////////////////////////////////////////
        // Unknown instruction                                      //
        //////////////////////////////////////////////////////////////
        
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
      break;
  
    ////////////////////////////////////////////////////////////////// 
    // Unknown class                                                //
    //////////////////////////////////////////////////////////////////
    
    default:
      debugWarning("Unknown class");
      debugInteger("CLA", CLA);
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      debugInteger("P2", P2);
      debugInteger("Lc", Lc);
      debugValue("data", apdu.data, Lc);
      ReturnSW(ISO7816_SW_CLA_NOT_SUPPORTED);
      break;
  }
}
#undef buffer
#undef U
