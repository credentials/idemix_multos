/**
 * idemix.c
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

// Name everything "idemix"
#pragma attribute("aid", "69 64 65 6D 69 78")
#pragma attribute("dir", "61 10 4f 6 69 64 65 6D 69 78 50 6 69 64 65 6D 69 78")

#include <ISO7816.h> // for APDU constants
#include <multosarith.h> // for COPYN()
#include <multosccr.h> // for ZFlag()
#include <string.h> // for memset()

#include "defs_apdu.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "funcs_helper.h"
#include "funcs_pin.h"
#include "crypto_helper.h"
#include "crypto_issuing.h"
#include "crypto_proving.h"
#include "crypto_messaging.h"

/********************************************************************/
/* Public segment (APDU buffer) variable declaration                */
/********************************************************************/
#pragma melpublic

// Idemix: protocol public variables
PublicData public;


/********************************************************************/
/* Session segment (application RAM memory) variable declaration    */
/********************************************************************/
#pragma melsession

// Idemix: protocol session variables
SessionData session; // 389
Credential *credential; // + 2 = 669
Byte flags; // + 1 = 670
Byte flag;

// Secure messaging: send sequence counter and session keys
Counter ssc; // 8
Byte key_enc[SIZE_KEY];
Byte key_mac[SIZE_KEY];


/********************************************************************/
/* Static segment (application EEPROM memory) variable declarations */
/********************************************************************/
#pragma melstatic

// Idemix: credentials and master secret
Credential credentials[MAX_CRED];
CLMessage masterSecret;

// Card holder verification: PIN
Byte pinCode[SIZE_PIN] = { 0x30, 0x30, 0x30, 0x30 };
Byte pinCount = PIN_COUNT;

// Card authentication: private key and modulus
Byte rsaSecret[SIZE_RSA_EXPONENT];
Byte rsaModulus[SIZE_RSA_MODULUS];

// Secure messaging: initialisation vector
Byte iv[SIZE_IV];


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

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

        case ISO7816_INS_INTERNAL_AUTHENTICATE:
          // Perform card authentication & secure messaging setup
          crypto_authenticate_card();
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_KEY_SEED_CARD);
          break;

        //////////////////////////////////////////////////////////////
        // Card holder verification                                 //
        //////////////////////////////////////////////////////////////

        case ISO7816_INS_VERIFY:
          // Perform card holder verification
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_PIN)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          pin_verify(public.apdu.data);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case ISO7816_INS_CHANGE_REFERENCE_DATA:
          // Update card holder verification
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_PIN)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          pin_update(public.apdu.data);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        //////////////////////////////////////////////////////////////
        // Unknown instruction byte (INS)                           //
        //////////////////////////////////////////////////////////////

        default:
          debugWarning("Unknown instruction");
          debugInteger("CLA", CLA);
          debugInteger("INS", INS);
          debugInteger("P1", P1);
          debugInteger("P2", P2);
          debugInteger("Lc", Lc);
          debugValue("data", public.apdu.data, Lc);
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
        debugValue("Unwrapped APDU", public.apdu.data, Lc);
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
          ZFlag(&flag);
          if (flag == 0) {
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
          COPYN(SIZE_M, masterSecret, public.apdu.data);
#endif // TEST
          debugValue("Initialised master secret", masterSecret, SIZE_M);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        //////////////////////////////////////////////////////////////
        // Personalisation / Issuance instructions                  //
        //////////////////////////////////////////////////////////////

        case INS_ISSUE_CREDENTIAL:
          debugMessage("INS_ISSUE_CREDENTIAL");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

          // Clear the session, if needed.
          TESTN(SIZE_H, session.issue.challenge);
          ZFlag(&flag);
          if (flag == 0) {
            crypto_clear_session();
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
              COPYN(SIZE_H, credential->proof.context, public.apdu.data);
              debugHash("Initialised context", credential->proof.context);
              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }

          // Out of space (all credential slots are occupied)
          debugWarning("Cannot issue another credential");
          ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED);
          break;

        case INS_ISSUE_PUBLIC_KEY_N:
          debugMessage("INS_ISSUE_PUBLIC_KEY_N");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          COPYN(SIZE_N, credential->issuerKey.n, public.apdu.data);
          debugNumber("Initialised isserKey.n", credential->issuerKey.n);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case INS_ISSUE_PUBLIC_KEY_Z:
          debugMessage("INS_ISSUE_PUBLIC_KEY_Z");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          COPYN(SIZE_N, credential->issuerKey.Z, public.apdu.data);
          debugNumber("Initialised isserKey.Z", credential->issuerKey.Z);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case INS_ISSUE_PUBLIC_KEY_S:
          debugMessage("INS_ISSUE_PUBLIC_KEY_S");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          COPYN(SIZE_N, credential->issuerKey.S, public.apdu.data);
          debugNumber("Initialised isserKey.S", credential->issuerKey.S);
          crypto_compute_S_();
          debugNumber("Initialised isserKey.S_", credential->issuerKey.S_);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case INS_ISSUE_PUBLIC_KEY_R:
          debugMessage("INS_ISSUE_PUBLIC_KEY_R");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 > MAX_ATTR) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

          COPYN(SIZE_N, credential->issuerKey.R[P1], public.apdu.data);
          debugNumberI("Initialised isserKey.R", credential->issuerKey.R, P1);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case INS_ISSUE_ATTRIBUTES:
          debugMessage("INS_ISSUE_ATTRIBUTES");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_M)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > MAX_ATTR) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          TESTN(SIZE_M, public.apdu.data);
          ZFlag(&flag);
          if (flag != 0) {
            debugWarning("Attribute cannot be empty");
            ReturnSW(ISO7816_SW_WRONG_DATA);
          }

          COPYN(SIZE_M, credential->attribute[P1 - 1], public.apdu.data);
          debugCLMessageI("Initialised attribute", credential->attribute, P1 - 1);
          // TODO: Implement some proper handling of the number of attributes
          if (P1 > credential->size) {
            credential->size = P1;
          }
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case INS_ISSUE_FLAGS:
          debugMessage("INS_ISSUE_FLAGS");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          credential->flags = P1;
          debugValue("Initialised flags", &(credential->flags), 1);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
          break;

        case INS_ISSUE_NONCE_1:
          debugMessage("INS_ISSUE_NONCE_1");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          COPYN(SIZE_STATZK, public.issue.nonce, public.apdu.data);
          debugNonce("Initialised nonce", public.issue.nonce);
          constructCommitment();
          debugNumber("Returned U", public.apdu.data);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
          break;

        case INS_ISSUE_PROOF_U:
          debugMessage("INS_ISSUE_PROOF_U");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          switch (P1) {
            case P1_PROOF_U_C:
              debugMessage("P1_PROOF_U_C");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_H, public.apdu.data, session.issue.challenge);
              debugHash("Returned c", public.apdu.data);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_H);
              break;

            case P1_PROOF_U_VPRIMEHAT:
              debugMessage("P1_PROOF_U_VPRIMEHAT");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_VPRIME_, public.apdu.data, session.issue.vPrimeHat);
              debugValue("Returned vPrimeHat", public.apdu.data, SIZE_VPRIME_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_VPRIME_);
              break;

            case P1_PROOF_U_S_A:
              debugMessage("P1_PROOF_U_S_A");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_S_A, public.apdu.data, session.issue.sA);
              debugValue("Returned s_A", public.apdu.data, SIZE_S_A);
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
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          COPYN(SIZE_STATZK, public.apdu.data, credential->proof.nonce);
          debugNonce("Returned nonce", public.apdu.data);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_STATZK);
          break;

        case INS_ISSUE_SIGNATURE:
          debugMessage("INS_ISSUE_SIGNATURE");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          switch(P1) {
            case P1_SIGNATURE_A:
              debugMessage("P1_SIGNATURE_A");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_N, credential->signature.A, public.apdu.data);
              debugNumber("Initialised signature.A", credential->signature.A);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;

            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_E)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_E, credential->signature.e, public.apdu.data);
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
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          switch(P1) {
            case P1_PROOF_A_C:
              debugMessage("P1_PROOF_A_C");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_H, credential->proof.challenge, public.apdu.data);
              debugHash("Initialised c", credential->proof.challenge);
              ReturnSW(ISO7816_SW_NO_ERROR);
              break;

            case P1_PROOF_A_S_E:
              debugMessage("P1_PROOF_A_S_E");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_N, credential->proof.response, public.apdu.data);
              debugNumber("Initialised s_e", credential->proof.response);
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

          // Clear the session, if needed.
          TESTN(SIZE_H, public.prove.context);
          ZFlag(&flag);
          if (flag == 0) {
            crypto_clear_session();
          }

          // Lookup the given credential ID and select it if it exists
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == P1P2) {
              credential = &credentials[i];
              if (pin_required && !pin_verified) {
                ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
              }
#ifndef SIMULATOR
              COPYN(SIZE_H, public.prove.context, public.apdu.data);
              debugHash("Initialised context", public.prove.context);
#else // SIMULATOR
              COPYN(SIZE_H, session.prove.context, public.apdu.data);
              debugHash("Initialised context", session.prove.context);
#endif // SIMULATOR
              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
          break;

        case INS_PROVE_SELECTION:
          debugMessage("INS_PROVE_SELECTION");
          if (pin_required && !pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          selectAttributes(P1P2);
          ReturnSW(ISO7816_SW_NO_ERROR);
          break;

        case INS_PROVE_NONCE:
          debugMessage("INS_PROVE_NONCE");
          if (pin_required && !pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_STATZK)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          constructProof();
          debugHash("Returned c", public.apdu.data);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_H);
          break;

        case INS_PROVE_SIGNATURE:
          debugMessage("INS_PROVE_SIGNATURE");
          if (pin_required && !pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          switch(P1) {
            case P1_SIGNATURE_A:
              debugMessage("P1_SIGNATURE_A");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_N, public.apdu.data, public.prove.APrime);
              debugNumber("Returned A'", public.apdu.data);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
              break;

            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_E_, public.apdu.data, public.prove.eHat);
              debugValue("Returned e^", public.apdu.data, SIZE_E_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_E_);
              break;

            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_V_, public.apdu.data, public.prove.vHat);
              debugValue("Returned v^", public.apdu.data, SIZE_V_);
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
          if (pin_required && !pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > credential->size) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          if (disclosed(P1) != 1) {
            ReturnSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation!
          }

          COPYN(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
          debugValue("Returned attribute", public.apdu.data, SIZE_M);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M);
          break;

        case INS_PROVE_RESPONSE:
          debugMessage("INS_PROVE_RESPONSE");
          if (pin_required && !pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 > MAX_ATTR) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          if (disclosed(P1) != 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2); // TODO: security violation?
          }

          COPYN(SIZE_M_, public.apdu.data, session.prove.mHat[P1]);
          debugValue("Returned response", public.apdu.data, SIZE_M_);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M_);
          break;

        //////////////////////////////////////////////////////////////
        // Administration instructions                              //
        //////////////////////////////////////////////////////////////

        case INS_ADMIN_CREDENTIAL:
          debugMessage("INS_PROVE_CREDENTIAL");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
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
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
          break;

        case INS_ADMIN_REMOVE:
          debugMessage("INS_ADMIN_REMOVE");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

          // Verify the given credential ID and remove it if it matches
          if (credential->id == P1P2) {
            crypto_clear_credential();
            debugInteger("Removed credential", P1P2);
            ReturnSW(ISO7816_SW_NO_ERROR);
          }
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
          break;

        case INS_ADMIN_FLAGS:
          debugMessage("INS_ADMIN_FLAGS");
          if (!pin_verified) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          credential->flags = P1;
          debugValue("Updated flags", &(credential->flags), 1);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);
          break;

        //////////////////////////////////////////////////////////////
        // Unknown instruction byte (INS)                           //
        //////////////////////////////////////////////////////////////

        default:
          debugWarning("Unknown instruction");
          debugInteger("CLA", CLA);
          debugInteger("INS", INS);
          debugInteger("P1", P1);
          debugInteger("P2", P2);
          debugInteger("Lc", Lc);
          debugValue("data", public.apdu.data, Lc);
          ReturnSW(ISO7816_SW_INS_NOT_SUPPORTED);
          break;
      }
      break;

    //////////////////////////////////////////////////////////////////
    // Unknown class byte (CLA)                                     //
    //////////////////////////////////////////////////////////////////

    default:
      debugWarning("Unknown class");
      debugInteger("CLA", CLA);
      debugInteger("INS", INS);
      debugInteger("P1", P1);
      debugInteger("P2", P2);
      debugInteger("Lc", Lc);
      debugValue("data", public.apdu.data, Lc);
      ReturnSW(ISO7816_SW_CLA_NOT_SUPPORTED);
      break;
  }
}
