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
#pragma attribute("aid", "49 52 4D 41 63 61 72 64")
#pragma attribute("dir", "61 10 4f 6 69 64 65 6D 69 78 50 6 69 64 65 6D 69 78")
#pragma attribute("fci", "49 00 07 00")

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
Byte terminal[SIZE_TERMINAL_ID];

/********************************************************************/
/* Static segment (application EEPROM memory) variable declarations */
/********************************************************************/
#pragma melstatic

// Idemix: credentials and master secret
Credential credentials[MAX_CRED];
CLMessage masterSecret;

// Card holder verification: PIN
PIN cardPIN = {
  { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x00, 0x00 },
  SIZE_CARD_PIN,
  PIN_COUNT,
  FLAG_CARD_PIN
};
PIN credPIN = {
  { 0x30, 0x30, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00 },
  SIZE_CRED_PIN,
  PIN_COUNT,
  FLAG_CRED_PIN
};

// Card authentication: private key and modulus
Byte rsaExponent[SIZE_RSA_EXPONENT];
Byte rsaModulus[SIZE_RSA_MODULUS];

// Secure messaging: initialisation vector
Byte iv[SIZE_IV];

// Logging
LogEntry *log;
LogEntry logList[SIZE_LOG];
Byte logHead = 0;


/********************************************************************/
/* APDU handling                                                    */
/********************************************************************/

void main(void) {
  int i;

  // Check whether the APDU has been wrapped for secure messaging
  if (wrapped) {
	if (!CheckCase(4)) {
	  ExitSW(ISO7816_SW_WRONG_LENGTH);
	}
	crypto_unwrap();
	debugValue("Unwrapped APDU", public.apdu.data, Lc);
  }

  switch (CLA & 0xF3) {

    //////////////////////////////////////////////////////////////////
    // Generic functionality                                        //
    //////////////////////////////////////////////////////////////////

    case ISO7816_CLA:
      // Process the instruction
      switch (INS) {

        //////////////////////////////////////////////////////////////
        // Authentication                                           //
        //////////////////////////////////////////////////////////////

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
          debugMessage("INS_VERIFY");
          if (P1 != 0x00) {
              ReturnSW(ISO7816_SW_WRONG_P1P2);			  
		  }
		  if (!((wrapped || CheckCase(3)) && Lc == SIZE_PIN_MAX)) {
			ReturnSW(ISO7816_SW_WRONG_LENGTH);
		  }
          switch (P2) {
            case P2_CARD_PIN:
              pin_verify(&cardPIN, public.apdu.data);
              break;

            case P2_CRED_PIN:
              pin_verify(&credPIN, public.apdu.data);
              break;

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
		  ReturnSW(ISO7816_SW_NO_ERROR);

        case ISO7816_INS_CHANGE_REFERENCE_DATA:
          debugMessage("INS_CHANGE_REFERENCE_DATA");
          if (P1 != 0x00) {
              ReturnSW(ISO7816_SW_WRONG_P1P2);			  
		  }
		  if (!((wrapped || CheckCase(3)) && Lc == 2*SIZE_PIN_MAX)) {
			ReturnSW(ISO7816_SW_WRONG_LENGTH);
		  }
          switch (P2) {
            case P2_CARD_PIN:
              pin_update(&cardPIN, public.apdu.data);
              break;

            case P2_CRED_PIN:
              pin_update(&credPIN, public.apdu.data);
              break;

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
		  ReturnSW(ISO7816_SW_NO_ERROR);

        //////////////////////////////////////////////////////////////
        // Unknown instruction byte (INS)                           //
        //////////////////////////////////////////////////////////////

        default:
          debugWarning("Unknown instruction");
          ReturnSW(ISO7816_SW_INS_NOT_SUPPORTED);
      }

    //////////////////////////////////////////////////////////////////
    // Idemix functionality                                         //
    //////////////////////////////////////////////////////////////////

    case CLA_IRMACARD:
      // Process the instruction
      switch (INS) {

        //////////////////////////////////////////////////////////////
        // Initialisation instructions                              //
        //////////////////////////////////////////////////////////////

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

        case INS_AUTHENTICATION_SECRET:
          debugMessage("INS_AUTHENTICATION_SECRET");
          if (P2 != 0x00) {
              ReturnSW(ISO7816_SW_WRONG_P1P2);
		  }
          switch (P1) {
            case P1_AUTHENTICATION_EXPONENT:
              debugMessage("P1_AUTHENTICATION_EXPONENT");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_RSA_EXPONENT)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_RSA_EXPONENT, rsaExponent, public.apdu.data);
              debugValue("Initialised rsaExponent", rsaExponent, SIZE_RSA_EXPONENT);
              break;

            case P1_AUTHENTICATION_MODULUS:
              debugMessage("P1_AUTHENTICATION_MODULUS");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_RSA_MODULUS)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_RSA_EXPONENT, rsaModulus, public.apdu.data);
              debugValue("Initialised rsaModulus", rsaModulus, SIZE_RSA_MODULUS);
              break;

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
		  ReturnSW(ISO7816_SW_NO_ERROR);

        //////////////////////////////////////////////////////////////
        // Personalisation / Issuance instructions                  //
        //////////////////////////////////////////////////////////////

        case INS_ISSUE_CREDENTIAL:
          debugMessage("INS_ISSUE_CREDENTIAL");
          if (!pin_verified(credPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) &&
              (Lc == 2 + SIZE_H + 2 || Lc == 2 + SIZE_H + 2 + SIZE_TIMESTAMP))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 != 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

          // Prevent reissuance of a credential
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == public.issuanceSetup.id) {
              debugWarning("Credential already exists");
              ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED_AGAIN);
            }
          }

          // Create a new credential
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == 0) {
              credential = &credentials[i];
              credential->id = public.issuanceSetup.id;
              credential->size = public.issuanceSetup.size;
              credential->flags = public.issuanceSetup.flags;
              COPYN(SIZE_H, credential->proof.context, public.issuanceSetup.context);
              debugHash("Initialised context", credential->proof.context);

              // Create new log entry
              log_new_entry();
              COPYN(SIZE_TIMESTAMP, log->timestamp, public.issuanceSetup.timestamp);
              COPYN(SIZE_TERMINAL_ID, log->terminal, terminal);
              log->action = ACTION_ISSUE;
              log->credential = credential->id;

              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }

          // Out of space (all credential slots are occupied)
          debugWarning("Cannot issue another credential");
          ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED);

        case INS_ISSUE_PUBLIC_KEY:
          debugMessage("INS_ISSUE_PUBLIC_KEY");
          if (!pin_verified(credPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          switch (P1) {
            case P1_PUBLIC_KEY_N:
              debugMessage("P1_PUBLIC_KEY_N");
              COPYN(SIZE_N, credential->issuerKey.n, public.apdu.data);
              debugNumber("Initialised isserKey.n", credential->issuerKey.n);
              break;

            case P1_PUBLIC_KEY_Z:
              debugMessage("P1_PUBLIC_KEY_Z");
              COPYN(SIZE_N, credential->issuerKey.Z, public.apdu.data);
              debugNumber("Initialised isserKey.Z", credential->issuerKey.Z);
              break;

            case P1_PUBLIC_KEY_S:
              debugMessage("P1_PUBLIC_KEY_S");
              COPYN(SIZE_N, credential->issuerKey.S, public.apdu.data);
              debugNumber("Initialised isserKey.S", credential->issuerKey.S);
              crypto_compute_S_();
              debugNumber("Initialised isserKey.S_", credential->issuerKey.S_);
              break;

            case P1_PUBLIC_KEY_R:
              debugMessage("P1_PUBLIC_KEY_R");
              if (P2 > MAX_ATTR) {
                ReturnSW(ISO7816_SW_WRONG_P1P2);
              }
              COPYN(SIZE_N, credential->issuerKey.R[P2], public.apdu.data);
              debugNumberI("Initialised isserKey.R", credential->issuerKey.R, P2);
              break;
              
            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
		  ReturnSW(ISO7816_SW_NO_ERROR);
          
        case INS_ISSUE_ATTRIBUTES:
          debugMessage("INS_ISSUE_ATTRIBUTES");
          if (!pin_verified(credPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(3)) && Lc == SIZE_M)) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 == 0 || P1 > credential->size) {
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
          ReturnSW(ISO7816_SW_NO_ERROR);

        case INS_ISSUE_COMMITMENT:
          debugMessage("INS_ISSUE_COMMITMENT");
          if (!pin_verified(credPIN)) {
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

        case INS_ISSUE_COMMITMENT_PROOF:
          debugMessage("INS_ISSUE_COMMITMENT_PROOF");
          if (!pin_verified(credPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
		  if (!(wrapped || CheckCase(1))) {
			ReturnSW(ISO7816_SW_WRONG_LENGTH);
		  }

          switch (P1) {
            case P1_PROOF_C:
              debugMessage("P1_COMMITMENT_PROOF_C");
              COPYN(SIZE_H, public.apdu.data, session.issue.challenge);
              debugHash("Returned c", public.apdu.data);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_H);

            case P1_PROOF_VPRIMEHAT:
              debugMessage("P1_COMMITMENT_PROOF_VPRIMEHAT");
              COPYN(SIZE_VPRIME_, public.apdu.data, session.issue.vPrimeHat);
              debugValue("Returned vPrimeHat", public.apdu.data, SIZE_VPRIME_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_VPRIME_);

            case P1_PROOF_SHAT:
              debugMessage("P1_COMMITMENT_PROOF_SHAT");
              COPYN(SIZE_S_, public.apdu.data, session.issue.sHat);
              debugValue("Returned s_A", public.apdu.data, SIZE_S_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_S_);

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

        case INS_ISSUE_CHALLENGE:
          debugMessage("INS_ISSUE_CHALLENGE");
          if (!pin_verified(credPIN)) {
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

        case INS_ISSUE_SIGNATURE:
          debugMessage("INS_ISSUE_SIGNATURE");
          if (!pin_verified(credPIN)) {
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
              break;

            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_E)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_E, credential->signature.e, public.apdu.data);
              debugValue("Initialised signature.e", credential->signature.e, SIZE_E);
              break;

            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_V)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              constructSignature();
              debugValue("Initialised signature.v", credential->signature.v, SIZE_V);
              break;

            case P1_SIGNATURE_VERIFY:
              debugMessage("P1_SIGNATURE_VERIFY");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              verifySignature();
              debugMessage("Verified signature");
              break;

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
		  ReturnSW(ISO7816_SW_NO_ERROR);

        case INS_ISSUE_SIGNATURE_PROOF:
          debugMessage("INS_ISSUE_SIGNATURE_PROOF");
          if (!pin_verified(credPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          
          switch(P1) {
            case P1_PROOF_C:
              debugMessage("P1_SIGNATURE_PROOF_C");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_H)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_H, credential->proof.challenge, public.apdu.data);
              debugHash("Initialised c", credential->proof.challenge);
              break;

            case P1_PROOF_S_E:
              debugMessage("P1_SIGNATURE_PROOF_S_E");
              if (!((wrapped || CheckCase(3)) && Lc == SIZE_N)) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              COPYN(SIZE_N, credential->proof.response, public.apdu.data);
              debugNumber("Initialised s_e", credential->proof.response);
              break;

            case P1_PROOF_VERIFY:
              debugMessage("P1_SIGNATURE_PROOF_VERIFY");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

              verifyProof();
              debugMessage("Verified proof");
              break;

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
		  ReturnSW(ISO7816_SW_NO_ERROR);

        //////////////////////////////////////////////////////////////
        // Disclosure / Proving instructions                        //
        //////////////////////////////////////////////////////////////

        case INS_PROVE_CREDENTIAL:
          debugMessage("INS_PROVE_CREDENTIAL");
          if (!((wrapped || CheckCase(3)) &&
              (Lc == SIZE_H || Lc == SIZE_H + SIZE_TIMESTAMP || Lc == SIZE_H + SIZE_TIMESTAMP + SIZE_TERMINAL_ID))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 != 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

          // FIXME: should be done during auth.
          COPYN(SIZE_TERMINAL_ID, terminal, public.verificationSetup.terminal);

          // Lookup the given credential ID and select it if it exists
          for (i = 0; i < MAX_CRED; i++) {
            if (credentials[i].id == public.verificationSetup.id) {
              credential = &credentials[i];
#ifndef SIMULATOR
              COPYN(SIZE_H, public.prove.context, public.verificationSetup.context);
              debugHash("Initialised context", public.prove.context);
#else // SIMULATOR
              COPYN(SIZE_H, session.prove.context, public.verificationSetup.context);
              debugHash("Initialised context", session.prove.context);
#endif // SIMULATOR

              // Create new log entry
              log_new_entry();
              COPYN(SIZE_TIMESTAMP, log->timestamp, public.verificationSetup.timestamp);
              COPYN(SIZE_TERMINAL_ID, log->terminal, terminal);
              log->action = ACTION_PROVE;
              log->credential = credential->id;

			  selectAttributes(public.verificationSetup.selection);

              ReturnSW(ISO7816_SW_NO_ERROR);
            }
          }
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);

        case INS_PROVE_COMMITMENT:
          debugMessage("INS_PROVE_COMMITMENT");
          if (pin_required && !pin_verified(credPIN)) {
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

        case INS_PROVE_SIGNATURE:
          debugMessage("INS_PROVE_SIGNATURE");
          if (pin_required && !pin_verified(credPIN)) {
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

#ifndef SIMULATOR
              COPYN(SIZE_N, public.apdu.data, public.prove.APrime);
#else // SIMULATOR
              COPYN(SIZE_N, public.apdu.data, session.prove.APrime);
#endif // SIMULATOR
              debugNumber("Returned A'", public.apdu.data);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_N);

            case P1_SIGNATURE_E:
              debugMessage("P1_SIGNATURE_E");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

#ifndef SIMULATOR
              COPYN(SIZE_E_, public.apdu.data, public.prove.eHat);
#else // SIMULATOR
              COPYN(SIZE_E_, public.apdu.data, session.prove.eHat);
#endif // SIMULATOR
              debugValue("Returned e^", public.apdu.data, SIZE_E_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_E_);

            case P1_SIGNATURE_V:
              debugMessage("P1_SIGNATURE_V");
              if (!(wrapped || CheckCase(1))) {
                ReturnSW(ISO7816_SW_WRONG_LENGTH);
              }

#ifndef SIMULATOR
              COPYN(SIZE_V_, public.apdu.data, public.prove.vHat);
#else // SIMULATOR
              COPYN(SIZE_V_, public.apdu.data, session.prove.vHat);
#endif // SIMULATOR
              debugValue("Returned v^", public.apdu.data, SIZE_V_);
              ReturnLa(ISO7816_SW_NO_ERROR, SIZE_V_);

            default:
              debugWarning("Unknown parameter");
              ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

        case INS_PROVE_ATTRIBUTE:
          debugMessage("INS_PROVE_ATTRIBUTE");
          if (pin_required && !pin_verified(credPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1 > credential->size) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }
          
          if (disclosed(P1)) {
            COPYN(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
            debugValue("Returned attribute", public.apdu.data, SIZE_M);
            ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M);
          } else {
            COPYN(SIZE_M_, public.apdu.data, session.prove.mHat[P1]);
            debugValue("Returned response", public.apdu.data, SIZE_M_);
            ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M_);
	      }


        //////////////////////////////////////////////////////////////
        // Administration instructions                              //
        //////////////////////////////////////////////////////////////

        case INS_ADMIN_CREDENTIALS:
          debugMessage("INS_ADMIN_CREDENTIALS");
          if (!pin_verified(cardPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          for (i = 0; i < MAX_CRED; i++) {
            ((short*) public.apdu.data)[i] = credentials[i].id;
          }

          ReturnLa(ISO7816_SW_NO_ERROR, 2*MAX_CRED);
          break;

        case INS_ADMIN_CREDENTIAL:
          debugMessage("INS_ADMIN_CREDENTIAL");
          if (!pin_verified(cardPIN)) {
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

        case INS_ADMIN_ATTRIBUTE:
          debugMessage("INS_ADMIN_ATTRIBUTE");
          if (!pin_verified(cardPIN)) {
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

          COPYN(SIZE_M, public.apdu.data, credential->attribute[P1 - 1]);
          debugValue("Returned attribute", public.apdu.data, SIZE_M);
          ReturnLa(ISO7816_SW_NO_ERROR, SIZE_M);
          break;

        case INS_ADMIN_REMOVE:
          debugMessage("INS_ADMIN_REMOVE");
          if (!pin_verified(cardPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(1)) ||
              ((wrapped || CheckCase(3)) && (Lc == SIZE_TIMESTAMP)))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          if (P1P2 == 0) {
            ReturnSW(ISO7816_SW_WRONG_P1P2);
          }

          // Verify the given credential ID and remove it if it matches
          if (credential->id == P1P2) {
            crypto_clear_credential();
            debugInteger("Removed credential", P1P2);

            // Create new log entry
            log_new_entry();
            COPYN(SIZE_TIMESTAMP, log->timestamp, public.apdu.data);
            COPYN(SIZE_TERMINAL_ID, log->terminal, terminal);
            log->action = ACTION_REMOVE;
            log->credential = P1P2;

            ReturnSW(ISO7816_SW_NO_ERROR);
          }
          
          ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
          break;

        case INS_ADMIN_FLAGS:
          debugMessage("INS_ADMIN_FLAGS");
          if (!pin_verified(cardPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (credential == NULL) {
            ReturnSW(ISO7816_SW_CONDITIONS_NOT_SATISFIED);
          }
          if (!((wrapped || CheckCase(1)) ||
              ((wrapped || CheckCase(3)) && (Lc == SIZE_FLAGS)))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }
          
          if (Lc > 0) {
            credential->flags = (short) public.apdu.data;
            debugInteger("Updated flags", credential->flags);
            ReturnSW(ISO7816_SW_NO_ERROR);
          } else {
            public.apdu.data[0] = credential->flags >> 8;
            public.apdu.data[1] = credential->flags & 0xff;
            debugInteger("Returned flags", (short) public.apdu.data);
            ReturnLa(ISO7816_SW_NO_ERROR, 2);
          }
          break;

        case INS_ADMIN_LOG:
          debugMessage("INS_ADMIN_LOG");
          if (!pin_verified(cardPIN)) {
            ReturnSW(ISO7816_SW_SECURITY_STATUS_NOT_SATISFIED);
          }
          if (!(wrapped || CheckCase(1))) {
            ReturnSW(ISO7816_SW_WRONG_LENGTH);
          }

          for (i = 0; i < 255 / sizeof(LogEntry); i++) {
            log_get_entry(P1 + i);
            memcpy(public.apdu.data + i*sizeof(LogEntry), log, sizeof(LogEntry));
          }
          ReturnLa(ISO7816_SW_NO_ERROR, (255 / sizeof(LogEntry)) * sizeof(LogEntry));
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
