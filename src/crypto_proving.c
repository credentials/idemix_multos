/**
 * crypto_proving.c
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, April 2012.
 */

#include "crypto_proving.h"

#include <ISO7816.h>
#include <multosarith.h>
#include <multosccr.h>
#include <multoscrypto.h>

#include "defs_apdu.h"
#include "defs_externals.h"
#include "defs_sizes.h"
#include "defs_types.h"
#include "funcs_debug.h"
#include "crypto_helper.h"
#include "crypto_multos.h"

/********************************************************************/
/* Proving functions                                                */
/********************************************************************/

/**
 * Select the attributes to be disclosed.
 *
 * @param selection bitmask of attributes to be disclosed.
 */
void selectAttributes(int selection) {

  // Do not allow modification of the selection within a protocol session.
  if (session.prove.disclose != 0) {
    debugError("selectAttributes(): selection cannot be modified once set");
    ReturnSW(ISO7816_SW_COMMAND_NOT_ALLOWED_AGAIN);
  }

  // Never disclose the master secret.
  if (selection & 0x0001 != 0) {
    debugError("selectAttributes(): master secret cannot be disclosed");
    credential = NULL;
    ReturnSW(ISO7816_SW_WRONG_DATA);
  }

#ifdef EXPIRY
  // Always disclose the expiry attribute.
  if (selection & 0x0002 == 0) {
    debugError("selectAttributes(): expiry attribute must be disclosed");
    credential = NULL;
    ReturnSW(ISO7816_SW_WRONG_DATA);
  }
#endif // EXPIRY

  // Do not allow non-existant attributes.
  if (selection & (0xFFFF << credential->size + 1) != 0) {
    debugError("selectAttributes(): selection contains non-existant attributes");
    credential = NULL;
    ReturnSW(ISO7816_SW_REFERENCED_DATA_NOT_FOUND);
  }

  // Set the attribute disclosure selection.
  session.prove.disclose = selection;
  debugInteger("Disclosure selection", session.prove.disclose);
  log->details.prove.selection = selection;
}

/**
 * Construct a proof.
 */
void constructProof(void) {
  int i;

#ifdef SIMULATOR
  // Get context from session memory since the simulator clears public
  COPYN(SIZE_H, public.prove.context, session.prove.context);
#endif // SIMULATOR

  // Generate random values for m~[i], e~, v~ and rA
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      // IMPORTANT: Correction to the length of mTilde to prevent overflows
      crypto_generate_random(session.prove.mHat[i], LENGTH_M_ - 1);
    }
  }
  debugValues("mTilde", (ByteArray) session.prove.mHat, SIZE_M_, SIZE_L);
  // IMPORTANT: Correction to the length of eTilde to prevent overflows
  crypto_generate_random(public.prove.eHat, LENGTH_E_ - 1);
  debugValue("eTilde", public.prove.eHat, SIZE_E_);
  // IMPORTANT: Correction to the length of vTilde to prevent overflows
  crypto_generate_random(public.prove.vHat, LENGTH_V_ - 1);
  debugValue("vTilde", public.prove.vHat, SIZE_V_);
  // IMPORTANT: Correction to the length of rA to prevent negative values
  crypto_generate_random(public.prove.rA + 1, LENGTH_R_A - 13);
  debugValue("rA", public.prove.rA, SIZE_R_A);

  // Compute A' = A * S^r_A
  // IMPORTANT: Correction to the size of rA to skip initial zero bytes
  crypto_modexp_special(SIZE_R_A - 1, public.prove.rA + 1, public.prove.APrime,
    public.prove.buffer.number[0]);
  debugValue("A' = S^r_A mod n", public.prove.APrime, SIZE_N);
  crypto_modmul(SIZE_N, public.prove.APrime, credential->signature.A, credential->issuerKey.n);
  debugValue("A' = A' * A mod n", public.prove.APrime, SIZE_N);

  // Compute ZTilde = A'^eTilde * S^vTilde * (R[i]^mTilde[i] foreach i not in D)
  crypto_modexp_special(SIZE_V_, public.prove.vHat, public.prove.buffer.number[0],
    public.prove.buffer.number[1]);
  debugValue("ZTilde = S^vTilde", public.prove.buffer.number[0], SIZE_N);
  crypto_modexp(SIZE_E_, SIZE_N, public.prove.eHat,
    credential->issuerKey.n, public.prove.APrime, public.prove.buffer.number[1]);
  debugValue("buffer = A'^eTilde", public.prove.buffer.number[1], SIZE_N);
  crypto_modmul(SIZE_N, public.prove.buffer.number[0],
    public.prove.buffer.number[1], credential->issuerKey.n);
  debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_modexp(SIZE_M_, SIZE_N, session.prove.mHat[i], credential->issuerKey.n,
        credential->issuerKey.R[i], public.prove.buffer.number[1]);
      debugValue("R_i^m_i", public.prove.buffer.number[1], SIZE_N);
      crypto_modmul(SIZE_N, public.prove.buffer.number[0],
        public.prove.buffer.number[1], credential->issuerKey.n);
      debugValue("ZTilde = ZTilde * buffer", public.prove.buffer.number[0], SIZE_N);
    }
  }

  // Compute challenge c = H(context | A' | ZTilde | nonce)
  public.prove.list[0].data = public.prove.context;
  public.prove.list[0].size = SIZE_H;
  public.prove.list[1].data = public.prove.APrime;
  public.prove.list[1].size = SIZE_N;
  public.prove.list[2].data = public.prove.buffer.number[0];
  public.prove.list[2].size = SIZE_N;
  public.prove.list[3].data = public.prove.apdu.nonce;
  public.prove.list[3].size = SIZE_STATZK;
  crypto_compute_hash(public.prove.list, 4, public.prove.apdu.challenge,
    public.prove.buffer.data, SIZE_BUFFER_C1);
  debugValue("c", public.prove.apdu.challenge, SIZE_H);

  crypto_compute_ePrime(); // Compute e' = e - 2^(l_e' - 1)
  debugValue("e' = e - 2^(l_e' - 1)",
    credential->signature.e + SIZE_E - SIZE_EPRIME, SIZE_EPRIME);

  crypto_compute_eHat(); // Compute e^ = e~ + c e'
  debugValue("e^ = e~ + c*e'", public.prove.eHat, SIZE_E_);

  crypto_compute_vPrime(); // Compute v' = v - e r_A
  debugValue("v' = v - e*r_A", public.prove.buffer.data, SIZE_V);

  crypto_compute_vHat(); // Compute v^ = v~ + c v'
  debugValue("vHat", public.prove.vHat, SIZE_V_);

  for (i = 0; i <= credential->size; i++) {
    if (disclosed(i) == 0) {
      crypto_compute_mHat(i); // Compute m_i^ = m_i~ + c m_i
    }
  }
  debugValues("mHat", (ByteArray) session.prove.mHat, SIZE_M_, SIZE_L);

#ifdef SIMULATOR
  // Store responses in session memory since the simulator clears public
  COPYN(SIZE_N, session.prove.APrime, public.prove.APrime);
  COPYN(SIZE_E_, session.prove.eHat, public.prove.eHat);
  COPYN(SIZE_V_, session.prove.vHat, public.prove.vHat);
#endif // SIMULATOR

  // return eHat, vHat, mHat[i], c, A'
}
