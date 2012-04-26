/**
 * defs_test.h
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
 * Copyright (C) Pim Vullers, Radboud University Nijmegen, January 2012.
 */
 
#ifndef __defs_test_H
#define __defs_test_H

#ifdef TEST

#include "defs_sizes.h"
#include "defs_types.h"

const Byte TEST_vPrime[SIZE_VPRIME] = { 0xAE, 0x47, 0x2C, 0xE1, 0x85, 0xE9, 0x48, 0x43, 0x85, 0xB2, 0xB9, 0xD6, 0xCA, 0x64, 0xFD, 0x44, 0xAC, 0x3E, 0x45, 0x68, 0x8A, 0x78, 0x03, 0x89, 0xB7, 0x3B, 0x4F, 0x0C, 0x26, 0x6F, 0x11, 0x02, 0x91, 0x79, 0x8C, 0x30, 0x3B, 0x0C, 0x7C, 0x28, 0xED, 0xFE, 0xBC, 0xEA, 0x0B, 0x78, 0x3F, 0x13, 0x8A, 0xB0, 0x0C, 0x87, 0x3B, 0x82, 0x0B, 0x8F, 0x77, 0xD6, 0x59, 0x12, 0x72, 0x86, 0x42, 0x9A, 0x18, 0x4C, 0x28, 0xE1, 0x22, 0x74, 0x3E, 0x31, 0x73, 0x14, 0x87, 0xD6, 0xD0, 0x49, 0xC9, 0x81, 0xD0, 0x9D, 0xEC, 0x7D, 0xB0, 0x90, 0x92, 0x23, 0xC7, 0x65, 0xE5, 0x02, 0x7C, 0x3A, 0x4D, 0x7B, 0x64, 0xF6, 0x1F, 0xAC, 0xDA, 0x5F, 0xD9, 0xD2, 0x0B, 0xDE, 0xA1, 0x31, 0xEF, 0x2A, 0x16, 0xED, 0x50, 0x8E, 0x53, 0x93, 0xC6, 0x32, 0xF2, 0x8E, 0xD6, 0x03, 0xE7, 0x24, 0xAC, 0xE9, 0xE9, 0x22, 0x41, 0x0E, 0x2D, 0x6F, 0x85, 0xBA, 0x4B, 0x25, 0xDC, 0x8C };
const Byte TEST_vPrime_[SIZE_VPRIME_] = { 0xF8, 0x7E, 0xFB, 0x69, 0x25, 0x65, 0x9C, 0xA7, 0x7D, 0xC2, 0x24, 0x70, 0x69, 0xD8, 0x4F, 0xC7, 0xCA, 0xA6, 0x03, 0x18, 0xC4, 0x22, 0x2A, 0x9F, 0xA1, 0x6E, 0x30, 0x3B, 0x92, 0x23, 0x43, 0x67, 0x90, 0x9A, 0xB4, 0xE0, 0x82, 0xFC, 0xDF, 0x66, 0x69, 0x2D, 0x98, 0xFE, 0x01, 0x9E, 0x86, 0xDF, 0x03, 0x47, 0xFA, 0xD1, 0xAF, 0x09, 0xAE, 0x55, 0xF7, 0xE6, 0xC0, 0xF7, 0x36, 0x58, 0x6C, 0xBD, 0x9B, 0x14, 0xBC, 0x23, 0xF5, 0x56, 0xF2, 0x9D, 0xCA, 0x1C, 0xA7, 0x90, 0x18, 0xC8, 0xAC, 0x61, 0x1E, 0x21, 0x20, 0x2A, 0x3F, 0xDE, 0x1A, 0x9F, 0xB5, 0x0C, 0x0C, 0xD9, 0x04, 0x42, 0x71, 0xEC, 0xA4, 0xA0, 0xC3, 0x59, 0x50, 0x06, 0x08, 0x5F, 0xC2, 0x89, 0x1F, 0x72, 0xC8, 0x8C, 0x63, 0xCF, 0x79, 0xE8, 0x43, 0xF2, 0x1C, 0x9C, 0xA4, 0x26, 0xA8, 0x08, 0xBC, 0x1A, 0x43, 0x29, 0x71, 0x12, 0xC7, 0xC3, 0x4A, 0x12, 0x59, 0x67, 0xB8, 0x5B, 0xEB, 0x42, 0x49, 0xEF, 0xCC, 0x2C, 0x16, 0x45, 0x5C, 0xF7, 0x96, 0xA0, 0x85, 0x1D, 0x50, 0xEE, 0xEB, 0x11, 0x5A, 0xA0, 0x8A, 0x58, 0xC2, 0xDF, 0x86, 0xD1, 0xF0, 0x8C, 0x40, 0xE5, 0xC4, 0x7D };
const Byte TEST_m_[SIZE_S_A] = { 0x01, 0x8C, 0xB1, 0xBF, 0xAA, 0xD3, 0x40, 0x27, 0x14, 0xE7, 0x96, 0xB4, 0xE2, 0xF7, 0xDC, 0x72, 0x46, 0x95, 0x0A, 0x07, 0x4D, 0x0A, 0x5F, 0x78, 0x2E, 0x25, 0x00, 0x56, 0x11, 0xFC, 0x63, 0x74, 0xFD, 0xC3, 0x95, 0xDE, 0x21, 0x02, 0x35, 0x12, 0x99, 0x07, 0x42, 0xAC, 0xC7, 0x0F, 0xBA, 0x8A, 0xED, 0x6F, 0xB6, 0x8F, 0x17, 0xA4, 0xD8, 0x4C, 0x7A, 0x27, 0x48, 0x6E, 0x56, 0x09, 0x9C };
const Byte TEST_n_2[SIZE_STATZK] = { 0x7B, 0xAF, 0x54, 0xEC, 0xE6, 0xCA, 0xDE, 0x70, 0x2C, 0xB8 };
const Byte TEST_r_A[SIZE_R_A] = { 0x01, 0xA7, 0xB7, 0x47, 0x00, 0x63, 0x34, 0x5F, 0x87, 0x21, 0x2D, 0x62, 0xF9, 0xD4, 0xE8, 0xEA, 0x4E, 0xCA, 0x78, 0xE6, 0xA6, 0xA7, 0x1D, 0xE6, 0x4D, 0xBF, 0x27, 0x39, 0x70, 0xAF, 0xD4, 0xBA, 0xF8, 0x05, 0x68, 0xF3, 0xBB, 0x98, 0x78, 0xC5, 0x6E, 0xB8, 0x57, 0xF4, 0x1D, 0x34, 0x47, 0x75, 0x36, 0xB4, 0x05, 0x8A, 0x2B, 0x88, 0xBD, 0xCA, 0xBD, 0x51, 0x5C, 0xC2, 0xC1, 0x73, 0x64, 0x62, 0x67, 0xB9, 0x52, 0x73, 0x1C, 0x6B, 0xF8, 0x63, 0x2D, 0x33, 0x33, 0x68, 0x33, 0x96, 0x11, 0xB4, 0x81, 0x12, 0xDA, 0x7C, 0xEB, 0xD1, 0x12, 0x81, 0x98, 0x7B, 0x04, 0x00, 0x35, 0xD6, 0xA6, 0x3E, 0x62, 0x36, 0xC1, 0xFF, 0x90, 0xC7, 0x73, 0x92, 0x40, 0xD3, 0xDD, 0xEE, 0x90, 0x5B, 0xE7, 0x3B, 0x75, 0x97, 0x12, 0x97, 0x1E, 0x12, 0x4C, 0xCB, 0x85, 0x2E, 0x9F, 0xD4, 0x54, 0xFF, 0x91, 0x04, 0x08, 0x3A, 0x7A, 0xF9, 0x99, 0x10, 0xB3, 0x50, 0x92, 0x89 };
const Byte TEST_m_0[SIZE_M_] = { 0x76, 0x22, 0xFF, 0xA2, 0x85, 0x14, 0xB7, 0x96, 0x50, 0xD9, 0x8E, 0x49, 0xB0, 0xC6, 0xCD, 0x9A, 0x55, 0x82, 0x16, 0xFE, 0x3E, 0xE4, 0xDD, 0xC5, 0x51, 0x40, 0x5F, 0x78, 0xE4, 0xAC, 0xD1, 0x4C, 0x0B, 0xA0, 0x60, 0x40, 0x9D, 0xE1, 0x0A, 0xE1, 0x06, 0x00, 0xCC, 0xAF, 0xF6, 0x73, 0x4A, 0xC6, 0x35, 0x3B, 0xB7, 0x24, 0x6E, 0x92, 0x99, 0x97, 0xC3, 0x75, 0xE0, 0x36, 0xDD, 0xA9 };
const Byte TEST_m_1[SIZE_M_] = { 0xE5, 0xB5, 0xC4, 0xB0, 0x3E, 0x78, 0xF8, 0xC4, 0x6D, 0x63, 0x72, 0x65, 0xE5, 0x78, 0x22, 0xCD, 0x57, 0xF7, 0x09, 0x94, 0x36, 0x1C, 0xD2, 0xBE, 0xDF, 0x81, 0x27, 0xFF, 0x10, 0x92, 0xBD, 0x38, 0x21, 0x03, 0x8A, 0x1F, 0xE7, 0x32, 0x90, 0x6D, 0xD1, 0x3A, 0x97, 0x97, 0xCC, 0x26, 0x7E, 0x42, 0x14, 0xD9, 0xCB, 0x75, 0x61, 0x47, 0x83, 0x8D, 0xB3, 0x34, 0xD1, 0xE6, 0x44, 0x52 };
const Byte TEST_m_2[SIZE_M_] = { 0xF1, 0xDB, 0x78, 0x71, 0xB6, 0x69, 0xCE, 0x64, 0xD0, 0xC7, 0x5F, 0x91, 0xEC, 0xFB, 0xC9, 0x7C, 0x6E, 0x8A, 0xEE, 0x0B, 0x9C, 0xAE, 0x90, 0x68, 0x4D, 0x4B, 0x80, 0x0F, 0x1B, 0x2C, 0x65, 0x0D, 0x70, 0x55, 0x9F, 0x96, 0x25, 0x72, 0xC1, 0x43, 0x43, 0x42, 0x63, 0x9B, 0x07, 0x39, 0x55, 0x76, 0x15, 0xA5, 0x8B, 0x25, 0xB3, 0xDA, 0x59, 0xA1, 0xE2, 0x05, 0x92, 0xA0, 0x90, 0x91 };
const Byte TEST_m_3[SIZE_M_] = { 0x22, 0x30, 0xF0, 0x71, 0xF1, 0x88, 0x3E, 0x51, 0x26, 0x5E, 0x06, 0x38, 0x0C, 0x4A, 0x59, 0x36, 0x0C, 0x35, 0x07, 0x7C, 0x4B, 0x7B, 0x98, 0xE3, 0x30, 0x90, 0xFA, 0x43, 0x7A, 0x23, 0xC7, 0x8F, 0xAC, 0x7C, 0x80, 0x8C, 0xF3, 0xD4, 0x0A, 0xE1, 0xE2, 0xF9, 0x76, 0xAA, 0x26, 0x1E, 0x70, 0xBC, 0x02, 0xCA, 0xE5, 0x99, 0x17, 0x3A, 0x5D, 0x98, 0x42, 0x34, 0x6E, 0xB8, 0x80, 0x32 };
const Byte TEST_e_[SIZE_E_] = { 0xBB, 0xB5, 0xAB, 0xB7, 0x45, 0x2E, 0x6E, 0x1A, 0x92, 0xDB, 0xE4, 0x8A, 0x17, 0x8B, 0xB1, 0xD7, 0xD4, 0x32, 0xE7, 0x69, 0x30, 0xDD, 0xDD, 0xA5, 0xFF, 0x66, 0x22, 0xD7, 0x6D, 0x25, 0xB3, 0x9B, 0x9F, 0x3F, 0xD1, 0xB4, 0xB1, 0x66, 0x0D, 0x69, 0xA9, 0x87, 0xD0, 0xBB, 0x47 };
const Byte TEST_v_[SIZE_V_] = { 0x0D, 0x6D, 0x04, 0x95, 0x5A, 0xC3, 0x5F, 0x1A, 0x2D, 0x02, 0x68, 0x81, 0x6B, 0x39, 0x46, 0xF6, 0xC5, 0x0A, 0x82, 0xB1, 0x56, 0x88, 0x89, 0x99, 0x20, 0x8B, 0xE9, 0xDD, 0x27, 0x57, 0xF6, 0x86, 0x2E, 0xAD, 0x7D, 0xBD, 0xF5, 0x98, 0x60, 0x92, 0x25, 0xDD, 0x27, 0xF1, 0x10, 0x3A, 0x15, 0x42, 0x27, 0x10, 0x42, 0x99, 0x27, 0xCC, 0x4C, 0xC9, 0x5F, 0x01, 0x35, 0x4D, 0xC2, 0xAB, 0x42, 0x8E, 0x72, 0x5C, 0xF8, 0xA2, 0x75, 0x96, 0xB7, 0xB2, 0x5E, 0xB8, 0xBA, 0x78, 0x0A, 0x61, 0x3C, 0x81, 0xB7, 0x50, 0x6C, 0x2A, 0x5B, 0xEC, 0xC5, 0x40, 0xB0, 0x14, 0x9B, 0x1D, 0xFE, 0xB4, 0xDD, 0x3D, 0x15, 0xB7, 0xD6, 0xED, 0x14, 0xD8, 0xF6, 0x41, 0x6C, 0x73, 0x67, 0xC2, 0x58, 0x63, 0x00, 0x11, 0x5D, 0xC9, 0x2C, 0xC8, 0x45, 0xEA, 0x63, 0x5F, 0xF7, 0x9F, 0x9A, 0xE0, 0x41, 0x7D, 0x5E, 0x3F, 0x43, 0x3E, 0x55, 0xC2, 0xE9, 0xEC, 0xAD, 0xBA, 0x7F, 0x7D, 0x4F, 0x64, 0x47, 0x60, 0xA3, 0x66, 0xC0, 0x4F, 0xCB, 0x01, 0x8E, 0x45, 0xCB, 0x3B, 0x0F, 0x55, 0x9E, 0x08, 0xAB, 0x15, 0x9F, 0x6E, 0x97, 0x6E, 0xBB, 0xF3, 0x64, 0x48, 0x45, 0x9F, 0x1B, 0x9E, 0xA5, 0xF1, 0xF7, 0xE7, 0x11, 0x59, 0xD7, 0x99, 0x98, 0xA8, 0xE7, 0x60, 0x43, 0x28, 0x77, 0x34, 0x54, 0x16, 0xC7, 0x9B, 0x24, 0xD1, 0x84, 0xBA, 0x72, 0xA2, 0xE4, 0x86, 0x72, 0xEF, 0x00, 0x48, 0x95, 0xEE, 0x90, 0x7B, 0x1B, 0xFF, 0xD3, 0x53, 0x65, 0xD1, 0xAA, 0x91, 0xBE, 0xB1, 0xE1, 0xB1, 0x2F, 0x79, 0x3E, 0xE2, 0x36, 0x35, 0xB6, 0xBB, 0x97, 0x1C, 0x89, 0x92, 0xC3 };

#endif // TEST

#endif // __defs_test_H
