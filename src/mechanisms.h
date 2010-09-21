/* $Id$ */

/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 mechanisms.h

 Functions for mechanism tests
 *****************************************************************************/

#ifndef _PKCS11_TESTING_MECHANISMS_H
#define _PKCS11_TESTING_MECHANISMS_H

#include "cryptoki.h"

int showMechs(char *slot);
int testDNSSEC(char *slot, char *pin);
int testSuiteB(char *slot, char *pin);

// showMechs helper functions
void printMechInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE mechType);
void printMechKeySize(CK_ULONG ulMinKeySize, CK_ULONG ulMaxKeySize);
void printMechFlags(CK_FLAGS flags);

// testDNSSEC helper functions
int testDNSSEC_digest(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testDNSSEC_rsa_keygen(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testDNSSEC_rsa_sign(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testDNSSEC_dsa_keygen(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testDNSSEC_dsa_sign(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);

// testSuiteB helper functions
int testSuiteB_AES(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testSuiteB_ECDSA(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testSuiteB_ECDH(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);
int testSuiteB_SHA(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession);

// Internal functions
const char* getMechName(CK_MECHANISM_TYPE mechType);

#endif // !_PKCS11_TESTING_MECHANISMS_H
