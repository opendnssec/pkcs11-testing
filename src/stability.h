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
 stability.h

 Functions for stability test
 *****************************************************************************/

#ifndef _PKCS11_TESTING_STABILITY_H
#define _PKCS11_TESTING_STABILITY_H

#include "cryptoki.h"

int testStability(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, int rollovers, int batchjobs, int signatures, int sleepTime);

// Internal
int testStability_generate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *hPublicKey, CK_OBJECT_HANDLE *hPrivateKey);
int testStability_sign(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPrivateKey, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR *ppSignature, CK_ULONG_PTR pulSignatureLen);
int testStability_verify(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

#endif // !_PKCS11_TESTING_STABILITY_H
