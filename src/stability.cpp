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
 stability.cpp

 Functions for stability test
 *****************************************************************************/

#include "stability.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>


extern CK_FUNCTION_LIST_PTR p11;

int testStability(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession, int rollovers, int batchjobs, int signatures, int sleepTime)
{
	CK_RV rv;
	int retVal = 0;
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CK_SESSION_HANDLE hSessionTmp;
	CK_BYTE_PTR pSignature = NULL;
        CK_ULONG ulSignatureLen = 0;
	CK_BYTE pData[] = {"Text"};
	CK_ULONG ulDataLen = sizeof(pData)-1;

	printf("\n********************************************************\n");
	printf("* Test for stability during key generation and signing *\n");
	printf("********************************************************\n\n");
	printf("This test will perform the following:\n\n");
	printf("* Key rollovers = %i\n", rollovers);
	printf("  The number of times that the key pair will be replaced.\n");
	printf("* Batchjobs = %i\n", batchjobs);
	printf("  The number of batchjobs for each key pair.\n");
	printf("* signatures = %i\n", signatures);
	printf("  Each batchjob will create signatures and verify them.\n");
	printf("* sleep time = %i\n", sleepTime);
	printf("  The process will sleep between the batchjobs.\n\n");

	for (int i = 0; i <= rollovers; i++)
	{
		// Generate key pair
		if (testStability_generate(hSession, &hPublicKey, &hPrivateKey))
		{
			retVal = 1;
			continue;
		}

		for (int j = 0; j < batchjobs; j++)
		{
			// Open Session
			rv = p11->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSessionTmp);
			if (rv != CKR_OK)
			{
				printf("ERROR: Failed to open a session. rv=%s\n", rv2string(rv));
				retVal = 1;
				continue;
			}

			printf("Creating signatures and verifying them...\n");

			for (int k = 0; k < signatures; k++)
			{
				// Sign data
				if (testStability_sign(
					hSessionTmp,
					hPrivateKey,
					pData,
					ulDataLen,
					&pSignature,
					&ulSignatureLen))
				{
					retVal = 1;
					continue;
				}

				// Verify signature
				if (testStability_verify(
					hSessionTmp,
					hPublicKey,
					pData,
					ulDataLen,
					pSignature,
					ulSignatureLen))
				{
					retVal = 1;
				}

				// Clean up
				if (pSignature != NULL)
				{
					free(pSignature);
					pSignature = NULL;
					ulSignatureLen = 0;
				}
			}

			// Close session
			rv = p11->C_CloseSession(hSessionTmp);
			if (rv != CKR_OK)
			{
				printf("ERROR: Failed to close session. rv=%s\n", rv2string(rv));
				retVal = 1;
			}

			// Sleep
			printf("Sleeping for %i seconds...\n", sleepTime);
			sleep(sleepTime);
		}

		// Delete key pair
		printf("Deleting the key pair...\n");
		rv = p11->C_DestroyObject(hSession, hPublicKey);
		if (rv != CKR_OK)
		{
			printf("ERROR: Failed to delete the public key. rv=%s\n", rv2string(rv));
			retVal = 1;
		}
		rv = p11->C_DestroyObject(hSession, hPrivateKey);
		if (rv != CKR_OK)
		{
			printf("ERROR: Failed to delete the private key. rv=%s\n", rv2string(rv));
			retVal = 1;
		}
	}

	if (retVal == 0)
	{
		printf("\nThe test was performed successfully.\n");
	}
	else
	{
		printf("\nThe test was not performed successfully.\n");
	}

	return retVal;
}

int testStability_generate(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE *hPublicKey, CK_OBJECT_HANDLE *hPrivateKey)
{
	CK_RV rv;
	CK_BBOOL ckTrue = CK_TRUE;
	CK_MECHANISM keyGenMechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_BYTE publicExponent[] = { 1, 0, 1 };
	CK_ULONG modulusBits = 1024;
	CK_MECHANISM mechanism = {
		CKM_VENDOR_DEFINED, NULL_PTR, 0
	};

	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) },
		{ CKA_VERIFY, &ckTrue, sizeof(ckTrue) },
		{ CKA_WRAP, &ckTrue, sizeof(ckTrue) },
		{ CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
		{ CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits) },
		{ CKA_PUBLIC_EXPONENT, &publicExponent, sizeof(publicExponent) }
	};
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_PRIVATE, &ckTrue, sizeof(ckTrue) },
		{ CKA_SENSITIVE, &ckTrue, sizeof(ckTrue) },
		{ CKA_DECRYPT, &ckTrue, sizeof(ckTrue) },
		{ CKA_SIGN, &ckTrue, sizeof(ckTrue) },
		{ CKA_UNWRAP, &ckTrue, sizeof(ckTrue) },
		{ CKA_TOKEN, &ckTrue, sizeof(ckTrue) }
	};

	printf("Generating a key pair...\n");
	rv = p11->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 6, hPublicKey, hPrivateKey);
	if (rv != CKR_OK)
	{
		printf("ERROR: Failed to generate a keypair. rv=%s\n", rv2string(rv));
		return 1;
	}

	return 0;
}

int testStability_sign
(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hPrivateKey,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR *ppSignature,
	CK_ULONG_PTR pulSignatureLen
)
{
	CK_RV rv;
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};

	rv = p11->C_SignInit(hSession, &mechanism, hPrivateKey);
	if (rv != CKR_OK)
	{
		printf("ERROR: Failed to initialize signing. rv=%s\n", rv2string(rv));
		return 1;
	}

	*pulSignatureLen = 0;
	rv = p11->C_Sign(hSession, pData, ulDataLen, NULL_PTR, pulSignatureLen);
	if (rv != CKR_OK)
	{
		printf("ERROR: Failed to check the size of the signature. rv=%s\n", rv2string(rv));
		return 1;
	}
	*ppSignature = (CK_BYTE_PTR)malloc(*pulSignatureLen);

	rv = p11->C_Sign(hSession, pData, ulDataLen, *ppSignature, pulSignatureLen);
	if (rv != CKR_OK)
	{
		printf("ERROR: Failed to sign the data. rv=%s\n", rv2string(rv));
		free(*ppSignature);
		*ppSignature = NULL;
		*pulSignatureLen = 0;
		return 1;
	}

	return 0;
}

int testStability_verify
(
	CK_SESSION_HANDLE hSession,
	CK_OBJECT_HANDLE hPublicKey,
	CK_BYTE_PTR pData,
	CK_ULONG ulDataLen,
	CK_BYTE_PTR pSignature,
	CK_ULONG ulSignatureLen
)
{
	CK_RV rv;
	CK_MECHANISM mechanism = {
		CKM_RSA_PKCS, NULL_PTR, 0
	};

	rv = p11->C_VerifyInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK)
	{
		printf("ERROR: Failed to initialize verification. rv=%s\n", rv2string(rv));
		return 1;
	}

	rv = p11->C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
	if (rv != CKR_OK)
	{
		printf("ERROR: Failed to verify signature. rv=%s\n", rv2string(rv));
		return 1;
	}

	return 0;
}
