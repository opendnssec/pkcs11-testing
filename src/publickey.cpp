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
 publickey.cpp

 Functions for public key tests
 *****************************************************************************/

#include "publickey.h"
#include "session.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>


extern CK_FUNCTION_LIST_PTR p11;

int testRSAPub(char *slot, char *pin)
{
	CK_SLOT_ID slotID;
	CK_RV rv;
	CK_SESSION_HANDLE hSession;
	int retVal = 0;

	CK_BBOOL ckTrue = CK_TRUE;
	CK_MECHANISM keyGenMechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_BYTE publicExponent[] = { 1, 0, 1 };
	CK_ULONG modulusBits = 1024;
	CK_MECHANISM mechanism = {
		CKM_VENDOR_DEFINED, NULL_PTR, 0
	};
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

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

	if (openLogin(slot, pin, &slotID, &hSession))
	{
		return 1;
	}

	printf("\n******************************************************\n");
	printf("* Test for public information in the RSA private key *\n");
	printf("******************************************************\n\n");
	printf("You normally have a public and private key object.\n");
	printf("But the private key could contain all the necessary\n");
	printf("information in order to export the public key from the\n");
	printf("private key object. However, PKCS#11 cannot guarantee\n");
	printf("that the HSM can do this. If the private key object\n");
	printf("has all the necessary information, then you only need\n");
	printf("to keep the private key. Thus saving space in the HSM.\n\n");

	printf("Generate a key pair: ");
	rv = p11->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 6, &hPublicKey, &hPrivateKey);
	if (rv != CKR_OK)
	{
		printf("Failed to generate a keypair. rv=0x%08X\n", rv);
		printf("RSA is probably not supported\n");
		return 1;
	}
	printf("OK\n");

	retVal = testRSAPub_keypair(hSession, hPublicKey, hPrivateKey);

	p11->C_DestroyObject(hSession, hPublicKey);
	p11->C_DestroyObject(hSession, hPrivateKey);
	p11->C_CloseSession(hSession);

	return retVal;
}

int testRSAPub_keypair(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_RV rv;
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_PUBLIC_EXPONENT, NULL_PTR, 0 },
		{ CKA_MODULUS, NULL_PTR, 0 }
	};
	CK_BYTE_PTR public_exponent1 = NULL;
	CK_BYTE_PTR public_exponent2 = NULL;
	CK_ULONG public_exponent_len1 = 0;
	CK_ULONG public_exponent_len2 = 0;
	CK_BYTE_PTR modulus1 = NULL;
	CK_BYTE_PTR modulus2 = NULL;
	CK_ULONG modulus_len1 = 0;
	CK_ULONG modulus_len2 = 0;
	int retVal = 0;

	printf("Public key information from public key object: ");

	// Get buffer sizes
	rv = p11->C_GetAttributeValue(hSession, hPublicKey, pubTemplate,  2);
	if (rv != CKR_OK)
	{
		printf("Failed to get the size of modulus and pubexp. rv=0x%08X\n", rv);
		return 1;
	}

	// Allocate memory
	public_exponent_len1 = pubTemplate[0].ulValueLen;
	modulus_len1 = pubTemplate[1].ulValueLen;
	public_exponent1 = (CK_BYTE_PTR)malloc(public_exponent_len1);
	pubTemplate[0].pValue = public_exponent1;
	if (public_exponent1 == NULL)
	{
		printf("Failed to allocate memory\n");
		return 1;
	}
	modulus1 = (CK_BYTE_PTR)malloc(modulus_len1);
	pubTemplate[1].pValue = modulus1;
	if (modulus1 == NULL)
	{
		printf("Failed to allocate memory\n");
		free(public_exponent1);
		return 1;
	}

	// Get the information from the public key
	rv = p11->C_GetAttributeValue(hSession, hPublicKey, pubTemplate,  2);
	if (rv != CKR_OK)
	{
		printf("Failed to get the modulus and pubexp. rv=0x%08X\n", rv);
		free(public_exponent1);
		free(modulus1);
		return 1;
	}

	printf("OK\n");
	printf("Public exponent: ");
	printBinBuffer(public_exponent1, public_exponent_len1);
	printf("Modulus: ");
	printBinBuffer(modulus1, modulus_len1);

	printf("Public key information from private key object: ");

	// Get buffer sizes
	pubTemplate[0].ulValueLen = 0;
	pubTemplate[1].ulValueLen = 0;
	pubTemplate[0].pValue = NULL_PTR;
	pubTemplate[1].pValue = NULL_PTR;
	rv = p11->C_GetAttributeValue(hSession, hPrivateKey, pubTemplate,  2);
	if (rv == CKR_ATTRIBUTE_TYPE_INVALID)
	{
		printf("Failed. The modulus or pubexp does not exist\n");
		free(public_exponent1);
		free(modulus1);
		return 1;
	}
	if (rv != CKR_OK)
	{
		printf("Failed to get the size of modulus and pubexp. rv=0x%08X\n", rv);
		free(public_exponent1);
		free(modulus1);
		return 1;
	}

	// Allocate memory
	public_exponent_len2 = pubTemplate[0].ulValueLen;
	modulus_len2 = pubTemplate[1].ulValueLen;
	public_exponent2 = (CK_BYTE_PTR)malloc(public_exponent_len2);
	pubTemplate[0].pValue = public_exponent2;
	if (public_exponent2 == NULL)
	{
		printf("Failed to allocate memory\n");
		free(public_exponent1);
		free(modulus1);
		return 1;
	}
	modulus2 = (CK_BYTE_PTR)malloc(modulus_len2);
	pubTemplate[1].pValue = modulus2;
	if (modulus2 == NULL)
	{
		printf("Failed to allocate memory\n");
		free(public_exponent1);
		free(modulus1);
		free(public_exponent2);
		return 1;
	}

	// Get the information from the private key
	rv = p11->C_GetAttributeValue(hSession, hPrivateKey, pubTemplate,  2);
	if (rv != CKR_OK)
	{
		printf("Failed to get the modulus and pubexp. rv=0x%08X\n", rv);
		free(public_exponent1);
		free(modulus1);
		free(public_exponent2);
		free(modulus2);
		return 1;
	}

	// Make sure that the information from the public and private key are equal
	if
	(
		public_exponent_len1 != public_exponent_len2 ||
		memcmp(public_exponent1, public_exponent2, public_exponent_len1) != 0 ||
		modulus_len1 != modulus_len2 ||
		memcmp(modulus1, modulus2, modulus_len1) != 0
	)
	{
		printf("Failed. The key information is not equal.\n");
		retVal = 1;
	}
	else
	{
		printf("OK\n");
	}

	printf("Public exponent: ");
	printBinBuffer(public_exponent2, public_exponent_len2);
	printf("Modulus: ");
	printBinBuffer(modulus2, modulus_len2);

	free(public_exponent1);
	free(modulus1);
	free(public_exponent2);
	free(modulus2);

	return retVal;
}

void printBinBuffer(void *pValue, unsigned long ulValueLen)
{
	char *buffer = (char*)pValue;

	if (buffer != NULL)
	{
		for (int i = 0; i < ulValueLen; i++)
		{
			printf("%02X", buffer[i] & 0xFF);
		}
	}

	printf("\n");
}
