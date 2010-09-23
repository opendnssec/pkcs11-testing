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
 import.cpp

 Functions for testing key import
 *****************************************************************************/

#include "import.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>


extern CK_FUNCTION_LIST_PTR p11;

int testRSAImport(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	int retVal = 0;

	CK_BYTE n[] = {
		0x0A, 0x66, 0x79, 0x1D, 0xC6, 0x98, 0x81, 0x68, 0xDE, 0x7A,
		0xB7, 0x74, 0x19, 0xBB, 0x7F, 0xB0, 0xC0, 0x01, 0xC6, 0x27,
		0x10, 0x27, 0x00, 0x75, 0x14, 0x29, 0x42, 0xE1, 0x9A, 0x8D,
		0x8C, 0x51, 0xD0, 0x53, 0xB3, 0xE3, 0x78, 0x2A, 0x1D, 0xE5,
		0xDC, 0x5A, 0xF4, 0xEB, 0xE9, 0x94, 0x68, 0x17, 0x01, 0x14,
		0xA1, 0xDF, 0xE6, 0x7C, 0xDC, 0x9A, 0x9A, 0xF5, 0x5D, 0x65,
		0x56, 0x20, 0xBB, 0xAB
	};
	CK_BYTE e[] = {
		0x01, 0x00, 0x01
	};
	CK_BYTE d[] = {
		0x01, 0x23, 0xC5, 0xB6, 0x1B, 0xA3, 0x6E, 0xDB, 0x1D, 0x36,
		0x79, 0x90, 0x41, 0x99, 0xA8, 0x9E, 0xA8, 0x0C, 0x09, 0xB9,
		0x12, 0x2E, 0x14, 0x00, 0xC0, 0x9A, 0xDC, 0xF7, 0x78, 0x46,
		0x76, 0xD0, 0x1D, 0x23, 0x35, 0x6A, 0x7D, 0x44, 0xD6, 0xBD,
		0x8B, 0xD5, 0x0E, 0x94, 0xBF, 0xC7, 0x23, 0xFA, 0x87, 0xD8,
		0x86, 0x2B, 0x75, 0x17, 0x76, 0x91, 0xC1, 0x1D, 0x75, 0x76,
		0x92, 0xDF, 0x88, 0x81
	};
	CK_BYTE p[] = {
		0x33, 0xD4, 0x84, 0x45, 0xC8, 0x59, 0xE5, 0x23, 0x40, 0xDE,
		0x70, 0x4B, 0xCD, 0xDA, 0x06, 0x5F, 0xBB, 0x40, 0x58, 0xD7,
		0x40, 0xBD, 0x1D, 0x67, 0xD2, 0x9E, 0x9C, 0x14, 0x6C, 0x11,
		0xCF, 0x61
	};
        CK_BYTE q[] = {
		0x33, 0x5E, 0x84, 0x08, 0x86, 0x6B, 0x0F, 0xD3, 0x8D, 0xC7,
		0x00, 0x2D, 0x3F, 0x97, 0x2C, 0x67, 0x38, 0x9A, 0x65, 0xD5,
		0xD8, 0x30, 0x65, 0x66, 0xD5, 0xC4, 0xF2, 0xA5, 0xAA, 0x52,
		0x62, 0x8B
	};
	CK_BYTE dp[] = {
		0x5D, 0x8E, 0xA4, 0xC8, 0xAF, 0x83, 0xA7, 0x06, 0x34, 0xD5,
		0x92, 0x0C, 0x3D, 0xB6, 0x6D, 0x90, 0x8A, 0xC3, 0xAF, 0x57,
		0xA5, 0x97, 0xFD, 0x75, 0xBC, 0x9B, 0xBB, 0x85, 0x61, 0x81,
		0xC1, 0x85
	};
	CK_BYTE dq[] = {
		0xC5, 0x98, 0xE5, 0x4D, 0xAE, 0xC8, 0xAB, 0xC1, 0xE9, 0x07,
		0x76, 0x9A, 0x6C, 0x2B, 0xD0, 0x16, 0x53, 0xED, 0x0C, 0x99,
		0x60, 0xE1, 0xED, 0xB7, 0xE1, 0x86, 0xFD, 0xA9, 0x22, 0x88,
		0x3A, 0x99
	};
	CK_BYTE iqmp[] = {
		0x7C, 0x6F, 0x27, 0xB5, 0xB5, 0x1B, 0x78, 0xAD, 0x80, 0xFB,
		0x36, 0xE7, 0x00, 0x99, 0x0C, 0xF3, 0x07, 0x86, 0x6F, 0x29,
		0x43, 0x12, 0x4C, 0xBD, 0x93, 0xD9, 0x7C, 0x13, 0x77, 0x94,
		0xC1, 0x04
	};

	CK_BYTE id[] = { 123 };
	CK_BBOOL ckTrue = CK_TRUE, ckFalse = CK_FALSE;
	CK_BYTE label[] = "label";
	CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY, privClass = CKO_PRIVATE_KEY;
	CK_KEY_TYPE keyType = CKK_RSA;
	CK_ATTRIBUTE pubTemplate[] = {
		{ CKA_CLASS,		&pubClass,	sizeof(pubClass) },
		{ CKA_KEY_TYPE,		&keyType,	sizeof(keyType) },
		{ CKA_LABEL,		label,		sizeof(label) },
		{ CKA_ID,		id,		sizeof(id) },
		{ CKA_TOKEN,		&ckTrue,	sizeof(ckTrue) },
		{ CKA_VERIFY,		&ckTrue,	sizeof(ckTrue) },
		{ CKA_ENCRYPT,		&ckFalse,	sizeof(ckFalse) },
		{ CKA_WRAP,		&ckFalse,	sizeof(ckFalse) },
		{ CKA_PUBLIC_EXPONENT,	e,		sizeof(e) },
		{ CKA_MODULUS,		n,		sizeof(n) }
	};
	CK_ATTRIBUTE privTemplate[] = {
		{ CKA_CLASS,		&privClass,	sizeof(privClass) },
		{ CKA_KEY_TYPE,		&keyType,	sizeof(keyType) },
		{ CKA_LABEL,		label,		sizeof(label) },
		{ CKA_ID,		id,		sizeof(id) },
		{ CKA_SIGN,		&ckTrue,	sizeof(ckTrue) },
		{ CKA_DECRYPT,		&ckFalse,	sizeof(ckFalse) },
		{ CKA_UNWRAP,		&ckFalse,	sizeof(ckFalse) },
		{ CKA_SENSITIVE,	&ckTrue,	sizeof(ckTrue) },
		{ CKA_TOKEN,		&ckTrue,	sizeof(ckTrue) },
		{ CKA_PRIVATE,		&ckTrue,	sizeof(ckTrue) },
		{ CKA_EXTRACTABLE,	&ckFalse,	sizeof(ckFalse) },
		{ CKA_PUBLIC_EXPONENT,	e,		sizeof(e) },
		{ CKA_MODULUS,		n,		sizeof(n) },
		{ CKA_PRIVATE_EXPONENT,	d,		sizeof(d) },
		{ CKA_PRIME_1,		p,		sizeof(p) },
		{ CKA_PRIME_2,		q,		sizeof(q) },
		{ CKA_EXPONENT_1,	dp,		sizeof(dp) },
		{ CKA_EXPONENT_2,	dq,		sizeof(dq) },
		{ CKA_COEFFICIENT,	iqmp,		sizeof(iqmp) }
        };
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;

	printf("\n************************************\n");
	printf("* Test for importing RSA key pairs *\n");
	printf("************************************\n\n");

	printf("Importing public key: ");
	rv = p11->C_CreateObject(hSession, pubTemplate, 10, &hPublicKey);
	if (rv != CKR_OK)
	{
		printf("Failed to import. rv=%s\n", rv2string(rv));
		return 1;
	}
	printf("OK\n");

	printf("Importing private key: ");
	rv = p11->C_CreateObject(hSession, privTemplate, 19, &hPrivateKey);
	if (rv != CKR_OK)
	{
		printf("Failed to import. rv=%s\n", rv2string(rv));
		p11->C_DestroyObject(hSession, hPublicKey);
		return 1;
	}
	printf("OK\n");

	if (testRSAImport_size(hSession, hPublicKey)) retVal = 1;
	if (testRSAImport_signverify(hSession, hPublicKey, hPrivateKey)) retVal = 1;

	p11->C_DestroyObject(hSession, hPublicKey);
	p11->C_DestroyObject(hSession, hPrivateKey);

	return retVal;
}

int testRSAImport_size(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey)
{
	CK_RV rv;
	CK_ULONG modulus_bits, bits;
	int mask;
	CK_BYTE_PTR modulus = NULL;
	CK_ATTRIBUTE template1[] = {
		{ CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG) }
	};
	CK_ATTRIBUTE template2[] = {
		{ CKA_MODULUS, NULL_PTR, 0 }
	};

	int retVal = 0;

	printf("Key size from CKA_MODULUS_BITS in public key: ");

	// Get value
	rv = p11->C_GetAttributeValue(hSession, hPublicKey, template1,  1);
	if (rv != CKR_OK)
	{
		printf("Failed to get attribute. rv=%s\n", rv2string(rv));
		retVal = 1;
	}
	else
	{
		printf("%i bits\n", modulus_bits);
	}

	printf("Key size from CKA_MODULUS in public key: ");

	// Get buffer sizes
	rv = p11->C_GetAttributeValue(hSession, hPublicKey, template2,  1);
	if (rv != CKR_OK)
	{
		printf("Failed to get the size of the attribute. rv=%s\n", rv2string(rv));
		return 1;
	}

	// Allocate memory
	modulus = (CK_BYTE_PTR)malloc(template2[0].ulValueLen);
	template2[0].pValue = modulus;
	if (modulus == NULL)
	{
		printf("Failed to allocate memory\n");
		return 1;
	}

	// Get the attribute
	rv = p11->C_GetAttributeValue(hSession, hPublicKey, template2,  1);
	if (rv != CKR_OK)
	{
		printf("Failed to get the attribute. rv=%s\n", rv2string(rv));
		free(modulus);
		return 1;
	}

	// Calculate size
	bits = template2[0].ulValueLen * 8;
	mask = 0x80;
	for (int i = 0; bits && (modulus[i] & mask) == 0; bits--)
	{
		mask >>= 1;
		if (mask == 0)
		{
			i++;
			mask = 0x80;
		}
	}
	free(modulus);

	printf("%i bits\n", bits);

	if (bits == modulus_bits)
	{
		printf("Equal bit length: Yes\n");
	}
	else
	{
		printf("Equal bit length: No\n");
		retVal = 1;
	}

	return retVal;
}

int testRSAImport_signverify(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey, CK_OBJECT_HANDLE hPrivateKey)
{
	CK_RV rv;
	CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
	CK_BYTE_PTR pSignature;
	CK_ULONG pSignature_len;
	CK_BYTE data[] = {"Text"};

	printf("Create signature: ");

	rv = p11->C_SignInit(hSession, &mechanism, hPrivateKey);
	if (rv != CKR_OK)
	{
		printf("Failed to initialize signing. rv=%s\n", rv2string(rv));
		return 1;
	}

	rv = p11->C_Sign(hSession, data, sizeof(data)-1, NULL_PTR, &pSignature_len);
	if (rv != CKR_OK)
	{
		printf("Failed to get the length of the signature. rv=%s\n", rv2string(rv));
		return 1;
	}

	pSignature = (CK_BYTE_PTR)malloc(pSignature_len);
	if (pSignature == NULL)
	{
		printf("Failed to allocate memory\n");
		return 1;
	}

	rv = p11->C_Sign(hSession, data, sizeof(data)-1, pSignature, &pSignature_len);
	if (rv != CKR_OK)
	{
		printf("Failed to sign data. rv=%s\n", rv2string(rv));
		free (pSignature);
		return 1;
	}

	printf("OK\n");
	printf("Verify signature: ");

	rv = p11->C_VerifyInit(hSession, &mechanism, hPublicKey);
	if (rv != CKR_OK)
	{
		printf("Failed to sign data. rv=%s\n", rv2string(rv));
		free (pSignature);
		return 1;
	}

	rv = p11->C_Verify(hSession, data, sizeof(data)-1, pSignature, pSignature_len);
	free (pSignature);
	if (rv != CKR_OK)
	{
		printf("Failed to verify signature. rv=%s\n", rv2string(rv));
		return 1;
	}

	printf("OK\n");
	return 0;
}
