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
 mechanisms.cpp

 Functions for mechanism tests
 *****************************************************************************/

#include "mechanisms.h"
#include "error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>


extern CK_FUNCTION_LIST_PTR p11;

int showMechs(char *slot)
{
	CK_MECHANISM_TYPE_PTR pMechanismList;
	CK_SLOT_ID slotID;
	CK_RV rv;
	CK_ULONG ulMechCount;

	if (slot == NULL)       
	{
		fprintf(stderr, "ERROR: A slot number must be supplied. "
			"Use --slot <number>\n");
		return 1;
	}
	slotID = atoi(slot);

	// Get the size of the buffer
	rv = p11->C_GetMechanismList(slotID, NULL_PTR, &ulMechCount);
	if (rv == CKR_SLOT_ID_INVALID)
	{
		fprintf(stderr, "ERROR: The slot does not exist.\n");
		return 1;
	}
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the number of mechanisms. rv=%s\n", rv2string(rv));
		return 1;
	}
        pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulMechCount * sizeof(CK_MECHANISM_TYPE_PTR));
        
	// Get the mechanism list
	rv = p11->C_GetMechanismList(slotID, pMechanismList, &ulMechCount);
	if (rv != CKR_OK)
	{
		fprintf(stderr, "ERROR: Could not get the list of mechanisms. rv=%s\n", rv2string(rv));
		free(pMechanismList);
		return 1;
	}

	printf("The following mechanisms are supported:\n");
	printf("(key size is in bits or bytes depending on mechanism)\n\n");

	for (int i = 0; i < ulMechCount; i++)
	{
		printMechInfo(slotID, pMechanismList[i]);
	}

	free(pMechanismList);

	return 0;
}

int testDNSSEC(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	int retVal = 0;

	printf("\n************************************************\n");
	printf("* Testing what DNSSEC algorithms are available *\n");
	printf("************************************************\n");
	printf("\n(Cannot test GOST since it is not available in PKCS#11 v2.20)\n");

	if (testDNSSEC_digest(slotID, hSession)) retVal = 1;
	if (testDNSSEC_rsa_keygen(slotID, hSession)) retVal = 1;
	if (testDNSSEC_rsa_sign(slotID, hSession)) retVal = 1;
	if (testDNSSEC_dsa_keygen(slotID, hSession)) retVal = 1;
	if (testDNSSEC_dsa_sign(slotID, hSession)) retVal = 1;

	return retVal;
}

int testSuiteB(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	int retVal = 0;

	printf("\n***************************************************\n");
	printf("* Testing if NSA Suite B algorithms are available *\n");
	printf("***************************************************\n");

	if (testSuiteB_AES(slotID, hSession)) retVal = 1;
	if (testSuiteB_ECDSA(slotID, hSession)) retVal = 1;
	if (testSuiteB_ECDH(slotID, hSession)) retVal = 1;
	if (testSuiteB_SHA(slotID, hSession)) retVal = 1;

	return retVal;
}

int testSuiteB_AES(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;

	CK_MECHANISM_TYPE types[] = {
		CKM_AES_KEY_GEN,
		CKM_AES_CBC
	};

	printf("\nTesting symmetric encryption\n");
	printf("****************************\n");
	printf("  (Not testing functionality)\n");
	printf("  Should support between 128 and 256 bits.\n");
	printf("  Note that GCM mode is not supported in PKCS#11 v2.20.\n\n");

	for (int i = 0; i < 2; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		if (info.ulMinKeySize > 16 || info.ulMaxKeySize < 32)
		{
			printf("OK, but only support %i-%i bits.\n", info.ulMinKeySize * 8, info.ulMaxKeySize * 8);
		}
		else
		{
			printf("OK\n");
		}
	}

	return retVal;
}

int testSuiteB_ECDSA(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;

	CK_MECHANISM_TYPE types[] = {
		CKM_EC_KEY_PAIR_GEN,
		CKM_ECDSA
	};

	printf("\nTesting signatures\n");
	printf("*********************\n");
	printf("  (Not testing functionality)\n");
	printf("  Should support between 256 and 384 bits.\n\n");

	for (int i = 0; i < 2; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		if (info.ulMinKeySize > 256 || info.ulMaxKeySize < 384)
		{
			printf("OK, but only support %i-%i bits\n", info.ulMinKeySize, info.ulMaxKeySize);
		}
		else
		{
			printf("OK\n");
		}
	}

	return retVal;
}

int testSuiteB_ECDH(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;

	CK_MECHANISM_TYPE types[] = {
		CKM_ECDH1_DERIVE,
		CKM_ECDH1_COFACTOR_DERIVE
	};

	printf("\nTesting key agreement\n");
	printf("*********************\n");
	printf("  (Not testing functionality)\n");
	printf("  Should support between 256 and 384 bits.\n\n");

	for (int i = 0; i < 2; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		if (info.ulMinKeySize > 256 || info.ulMaxKeySize < 384)
		{
			printf("OK, but only support %i-%i bits\n", info.ulMinKeySize, info.ulMaxKeySize);
		}
		else
		{
			printf("OK\n");
		}
	}

	return retVal;
}

int testSuiteB_SHA(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;

	CK_MECHANISM_TYPE types[] = {
		CKM_SHA256,
		CKM_SHA384
	};

	printf("\nTesting digesting\n");
	printf("*****************\n");
	printf("  (Not testing functionality)\n");
	printf("  Will test if the digesting mechanisms are supported.\n");
	printf("  If the digesting algorithms are not available, \n");
	printf("  then digesting has to be done in the host application.\n\n");

	for (int i = 0; i < 2; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		printf("OK\n");
	}

	return retVal;
}

int testDNSSEC_digest(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;
	CK_BYTE_PTR digest;
	CK_ULONG digestLen;
	CK_BYTE data[] = {"Text to digest"};
	CK_MECHANISM mechanism = {
		CKM_VENDOR_DEFINED, NULL_PTR, 0
	};

	CK_MECHANISM_TYPE types[] = {
		CKM_MD5,
		CKM_SHA_1,
		CKM_SHA256,
		CKM_SHA512
	};

	printf("\nTesting digesting\n");
	printf("*****************\n");
	printf("  Will test the digesting mechanisms.\n");
	printf("  If the algorithm is not available, then digesting has to be done\n");
	printf("  in the host application. (MD5 is not recommended to use)\n\n");

	for (int i = 0; i < 4; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		mechanism.mechanism = types[i];
		rv = p11->C_DigestInit(hSession, &mechanism);
		if (rv != CKR_OK)
		{
			printf("Available, but could not initialize digesting. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		rv = p11->C_Digest(hSession, data, sizeof(data)-1, NULL_PTR, &digestLen);
		if (rv != CKR_OK)
		{
			printf("Available, but could not check the size of the digest. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}
		digest = (CK_BYTE_PTR)malloc(digestLen);

		rv = p11->C_Digest(hSession, data, sizeof(data)-1, digest, &digestLen);
		free(digest);
		if (rv != CKR_OK)
		{
			printf("Available, but could not digest the data. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		printf("OK\n");
	}

	return retVal;
}

int testDNSSEC_rsa_keygen(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CK_BBOOL ckTrue = CK_TRUE;
	CK_MECHANISM keyGenMechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_BYTE publicExponent[] = { 1, 0, 1 };

	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_ENCRYPT, &ckTrue, sizeof(ckTrue) },
		{ CKA_VERIFY, &ckTrue, sizeof(ckTrue) },
		{ CKA_WRAP, &ckTrue, sizeof(ckTrue) },
		{ CKA_TOKEN, &ckTrue, sizeof(ckTrue) },
		{ CKA_MODULUS_BITS, NULL_PTR, 0 },
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

	CK_ULONG keySizes[] = {
		512,
		768,
		1024,
		1536,
		2048,
		3072,
		4096
	};

	printf("\nTesting RSA key generation\n");
	printf("******************************\n");
	printf("  Will test if RSA key generation is supported.\n");
	printf("  DNSSEC support keys up to 4096 bits.\n\n");

	printf("  %s: ", getMechName(CKM_RSA_PKCS_KEY_PAIR_GEN));
	rv = p11->C_GetMechanismInfo(slotID, CKM_RSA_PKCS_KEY_PAIR_GEN, &info);
	if (rv == CKR_MECHANISM_INVALID)
	{
		printf("Not available\n");
		return 1;
	}
	if (rv != CKR_OK)
	{
		printf("Not available. rv=%s\n", rv2string(rv));
		return 1;
	}

	if (info.ulMaxKeySize < 4096)
	{
		printf("OK, but support maximum %i bits\n", info.ulMaxKeySize);
	}
	else
	{
		printf("OK\n");
	}

	for (int i = 0; i < 7; i++)
	{
		printf("  %i bits: ", keySizes[i]);

		CK_ULONG keySize = keySizes[i];

		publicKeyTemplate[4].pValue = &keySize;
		publicKeyTemplate[4].ulValueLen = sizeof(keySize);
		rv = p11->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 6, &hPublicKey, &hPrivateKey);
		if (rv != CKR_OK)
		{
			printf("Failed. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		printf("OK\n");

		p11->C_DestroyObject(hSession, hPublicKey);
		p11->C_DestroyObject(hSession, hPrivateKey);
	}

	return retVal;
}

int testDNSSEC_rsa_sign(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CK_BBOOL ckTrue = CK_TRUE;
	CK_MECHANISM keyGenMechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_BYTE publicExponent[] = { 1, 0, 1 };
	CK_ULONG modulusBits = 1024;
	CK_MECHANISM mechanism = {
		CKM_VENDOR_DEFINED, NULL_PTR, 0
	};
	CK_ULONG length;
	CK_BYTE_PTR pSignature;
	CK_BYTE data[] = {"Text"};

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

	CK_MECHANISM_TYPE types[] = {
		CKM_RSA_PKCS,
		CKM_RSA_X_509,
		CKM_MD5_RSA_PKCS,
		CKM_SHA1_RSA_PKCS,
		CKM_SHA256_RSA_PKCS,
		CKM_SHA512_RSA_PKCS
	};

	printf("\nTesting RSA signing\n");
	printf("*******************\n");
	printf("  Will test if RSA signing is supported.\n");
	printf("  Doing RAW RSA signing is not recommended (CKM_RSA_X_509)\n");
	printf("  If the digesting algorithms are not available, \n");
	printf("  then digesting has to be done in the host application.\n");
	printf("  Then use the RSA only mechanisms.\n\n");

	rv = p11->C_GenerateKeyPair(hSession, &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 6, &hPublicKey, &hPrivateKey);
	if (rv != CKR_OK)
	{
		printf("Failed to generate a keypair. rv=%s\n", rv2string(rv));
		printf("RSA is probably not supported\n");
		return 1;
	}

	for (int i = 0; i < 6; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		mechanism.mechanism = types[i];
		rv = p11->C_SignInit(hSession, &mechanism, hPrivateKey);
		if (rv != CKR_OK)
		{
			printf("Available, but could not initialize signing. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		rv = p11->C_Sign(hSession, data, sizeof(data)-1, NULL_PTR, &length);
		if (rv != CKR_OK)
		{
			printf("Available, but could not check the size of the signature. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}
		pSignature = (CK_BYTE_PTR)malloc(length);

		rv = p11->C_Sign(hSession, data, sizeof(data)-1, pSignature, &length);
		free(pSignature);
		if (rv != CKR_OK)
		{
			printf("Available, but could not sign the data. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		printf("OK\n");
	}

	p11->C_DestroyObject(hSession, hPublicKey);
	p11->C_DestroyObject(hSession, hPrivateKey);

	return retVal;
}

int testDNSSEC_dsa_keygen(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;

	CK_ULONG keySizes[] = {
		512,
		640,
		768,
		896,
		1024
	};

	printf("\nTesting DSA key generation\n");
	printf("**************************\n");
	printf("  (Not testing functionality)\n");
	printf("  Will test if DSA key generation is supported.\n");
	printf("  DNSSEC support keys up to 1024 bits.\n\n");

	printf("  %s: ", getMechName(CKM_DSA_PARAMETER_GEN));
	rv = p11->C_GetMechanismInfo(slotID, CKM_DSA_PARAMETER_GEN, &info);
	if (rv == CKR_MECHANISM_INVALID)
	{
		printf("Not available\n");
		retVal = 1;
	}
	else if (rv != CKR_OK)
	{
		printf("Not available. rv=%s\n", rv2string(rv));
		retVal = 1;
	}
	else
	{
		if (info.ulMaxKeySize < 1024)
		{
			printf("OK, but support maximum %i bits\n", info.ulMaxKeySize);
		}
		else
		{
			printf("OK\n");
		}
	}

	printf("  %s: ", getMechName(CKM_DSA_KEY_PAIR_GEN));
	rv = p11->C_GetMechanismInfo(slotID, CKM_DSA_KEY_PAIR_GEN, &info);
	if (rv == CKR_MECHANISM_INVALID)
	{
		printf("Not available\n");
		retVal = 1;
	}
	else if (rv != CKR_OK)
	{
		printf("Not available. rv=%s\n", rv2string(rv));
		retVal = 1;
	}
	else
	{
		if (info.ulMaxKeySize < 1024)
		{
			printf("OK, but support maximum %i bits\n", info.ulMaxKeySize);
		}
		else
		{
			printf("OK\n");
		}
	}

	// for (int i = 0; i < 5; i++)
	// {
	// }

	return retVal;
}

int testDNSSEC_dsa_sign(CK_SLOT_ID slotID, CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	CK_MECHANISM_INFO info;
	int retVal = 0;

	CK_MECHANISM_TYPE types[] = {
		CKM_DSA,
		CKM_DSA_SHA1
	};

	printf("\nTesting DSA signing\n");
	printf("*******************\n");
	printf("  (Not testing functionality)\n");
	printf("  Will test if DSA signing is supported.\n");
	printf("  If the digesting algorithm is not available, \n");
	printf("  then digesting has to be done in the host application.\n");
	printf("  Then use the DSA only mechanism.\n\n");

	for (int i = 0; i < 2; i++)
	{
		printf("  %s: ", getMechName(types[i]));
		rv = p11->C_GetMechanismInfo(slotID, types[i], &info);
		if (rv == CKR_MECHANISM_INVALID)
		{
			printf("Not available\n");
			retVal = 1;
			continue;
		}
		if (rv != CKR_OK)
		{
			printf("Not available. rv=%s\n", rv2string(rv));
			retVal = 1;
			continue;
		}

		printf("OK\n");
	}

	return retVal;
}

void printMechInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE mechType)
{
	CK_MECHANISM_INFO info;
	CK_RV rv;

	info.ulMinKeySize = 0;
	info.ulMaxKeySize = 0;

	printf("%-36s", getMechName(mechType));

	rv = p11->C_GetMechanismInfo(slotID, mechType, &info);
	if (rv != CKR_OK)
	{
		printf("   Could not get info about the mechanism. rv=%s\n", rv2string(rv));
		return;
	}

	printMechKeySize(info.ulMinKeySize, info.ulMaxKeySize);
	printMechFlags(info.flags);
}

void printMechKeySize(CK_ULONG ulMinKeySize, CK_ULONG ulMaxKeySize)
{
	char buffer[512];
	buffer[0] = '\0';

	if (ulMinKeySize)
	{
		if (ulMaxKeySize > ulMinKeySize)
		{
			sprintf(buffer, "%i - %i", ulMinKeySize, ulMaxKeySize);
		}
		else
		{
			sprintf(buffer, "%i", ulMinKeySize);
		}
	}
	printf("%-14s", buffer);
}

void printMechFlags(CK_FLAGS flags)
{
	std::string stringFlags = "";

	if (flags & CKF_HW)
	{
		stringFlags += "HW ";
		flags ^= CKF_HW;
	}
	else
	{
		stringFlags += "No-HW ";
	}

	if (flags & CKF_ENCRYPT)
	{
		stringFlags += "encrypt ";
		flags ^= CKF_ENCRYPT;
	}
	if (flags & CKF_DECRYPT)
	{
		stringFlags += "decrypt ";
		flags ^= CKF_DECRYPT;
	}
	if (flags & CKF_DIGEST)
	{
		stringFlags += "digest ";
		flags ^= CKF_DIGEST;
	}
	if (flags & CKF_SIGN)
	{
		stringFlags += "sign ";
		flags ^= CKF_SIGN;
	}
	if (flags & CKF_SIGN_RECOVER)
	{
		stringFlags += "sign-recover ";
		flags ^= CKF_SIGN_RECOVER;
	}
	if (flags & CKF_VERIFY)
	{
		stringFlags += "verify ";
		flags ^= CKF_VERIFY;
	}
	if (flags & CKF_VERIFY_RECOVER)
	{
		stringFlags += "verify-recover ";
		flags ^= CKF_VERIFY_RECOVER;
	}
	if (flags & CKF_GENERATE)
	{
		stringFlags += "generate ";
		flags ^= CKF_GENERATE;
	}
	if (flags & CKF_GENERATE_KEY_PAIR)
	{
		stringFlags += "generate-key-pair ";
		flags ^= CKF_GENERATE_KEY_PAIR;
	}
	if (flags & CKF_WRAP)
	{
		stringFlags += "wrap ";
		flags ^= CKF_WRAP;
	}
	if (flags & CKF_UNWRAP)
	{
		stringFlags += "unwrap ";
		flags ^= CKF_UNWRAP;
	}
	if (flags & CKF_DERIVE)
	{
		stringFlags += "derive ";
		flags ^= CKF_DERIVE;
	}

	printf("%s\n", stringFlags.c_str());
}

const char* getMechName(CK_MECHANISM_TYPE mechType)
{
	static char buffer[20];

	switch (mechType)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			return "CKM_RSA_PKCS_KEY_PAIR_GEN";
		case CKM_RSA_PKCS:
			return "CKM_RSA_PKCS";
		case CKM_RSA_9796:
			return "CKM_RSA_9796";
		case CKM_RSA_X_509:
			return "CKM_RSA_X_509";
		case CKM_MD2_RSA_PKCS:
			return "CKM_MD2_RSA_PKCS";
		case CKM_MD5_RSA_PKCS:
			return "CKM_MD5_RSA_PKCS";
		case CKM_SHA1_RSA_PKCS:
			return "CKM_SHA1_RSA_PKCS";
		case CKM_RIPEMD128_RSA_PKCS:
			return "CKM_RIPEMD128_RSA_PKCS";
		case CKM_RIPEMD160_RSA_PKCS:
			return "CKM_RIPEMD160_RSA_PKCS";
		case CKM_RSA_PKCS_OAEP:
			return "CKM_RSA_PKCS_OAEP";
		case CKM_RSA_X9_31_KEY_PAIR_GEN:
			return "CKM_RSA_X9_31_KEY_PAIR_GEN";
		case CKM_RSA_X9_31:
			return "CKM_RSA_X9_31";
		case CKM_SHA1_RSA_X9_31:
			return "CKM_SHA1_RSA_X9_31";
		case CKM_RSA_PKCS_PSS:
			return "CKM_RSA_PKCS_PSS";
		case CKM_SHA1_RSA_PKCS_PSS:
			return "CKM_SHA1_RSA_PKCS_PSS";
		case CKM_DSA_KEY_PAIR_GEN:
			return "CKM_DSA_KEY_PAIR_GEN";
		case CKM_DSA:
			return "CKM_DSA";
		case CKM_DSA_SHA1:
			return "CKM_DSA_SHA1";
		case CKM_DH_PKCS_KEY_PAIR_GEN:
			return "CKM_DH_PKCS_KEY_PAIR_GEN";
		case CKM_DH_PKCS_DERIVE:
			return "CKM_DH_PKCS_DERIVE";
		case CKM_X9_42_DH_KEY_PAIR_GEN:
			return "CKM_X9_42_DH_KEY_PAIR_GEN";
		case CKM_X9_42_DH_DERIVE:
			return "CKM_X9_42_DH_DERIVE";
		case CKM_X9_42_DH_HYBRID_DERIVE:
			return "CKM_X9_42_DH_HYBRID_DERIVE";
		case CKM_X9_42_MQV_DERIVE:
			return "CKM_X9_42_MQV_DERIVE";
		case CKM_SHA256_RSA_PKCS:
			return "CKM_SHA256_RSA_PKCS";
		case CKM_SHA384_RSA_PKCS:
			return "CKM_SHA384_RSA_PKCS";
		case CKM_SHA512_RSA_PKCS:
			return "CKM_SHA512_RSA_PKCS";
		case CKM_SHA256_RSA_PKCS_PSS:
			return "CKM_SHA256_RSA_PKCS_PSS";
		case CKM_SHA384_RSA_PKCS_PSS:
			return "CKM_SHA384_RSA_PKCS_PSS";
		case CKM_SHA512_RSA_PKCS_PSS:
			return "CKM_SHA512_RSA_PKCS_PSS";
		case CKM_SHA224_RSA_PKCS:
			return "CKM_SHA224_RSA_PKCS";
		case CKM_SHA224_RSA_PKCS_PSS:
			return "CKM_SHA224_RSA_PKCS_PSS";
		case CKM_RC2_KEY_GEN:
			return "CKM_RC2_KEY_GEN";
		case CKM_RC2_ECB:
			return "CKM_RC2_ECB";
		case CKM_RC2_CBC:
			return "CKM_RC2_CBC";
		case CKM_RC2_MAC:
			return "CKM_RC2_MAC";
		case CKM_RC2_MAC_GENERAL:
			return "CKM_RC2_MAC_GENERAL";
		case CKM_RC2_CBC_PAD:
			return "CKM_RC2_CBC_PAD";
		case CKM_RC4_KEY_GEN:
			return "CKM_RC4_KEY_GEN";
		case CKM_RC4:
			return "CKM_RC4";
		case CKM_DES_KEY_GEN:
			return "CKM_DES_KEY_GEN";
		case CKM_DES_ECB:
			return "CKM_DES_ECB";
		case CKM_DES_CBC:
			return "CKM_DES_CBC";
		case CKM_DES_MAC:
			return "CKM_DES_MAC";
		case CKM_DES_MAC_GENERAL:
			return "CKM_DES_MAC_GENERAL";
		case CKM_DES_CBC_PAD:
			return "CKM_DES_CBC_PAD";
		case CKM_DES2_KEY_GEN:
			return "CKM_DES2_KEY_GEN";
		case CKM_DES3_KEY_GEN:
			return "CKM_DES3_KEY_GEN";
		case CKM_DES3_ECB:
			return "CKM_DES3_ECB";
		case CKM_DES3_CBC:
			return "CKM_DES3_CBC";
		case CKM_DES3_MAC:
			return "CKM_DES3_MAC";
		case CKM_DES3_MAC_GENERAL:
			return "CKM_DES3_MAC_GENERAL";
		case CKM_DES3_CBC_PAD:
			return "CKM_DES3_CBC_PAD";
		case CKM_CDMF_KEY_GEN:
			return "CKM_CDMF_KEY_GEN";
		case CKM_CDMF_ECB:
			return "CKM_CDMF_ECB";
		case CKM_CDMF_CBC:
			return "CKM_CDMF_CBC";
		case CKM_CDMF_MAC:
			return "CKM_CDMF_MAC";
		case CKM_CDMF_MAC_GENERAL:
			return "CKM_CDMF_MAC_GENERAL";
		case CKM_CDMF_CBC_PAD:
			return "CKM_CDMF_CBC_PAD";
		case CKM_DES_OFB64:
			return "CKM_DES_OFB64";
		case CKM_DES_OFB8:
			return "CKM_DES_OFB8";
		case CKM_DES_CFB64:
			return "CKM_DES_CFB64";
		case CKM_DES_CFB8:
			return "CKM_DES_CFB8";
		case CKM_MD2:
			return "CKM_MD2";
		case CKM_MD2_HMAC:
			return "CKM_MD2_HMAC";
		case CKM_MD2_HMAC_GENERAL:
			return "CKM_MD2_HMAC_GENERAL";
		case CKM_MD5:
			return "CKM_MD5";
		case CKM_MD5_HMAC:
			return "CKM_MD5_HMAC";
		case CKM_MD5_HMAC_GENERAL:
			return "CKM_MD5_HMAC_GENERAL";
		case CKM_SHA_1:
			return "CKM_SHA_1";
		case CKM_SHA_1_HMAC:
			return "CKM_SHA_1_HMAC";
		case CKM_SHA_1_HMAC_GENERAL:
			return "CKM_SHA_1_HMAC_GENERAL";
		case CKM_RIPEMD128:
			return "CKM_RIPEMD128";
		case CKM_RIPEMD128_HMAC:
			return "CKM_RIPEMD128_HMAC";
		case CKM_RIPEMD128_HMAC_GENERAL:
			return "CKM_RIPEMD128_HMAC_GENERAL";
		case CKM_RIPEMD160:
			return "CKM_RIPEMD160";
		case CKM_RIPEMD160_HMAC:
			return "CKM_RIPEMD160_HMAC";
		case CKM_RIPEMD160_HMAC_GENERAL:
			return "CKM_RIPEMD160_HMAC_GENERAL";
		case CKM_SHA256:
			return "CKM_SHA256";
		case CKM_SHA256_HMAC:
			return "CKM_SHA256_HMAC";
		case CKM_SHA256_HMAC_GENERAL:
			return "CKM_SHA256_HMAC_GENERAL";
		case CKM_SHA224:
			return "CKM_SHA224";
		case CKM_SHA224_HMAC:
			return "CKM_SHA224_HMAC";
		case CKM_SHA224_HMAC_GENERAL:
			return "CKM_SHA224_HMAC_GENERAL";
		case CKM_SHA384:
			return "CKM_SHA384";
		case CKM_SHA384_HMAC:
			return "CKM_SHA384_HMAC";
		case CKM_SHA384_HMAC_GENERAL:
			return "CKM_SHA384_HMAC_GENERAL";
		case CKM_SHA512:
			return "CKM_SHA512";
		case CKM_SHA512_HMAC:
			return "CKM_SHA512_HMAC";
		case CKM_SHA512_HMAC_GENERAL:
			return "CKM_SHA512_HMAC_GENERAL";
		case CKM_SECURID_KEY_GEN:
			return "CKM_SECURID_KEY_GEN";
		case CKM_SECURID:
			return "CKM_SECURID";
		case CKM_HOTP_KEY_GEN:
			return "CKM_HOTP_KEY_GEN";
		case CKM_HOTP:
			return "CKM_HOTP";
		case CKM_ACTI:
			return "CKM_ACTI";
		case CKM_ACTI_KEY_GEN:
			return "CKM_ACTI_KEY_GEN";
		case CKM_CAST_KEY_GEN:
			return "CKM_CAST_KEY_GEN";
		case CKM_CAST_ECB:
			return "CKM_CAST_ECB";
		case CKM_CAST_CBC:
			return "CKM_CAST_CBC";
		case CKM_CAST_MAC:
			return "CKM_CAST_MAC";
		case CKM_CAST_MAC_GENERAL:
			return "CKM_CAST_MAC_GENERAL";
		case CKM_CAST_CBC_PAD:
			return "CKM_CAST_CBC_PAD";
		case CKM_CAST3_KEY_GEN:
			return "CKM_CAST3_KEY_GEN";
		case CKM_CAST3_ECB:
			return "CKM_CAST3_ECB";
		case CKM_CAST3_CBC:
			return "CKM_CAST3_CBC";
		case CKM_CAST3_MAC:
			return "CKM_CAST3_MAC";
		case CKM_CAST3_MAC_GENERAL:
			return "CKM_CAST3_MAC_GENERAL";
		case CKM_CAST3_CBC_PAD:
			return "CKM_CAST3_CBC_PAD";
		case CKM_CAST128_KEY_GEN:
			return "CKM_CAST128_KEY_GEN";
		case CKM_CAST128_ECB:
			return "CKM_CAST128_ECB";
		case CKM_CAST128_CBC:
			return "CKM_CAST128_CBC";
		case CKM_CAST128_MAC:
			return "CKM_CAST128_MAC";
		case CKM_CAST128_MAC_GENERAL:
			return "CKM_CAST128_MAC_GENERAL";
		case CKM_CAST128_CBC_PAD:
			return "CKM_CAST128_CBC_PAD";
		case CKM_RC5_KEY_GEN:
			return "CKM_RC5_KEY_GEN";
		case CKM_RC5_ECB:
			return "CKM_RC5_ECB";
		case CKM_RC5_CBC:
			return "CKM_RC5_CBC";
		case CKM_RC5_MAC:
			return "CKM_RC5_MAC";
		case CKM_RC5_MAC_GENERAL:
			return "CKM_RC5_MAC_GENERAL";
		case CKM_RC5_CBC_PAD:
			return "CKM_RC5_CBC_PAD";
		case CKM_IDEA_KEY_GEN:
			return "CKM_IDEA_KEY_GEN";
		case CKM_IDEA_ECB:
			return "CKM_IDEA_ECB";
		case CKM_IDEA_CBC:
			return "CKM_IDEA_CBC";
		case CKM_IDEA_MAC:
			return "CKM_IDEA_MAC";
		case CKM_IDEA_MAC_GENERAL:
			return "CKM_IDEA_MAC_GENERAL";
		case CKM_IDEA_CBC_PAD:
			return "CKM_IDEA_CBC_PAD";
		case CKM_GENERIC_SECRET_KEY_GEN:
			return "CKM_GENERIC_SECRET_KEY_GEN";
		case CKM_CONCATENATE_BASE_AND_KEY:
			return "CKM_CONCATENATE_BASE_AND_KEY";
		case CKM_CONCATENATE_BASE_AND_DATA:
			return "CKM_CONCATENATE_BASE_AND_DATA";
		case CKM_CONCATENATE_DATA_AND_BASE:
			return "CKM_CONCATENATE_DATA_AND_BASE";
		case CKM_XOR_BASE_AND_DATA:
			return "CKM_XOR_BASE_AND_DATA";
		case CKM_EXTRACT_KEY_FROM_KEY:
			return "CKM_EXTRACT_KEY_FROM_KEY";
		case CKM_SSL3_PRE_MASTER_KEY_GEN:
			return "CKM_SSL3_PRE_MASTER_KEY_GEN";
		case CKM_SSL3_MASTER_KEY_DERIVE:
			return "CKM_SSL3_MASTER_KEY_DERIVE";
		case CKM_SSL3_KEY_AND_MAC_DERIVE:
			return "CKM_SSL3_KEY_AND_MAC_DERIVE";
		case CKM_SSL3_MASTER_KEY_DERIVE_DH:
			return "CKM_SSL3_MASTER_KEY_DERIVE_DH";
		case CKM_TLS_PRE_MASTER_KEY_GEN:
			return "CKM_TLS_PRE_MASTER_KEY_GEN";
		case CKM_TLS_MASTER_KEY_DERIVE:
			return "CKM_TLS_MASTER_KEY_DERIVE";
		case CKM_TLS_KEY_AND_MAC_DERIVE:
			return "CKM_TLS_KEY_AND_MAC_DERIVE";
		case CKM_TLS_MASTER_KEY_DERIVE_DH:
			return "CKM_TLS_MASTER_KEY_DERIVE_DH";
		case CKM_TLS_PRF:
			return "CKM_TLS_PRF";
		case CKM_SSL3_MD5_MAC:
			return "CKM_SSL3_MD5_MAC";
		case CKM_SSL3_SHA1_MAC:
			return "CKM_SSL3_SHA1_MAC";
		case CKM_MD5_KEY_DERIVATION:
			return "CKM_MD5_KEY_DERIVATION";
		case CKM_MD2_KEY_DERIVATION:
			return "CKM_MD2_KEY_DERIVATION";
		case CKM_SHA1_KEY_DERIVATION:
			return "CKM_SHA1_KEY_DERIVATION";
		case CKM_SHA256_KEY_DERIVATION:
			return "CKM_SHA256_KEY_DERIVATION";
		case CKM_SHA384_KEY_DERIVATION:
			return "CKM_SHA384_KEY_DERIVATION";
		case CKM_SHA512_KEY_DERIVATION:
			return "CKM_SHA512_KEY_DERIVATION";
		case CKM_SHA224_KEY_DERIVATION:
			return "CKM_SHA224_KEY_DERIVATION";
		case CKM_PBE_MD2_DES_CBC:
			return "CKM_PBE_MD2_DES_CBC";
		case CKM_PBE_MD5_DES_CBC:
			return "CKM_PBE_MD5_DES_CBC";
		case CKM_PBE_MD5_CAST_CBC:
			return "CKM_PBE_MD5_CAST_CBC";
		case CKM_PBE_MD5_CAST3_CBC:
			return "CKM_PBE_MD5_CAST3_CBC";
		case CKM_PBE_MD5_CAST128_CBC:
			return "CKM_PBE_MD5_CAST128_CBC";
		case CKM_PBE_SHA1_CAST128_CBC:
			return "CKM_PBE_SHA1_CAST128_CBC";
		case CKM_PBE_SHA1_RC4_128:
			return "CKM_PBE_SHA1_RC4_128";
		case CKM_PBE_SHA1_RC4_40:
			return "CKM_PBE_SHA1_RC4_40";
		case CKM_PBE_SHA1_DES3_EDE_CBC:
			return "CKM_PBE_SHA1_DES3_EDE_CBC";
		case CKM_PBE_SHA1_DES2_EDE_CBC:
			return "CKM_PBE_SHA1_DES2_EDE_CBC";
		case CKM_PBE_SHA1_RC2_128_CBC:
			return "CKM_PBE_SHA1_RC2_128_CBC";
		case CKM_PBE_SHA1_RC2_40_CBC:
			return "CKM_PBE_SHA1_RC2_40_CBC";
		case CKM_PKCS5_PBKD2:
			return "CKM_PKCS5_PBKD2";
		case CKM_PBA_SHA1_WITH_SHA1_HMAC:
			return "CKM_PBA_SHA1_WITH_SHA1_HMAC";
		case CKM_WTLS_PRE_MASTER_KEY_GEN:
			return "CKM_WTLS_PRE_MASTER_KEY_GEN";
		case CKM_WTLS_MASTER_KEY_DERIVE:
			return "CKM_WTLS_MASTER_KEY_DERIVE";
		case CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC:
			return "CKM_WTLS_MASTER_KEY_DERVIE_DH_ECC";
		case CKM_WTLS_PRF:
			return "CKM_WTLS_PRF";
		case CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE:
			return "CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE";
		case CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE:
			return "CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE";
		case CKM_KEY_WRAP_LYNKS:
			return "CKM_KEY_WRAP_LYNKS";
		case CKM_KEY_WRAP_SET_OAEP:
			return "CKM_KEY_WRAP_SET_OAEP";
		case CKM_CMS_SIG:
			return "CKM_CMS_SIG";
		case CKM_KIP_DERIVE:
			return "CKM_KIP_DERIVE";
		case CKM_KIP_WRAP:
			return "CKM_KIP_WRAP";
		case CKM_KIP_MAC:
			return "CKM_KIP_MAC";
		case CKM_CAMELLIA_KEY_GEN:
			return "CKM_CAMELLIA_KEY_GEN";
		case CKM_CAMELLIA_ECB:
			return "CKM_CAMELLIA_ECB";
		case CKM_CAMELLIA_CBC:
			return "CKM_CAMELLIA_CBC";
		case CKM_CAMELLIA_MAC:
			return "CKM_CAMELLIA_MAC";
		case CKM_CAMELLIA_MAC_GENERAL:
			return "CKM_CAMELLIA_MAC_GENERAL";
		case CKM_CAMELLIA_CBC_PAD:
			return "CKM_CAMELLIA_CBC_PAD";
		case CKM_CAMELLIA_ECB_ENCRYPT_DATA:
			return "CKM_CAMELLIA_ECB_ENCRYPT_DATA";
		case CKM_CAMELLIA_CBC_ENCRYPT_DATA:
			return "CKM_CAMELLIA_CBC_ENCRYPT_DATA";
		case CKM_CAMELLIA_CTR:
			return "CKM_CAMELLIA_CTR";
		case CKM_ARIA_KEY_GEN:
			return "CKM_ARIA_KEY_GEN";
		case CKM_ARIA_ECB:
			return "CKM_ARIA_ECB";
		case CKM_ARIA_CBC:
			return "CKM_ARIA_CBC";
		case CKM_ARIA_MAC:
			return "CKM_ARIA_MAC";
		case CKM_ARIA_MAC_GENERAL:
			return "CKM_ARIA_MAC_GENERAL";
		case CKM_ARIA_CBC_PAD:
			return "CKM_ARIA_CBC_PAD";
		case CKM_ARIA_ECB_ENCRYPT_DATA:
			return "CKM_ARIA_ECB_ENCRYPT_DATA";
		case CKM_ARIA_CBC_ENCRYPT_DATA:
			return "CKM_ARIA_CBC_ENCRYPT_DATA";
		case CKM_SKIPJACK_KEY_GEN:
			return "CKM_SKIPJACK_KEY_GEN";
		case CKM_SKIPJACK_ECB64:
			return "CKM_SKIPJACK_ECB64";
		case CKM_SKIPJACK_CBC64:
			return "CKM_SKIPJACK_CBC64";
		case CKM_SKIPJACK_OFB64:
			return "CKM_SKIPJACK_OFB64";
		case CKM_SKIPJACK_CFB64:
			return "CKM_SKIPJACK_CFB64";
		case CKM_SKIPJACK_CFB32:
			return "CKM_SKIPJACK_CFB32";
		case CKM_SKIPJACK_CFB16:
			return "CKM_SKIPJACK_CFB16";
		case CKM_SKIPJACK_CFB8:
			return "CKM_SKIPJACK_CFB8";
		case CKM_SKIPJACK_WRAP:
			return "CKM_SKIPJACK_WRAP";
		case CKM_SKIPJACK_PRIVATE_WRAP:
			return "CKM_SKIPJACK_PRIVATE_WRAP";
		case CKM_SKIPJACK_RELAYX:
			return "CKM_SKIPJACK_RELAYX";
		case CKM_KEA_KEY_PAIR_GEN:
			return "CKM_KEA_KEY_PAIR_GEN";
		case CKM_KEA_KEY_DERIVE:
			return "CKM_KEA_KEY_DERIVE";
		case CKM_FORTEZZA_TIMESTAMP:
			return "CKM_FORTEZZA_TIMESTAMP";
		case CKM_BATON_KEY_GEN:
			return "CKM_BATON_KEY_GEN";
		case CKM_BATON_ECB128:
			return "CKM_BATON_ECB128";
		case CKM_BATON_ECB96:
			return "CKM_BATON_ECB96";
		case CKM_BATON_CBC128:
			return "CKM_BATON_CBC128";
		case CKM_BATON_COUNTER:
			return "CKM_BATON_COUNTER";
		case CKM_BATON_SHUFFLE:
			return "CKM_BATON_SHUFFLE";
		case CKM_BATON_WRAP:
			return "CKM_BATON_WRAP";
		case CKM_EC_KEY_PAIR_GEN:
			return "CKM_EC_KEY_PAIR_GEN";
		case CKM_ECDSA:
			return "CKM_ECDSA";
		case CKM_ECDSA_SHA1:
			return "CKM_ECDSA_SHA1";
		case CKM_ECDH1_DERIVE:
			return "CKM_ECDH1_DERIVE";
		case CKM_ECDH1_COFACTOR_DERIVE:
			return "CKM_ECDH1_COFACTOR_DERIVE";
		case CKM_ECMQV_DERIVE:
			return "CKM_ECMQV_DERIVE";
		case CKM_JUNIPER_KEY_GEN:
			return "CKM_JUNIPER_KEY_GEN";
		case CKM_JUNIPER_ECB128:
			return "CKM_JUNIPER_ECB128";
		case CKM_JUNIPER_CBC128:
			return "CKM_JUNIPER_CBC128";
		case CKM_JUNIPER_COUNTER:
			return "CKM_JUNIPER_COUNTER";
		case CKM_JUNIPER_SHUFFLE:
			return "CKM_JUNIPER_SHUFFLE";
		case CKM_JUNIPER_WRAP:
			return "CKM_JUNIPER_WRAP";
		case CKM_FASTHASH:
			return "CKM_FASTHASH";
		case CKM_AES_KEY_GEN:
			return "CKM_AES_KEY_GEN";
		case CKM_AES_ECB:
			return "CKM_AES_ECB";
		case CKM_AES_CBC:
			return "CKM_AES_CBC";
		case CKM_AES_MAC:
			return "CKM_AES_MAC";
		case CKM_AES_MAC_GENERAL:
			return "CKM_AES_MAC_GENERAL";
		case CKM_AES_CBC_PAD:
			return "CKM_AES_CBC_PAD";
		case CKM_AES_CTR:
			return "CKM_AES_CTR";
		case CKM_BLOWFISH_KEY_GEN:
			return "CKM_BLOWFISH_KEY_GEN";
		case CKM_BLOWFISH_CBC:
			return "CKM_BLOWFISH_CBC";
		case CKM_TWOFISH_KEY_GEN:
			return "CKM_TWOFISH_KEY_GEN";
		case CKM_TWOFISH_CBC:
			return "CKM_TWOFISH_CBC";
		case CKM_DES_ECB_ENCRYPT_DATA:
			return "CKM_DES_ECB_ENCRYPT_DATA";
		case CKM_DES_CBC_ENCRYPT_DATA:
			return "CKM_DES_CBC_ENCRYPT_DATA";
		case CKM_DES3_ECB_ENCRYPT_DATA:
			return "CKM_DES3_ECB_ENCRYPT_DATA";
		case CKM_DES3_CBC_ENCRYPT_DATA:
			return "CKM_DES3_CBC_ENCRYPT_DATA";
		case CKM_AES_ECB_ENCRYPT_DATA:
			return "CKM_AES_ECB_ENCRYPT_DATA";
		case CKM_AES_CBC_ENCRYPT_DATA:
			return "CKM_AES_CBC_ENCRYPT_DATA";
		case CKM_DSA_PARAMETER_GEN:
			return "CKM_DSA_PARAMETER_GEN";
		case CKM_DH_PKCS_PARAMETER_GEN:
			return "CKM_DH_PKCS_PARAMETER_GEN";
		case CKM_X9_42_DH_PARAMETER_GEN:
			return "CKM_X9_42_DH_PARAMETER_GEN";
		case CKM_VENDOR_DEFINED:
			return "CKM_VENDOR_DEFINED";
		defult:
			break;
	}

	sprintf(buffer, "0x%08X", mechType);

	return buffer;
}
